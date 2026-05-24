use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{error, warn};

use crate::api::{AuthTokens, CertificateRequest, CertificateResponse, ProtonApiClient};
use crate::config::{AppConfig, RenderConfig, RuntimeContext, TopologyConfig, read_json};
use crate::crypto::{KeyMaterial, generate_key_material};
use crate::filter::{ServerFilter, select_target};
use crate::health::{HealthMonitor, HealthStatus, ProbeResult};
use crate::model::{LogicalServer, PhysicalServer, ProtonLogicalResponse};
use crate::provider::{
    PROTON_PROVIDER, ProvidersConfig, WireGuardEndpointOverrides, WireGuardServerFilter,
    resolve_wireguard_endpoint, select_wireguard_server,
};
use crate::session::UserSession;
use crate::singbox_adapter::default_allowed_ips;
use crate::state::{
    HealthRecord, OutboundCertificateUpdate, StateStore, WireGuardEndpointStateUpdate,
    topology_state_file, write_state_file,
};
use crate::supervisor_render::{
    endpoint_specs, ensure_sessions_exist, render_and_deploy, rendered_output_path, session_map,
    template_path, topology_output_path,
};

const DEFAULT_COALESCE_DELAY: Duration = Duration::from_secs(5);
const MAX_CERT_FAILURES_BEFORE_KEY_ROTATION: i64 = 4;

#[derive(Clone, Debug)]
pub struct SupervisorOptions {
    pub access_token: Option<String>,
    pub raw_ip: Option<String>,
    pub proxy_url: Option<String>,
    pub once: bool,
    pub interval: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct ProtonEndpointSpec {
    pub(crate) tag: String,
    pub(crate) username: String,
    pub(crate) filter: ServerFilter,
    pub(crate) health_proxy_url: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct StaticWireGuardEndpointSpec {
    pub(crate) tag: String,
    pub(crate) provider: String,
    pub(crate) filter: WireGuardServerFilter,
    pub(crate) local_address: Vec<String>,
    pub(crate) allowed_ips: Vec<String>,
    pub(crate) persistent_keepalive_interval: Option<u16>,
    pub(crate) reserved: Option<Vec<u8>>,
    pub(crate) health_proxy_url: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum EndpointSpec {
    Proton(ProtonEndpointSpec),
    StaticWireGuard(StaticWireGuardEndpointSpec),
}

impl EndpointSpec {
    pub(crate) fn tag(&self) -> &str {
        match self {
            Self::Proton(spec) => &spec.tag,
            Self::StaticWireGuard(spec) => &spec.tag,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SupervisorRuntime {
    pub(crate) context: RuntimeContext,
    pub(crate) render: RenderConfig,
    pub(crate) topology: TopologyConfig,
    pub(crate) providers: ProvidersConfig,
    pub(crate) template: Value,
    pub(crate) specs: Vec<EndpointSpec>,
    pub(crate) sessions: BTreeMap<String, UserSession>,
    pub(crate) options: SupervisorOptions,
    pub(crate) token_locks: Arc<BTreeMap<String, Arc<Mutex<()>>>>,
}

pub async fn run_supervisor(
    context: &RuntimeContext,
    config: &AppConfig,
    options: SupervisorOptions,
) -> Result<()> {
    config.providers.validate()?;
    let template_path = template_path(&config.render);
    let template: Value = read_json(&template_path)?;
    let specs = endpoint_specs(&template)?;
    if specs.is_empty() {
        anyhow::bail!("run requires at least one provider endpoint in the template");
    }
    let sessions = if specs
        .iter()
        .any(|spec| matches!(spec, EndpointSpec::Proton(_)))
    {
        session_map(&config.render.sessions)?
    } else {
        BTreeMap::new()
    };
    ensure_sessions_exist(&specs, &sessions)?;
    let token_locks = sessions
        .keys()
        .map(|username| (username.clone(), Arc::new(Mutex::new(()))))
        .collect();

    let raw_ip = match options.raw_ip.clone() {
        Some(ip) => ip,
        None => HealthMonitor::acquire_baseline().await?,
    };
    let options = SupervisorOptions {
        raw_ip: Some(raw_ip),
        ..options
    };
    let runtime = SupervisorRuntime {
        context: context.clone(),
        render: config.render.clone(),
        topology: config.topology.clone(),
        providers: config.providers.clone(),
        template,
        specs,
        sessions,
        options,
        token_locks: Arc::new(token_locks),
    };

    if let Some(username) = first_proton_username(&runtime.specs) {
        refresh_topology(&runtime, username).await?;
    }
    supervise_once(&runtime).await?;
    if runtime.options.once {
        return Ok(());
    }

    run_continuous(runtime).await
}

async fn run_continuous(runtime: SupervisorRuntime) -> Result<()> {
    let (deploy_tx, deploy_rx) = mpsc::channel(64);
    let deploy_runtime = runtime.clone();
    tokio::spawn(async move { deployment_loop(deploy_runtime, deploy_rx).await });

    if let Some(username) = first_proton_username(&runtime.specs) {
        let topology_runtime = runtime.clone();
        let topology_tx = deploy_tx.clone();
        tokio::spawn(async move { topology_loop(topology_runtime, username, topology_tx).await });
    }

    for spec in runtime.specs.clone() {
        let outbound_runtime = runtime.clone();
        let outbound_tx = deploy_tx.clone();
        tokio::spawn(async move { outbound_loop(outbound_runtime, spec, outbound_tx).await });
    }
    drop(deploy_tx);

    std::future::pending::<()>().await;
    Ok(())
}

async fn supervise_once(runtime: &SupervisorRuntime) -> Result<()> {
    let mut changed = false;
    for spec in &runtime.specs {
        changed |= process_endpoint(runtime, spec, false).await?;
    }
    if changed || !rendered_output_path(&runtime.context, &runtime.render).exists() {
        render_and_deploy(runtime).await?;
    }
    Ok(())
}

async fn topology_loop(runtime: SupervisorRuntime, username: String, deploy_tx: mpsc::Sender<()>) {
    loop {
        sleep(runtime.options.interval).await;
        match refresh_topology(&runtime, username.clone()).await {
            Ok(()) => {
                let _ = deploy_tx.send(()).await;
            }
            Err(error) => {
                warn!(%error, "topology refresh failed");
                record_runtime_error(
                    &runtime.context,
                    None,
                    None,
                    "topology_refresh_failed",
                    &error,
                );
            }
        }
    }
}

async fn outbound_loop(
    runtime: SupervisorRuntime,
    spec: EndpointSpec,
    deploy_tx: mpsc::Sender<()>,
) {
    loop {
        match process_endpoint(&runtime, &spec, false).await {
            Ok(true) => {
                let _ = deploy_tx.send(()).await;
            }
            Ok(false) => {}
            Err(error) => {
                error!(tag = %spec.tag(), %error, "outbound supervisor cycle failed");
                record_runtime_error(
                    &runtime.context,
                    endpoint_username(&spec),
                    Some(spec.tag()),
                    "outbound_cycle_failed",
                    &error,
                );
            }
        }
        sleep(runtime.options.interval).await;
    }
}

async fn deployment_loop(runtime: SupervisorRuntime, mut deploy_rx: mpsc::Receiver<()>) {
    while deploy_rx.recv().await.is_some() {
        sleep(DEFAULT_COALESCE_DELAY).await;
        while deploy_rx.try_recv().is_ok() {}
        if let Err(error) = render_and_deploy(&runtime).await {
            error!(%error, "coalesced sing-box deployment failed");
            record_runtime_error(
                &runtime.context,
                None,
                None,
                "coalesced_deployment_failed",
                &error,
            );
        }
    }
}

async fn process_endpoint(
    runtime: &SupervisorRuntime,
    spec: &EndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    match spec {
        EndpointSpec::Proton(spec) => process_proton_endpoint(runtime, spec, force_refresh).await,
        EndpointSpec::StaticWireGuard(spec) => {
            process_static_wireguard_endpoint(runtime, spec, force_refresh).await
        }
    }
}

async fn process_proton_endpoint(
    runtime: &SupervisorRuntime,
    spec: &ProtonEndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    let topology = load_topology(runtime)?;
    let session = runtime
        .sessions
        .get(&spec.username)
        .with_context(|| format!("missing render session for {}", spec.username))?;
    let selected = select_target(&topology, &spec.filter, session)?;
    let access_token = access_token_for_user(runtime, &spec.username).await?;
    let cert_changed = ensure_certificate(
        runtime,
        spec,
        &selected.physical,
        &access_token,
        force_refresh,
    )
    .await?;

    if cert_changed || !rendered_output_path(&runtime.context, &runtime.render).exists() {
        return Ok(true);
    }

    let store = StateStore::open(&runtime.context)?;
    let probe = probe_endpoint_once(
        runtime,
        Some(&spec.username),
        &spec.tag,
        spec.health_proxy_url.as_deref(),
    )
    .await?;

    if probe.status == HealthStatus::Healthy {
        return Ok(cert_changed);
    }

    let details = serde_json::to_string(&json!({
        "status": format!("{:?}", probe.status),
        "reason": probe.reason,
    }))?;
    store.record_event(
        Some(&spec.username),
        Some(&spec.tag),
        "health_recovery_requested",
        Some(&details),
    )?;
    ensure_certificate(runtime, spec, &selected.physical, &access_token, true).await?;
    Ok(true)
}

async fn process_static_wireguard_endpoint(
    runtime: &SupervisorRuntime,
    spec: &StaticWireGuardEndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    let state_changed = ensure_static_wireguard_endpoint_state(runtime, spec, force_refresh)?;
    if state_changed || !rendered_output_path(&runtime.context, &runtime.render).exists() {
        return Ok(true);
    }

    let store = StateStore::open(&runtime.context)?;
    let probe =
        probe_endpoint_once(runtime, None, &spec.tag, spec.health_proxy_url.as_deref()).await?;

    if probe.status == HealthStatus::Healthy {
        return Ok(state_changed);
    }

    let details = serde_json::to_string(&json!({
        "provider": spec.provider,
        "status": format!("{:?}", probe.status),
        "reason": probe.reason,
    }))?;
    store.record_event(
        None,
        Some(&spec.tag),
        "health_reselection_requested",
        Some(&details),
    )?;
    ensure_static_wireguard_endpoint_state(runtime, spec, true)
}

fn ensure_static_wireguard_endpoint_state(
    runtime: &SupervisorRuntime,
    spec: &StaticWireGuardEndpointSpec,
    force_reselect: bool,
) -> Result<bool> {
    let provider = runtime
        .providers
        .wireguard_provider(&spec.provider)
        .with_context(|| {
            format!(
                "template endpoint {} references unknown WireGuard provider '{}'",
                spec.tag, spec.provider
            )
        })?;
    let store = StateStore::open(&runtime.context)?;
    let current = store.load_wireguard_endpoint_state(&spec.tag)?;
    let avoid_server_id = force_reselect
        .then(|| current.as_ref().map(|state| state.server_id.as_str()))
        .flatten();
    let selected = select_wireguard_server(provider, &spec.filter, avoid_server_id)?;
    let resolved = resolve_wireguard_endpoint(
        provider,
        &selected,
        &WireGuardEndpointOverrides {
            local_address: spec.local_address.clone(),
            allowed_ips: spec.allowed_ips.clone(),
            persistent_keepalive_interval: spec.persistent_keepalive_interval,
            reserved: spec.reserved.clone(),
        },
    )?;

    let unchanged = current
        .as_ref()
        .map(|state| {
            state.provider == resolved.provider
                && state.server_id == resolved.server_id
                && state.endpoint == resolved.endpoint
                && state.peer_public_key == resolved.peer_public_key
                && state.assigned_ips == resolved.assigned_ips
                && state.allowed_ips == resolved.allowed_ips
                && state.persistent_keepalive_interval == resolved.persistent_keepalive_interval
                && state.reserved == resolved.reserved
        })
        .unwrap_or(false);
    if unchanged {
        return Ok(false);
    }

    let key_material = current
        .as_ref()
        .map(|state| KeyMaterial {
            private_key_base64: state.private_key.clone(),
            public_key_base64: state.public_key.clone(),
        })
        .unwrap_or_else(generate_key_material);
    store.store_wireguard_endpoint_state(WireGuardEndpointStateUpdate {
        outbound_tag: &spec.tag,
        provider: &resolved.provider,
        identity: None,
        server_id: &resolved.server_id,
        server_name: &resolved.server_name,
        endpoint: &resolved.endpoint,
        peer_public_key: &resolved.peer_public_key,
        private_key: &key_material.private_key_base64,
        public_key: &key_material.public_key_base64,
        assigned_ips: &resolved.assigned_ips,
        allowed_ips: &resolved.allowed_ips,
        persistent_keepalive_interval: resolved.persistent_keepalive_interval,
        reserved: resolved.reserved.as_deref(),
        mtu: 1408,
        expires_at_ms: None,
        refresh_at_ms: None,
    })?;
    Ok(true)
}

async fn probe_endpoint_once(
    runtime: &SupervisorRuntime,
    username: Option<&str>,
    outbound_tag: &str,
    health_proxy_url: Option<&str>,
) -> Result<ProbeResult> {
    let raw_ip = runtime
        .options
        .raw_ip
        .as_deref()
        .context("raw IP baseline was not initialized")?;
    let monitor = HealthMonitor::new(raw_ip.to_string(), runtime.options.interval)?;
    let proxy_url = health_proxy_url.or(runtime.options.proxy_url.as_deref());
    let probe = monitor.probe_once(proxy_url).await;
    StateStore::open(&runtime.context)?.record_health(HealthRecord {
        username,
        outbound_tag: Some(outbound_tag),
        status: &format!("{:?}", probe.status),
        raw_ip,
        returned_ip: probe.returned_ip.as_deref(),
        reason: &probe.reason,
    })?;
    Ok(probe)
}

async fn ensure_certificate(
    runtime: &SupervisorRuntime,
    spec: &ProtonEndpointSpec,
    server: &PhysicalServer,
    access_token: &str,
    force_refresh: bool,
) -> Result<bool> {
    let store = StateStore::open(&runtime.context)?;
    let current = store.load_outbound_certificate(&spec.tag)?;
    let now_ms = current_time_ms();
    let server_id = stable_server_id(server);
    let server_changed = current
        .as_ref()
        .map(|state| state.server_id != server_id)
        .unwrap_or(true);
    let due = current
        .as_ref()
        .and_then(|state| state.refresh_at_ms)
        .map(|refresh_at_ms| refresh_at_ms <= now_ms)
        .unwrap_or(true);
    let wireguard_state_missing = store.load_wireguard_endpoint_state(&spec.tag)?.is_none();

    if !force_refresh && !server_changed && !due {
        if wireguard_state_missing {
            let state = current.as_ref().context("missing outbound cert state")?;
            let assigned_ip = state
                .assigned_ip
                .clone()
                .context("certificate state is missing assigned IP")?;
            let assigned_ips = vec![assigned_ip];
            let allowed_ips = default_allowed_ips();
            store.store_wireguard_endpoint_state(WireGuardEndpointStateUpdate {
                outbound_tag: &spec.tag,
                provider: PROTON_PROVIDER,
                identity: Some(&spec.username),
                server_id: &state.server_id,
                server_name: &state.server_name,
                endpoint: &state.endpoint,
                peer_public_key: &state.peer_public_key,
                private_key: &state.private_key,
                public_key: &state.public_key,
                assigned_ips: &assigned_ips,
                allowed_ips: &allowed_ips,
                persistent_keepalive_interval: Some(25),
                reserved: None,
                mtu: 1408,
                expires_at_ms: state.expires_at_ms,
                refresh_at_ms: state.refresh_at_ms,
            })?;
            return Ok(true);
        }
        return Ok(false);
    }

    let rotate_key = current
        .as_ref()
        .map(|state| state.consecutive_failures >= MAX_CERT_FAILURES_BEFORE_KEY_ROTATION)
        .unwrap_or(true);
    let key_material = if rotate_key {
        generate_key_material()
    } else {
        let state = current.as_ref().context("missing outbound cert state")?;
        KeyMaterial {
            private_key_base64: state.private_key.clone(),
            public_key_base64: state.public_key.clone(),
        }
    };

    let api = ProtonApiClient::new(&runtime.context.api_base_url)?;
    let request = CertificateRequest::wireguard_session(&key_material.public_key_base64);
    let certificate = match api.get_certificate(access_token, &request).await {
        Ok(certificate) => certificate,
        Err(error) => {
            store.store_outbound_certificate_failure(
                &spec.username,
                &spec.tag,
                &error.to_string(),
            )?;
            return Err(error);
        }
    };
    persist_certificate(&store, spec, server, &key_material, &certificate)?;
    Ok(true)
}

fn persist_certificate(
    store: &StateStore,
    spec: &ProtonEndpointSpec,
    server: &PhysicalServer,
    key_material: &KeyMaterial,
    certificate: &CertificateResponse,
) -> Result<()> {
    let endpoint = certificate
        .endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| endpoint_for_server(server));
    let peer_public_key = certificate
        .peer_public_key
        .clone()
        .or(server.public_key.clone())
        .context("Proton certificate and server topology did not include peer public key")?;
    store.store_outbound_certificate_success(OutboundCertificateUpdate {
        outbound_tag: &spec.tag,
        username: &spec.username,
        server_id: &stable_server_id(server),
        server_name: &server.name,
        endpoint: &endpoint,
        peer_public_key: &peer_public_key,
        private_key: &key_material.private_key_base64,
        public_key: &key_material.public_key_base64,
        assigned_ip: &certificate.assigned_ip,
        expires_at_ms: certificate.expiration_time_ms as i64,
        refresh_at_ms: certificate.refresh_time_ms as i64,
    })
}

async fn refresh_topology(runtime: &SupervisorRuntime, username: String) -> Result<()> {
    let output = topology_output_path(&runtime.context, &runtime.render);
    let token = access_token_for_user(runtime, &username).await?;
    let api = ProtonApiClient::new(&runtime.context.api_base_url)?;
    match api.get_logicals(&token).await {
        Ok(logicals) => {
            let value = json!({ "LogicalServers": logicals });
            let text = serde_json::to_string_pretty(&value)?;
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            std::fs::write(&output, &text)
                .with_context(|| format!("failed to write {}", output.display()))?;
            write_state_file(&topology_state_file(&runtime.context), &text)?;
            StateStore::open(&runtime.context)?.record_event(
                Some(&username),
                None,
                "topology_refreshed",
                None,
            )?;
        }
        Err(error) => {
            load_topology(runtime).with_context(|| {
                format!("topology fetch failed and no usable fallback was found: {error:#}")
            })?;
            warn!(%error, "using existing topology state after fetch failure");
        }
    }
    Ok(())
}

fn load_topology(runtime: &SupervisorRuntime) -> Result<Vec<LogicalServer>> {
    let primary = topology_output_path(&runtime.context, &runtime.render);
    let state = topology_state_file(&runtime.context);
    let fallback = runtime.topology.fallback_topology.as_ref();
    for path in [Some(&primary), Some(&state), fallback]
        .into_iter()
        .flatten()
    {
        if path.exists() {
            let response: ProtonLogicalResponse = read_json(path)?;
            return Ok(response.into_servers());
        }
    }
    anyhow::bail!("no topology file is available for supervisor")
}

async fn access_token_for_user(runtime: &SupervisorRuntime, username: &str) -> Result<String> {
    if let Some(access_token) = &runtime.options.access_token {
        return Ok(access_token.clone());
    }

    let token_lock = runtime
        .token_locks
        .get(username)
        .with_context(|| format!("missing token lock for {username}"))?;
    let _guard = token_lock.lock().await;
    let store = StateStore::open(&runtime.context)?;
    let state = store.load_vpn_session(username)?;
    let api = ProtonApiClient::new(&runtime.context.api_base_url)?;
    let refreshed: AuthTokens = api
        .refresh_session(&state.uid, &state.refresh_token)
        .await
        .with_context(|| format!("failed to refresh VPN token for {username}"))?;
    let uid = refreshed.uid.as_deref().unwrap_or(&state.uid);
    store.store_vpn_session(username, uid, &refreshed.refresh_token)?;
    Ok(refreshed.access_token)
}

fn first_proton_username(specs: &[EndpointSpec]) -> Option<String> {
    specs.iter().find_map(|spec| match spec {
        EndpointSpec::Proton(spec) => Some(spec.username.clone()),
        EndpointSpec::StaticWireGuard(_) => None,
    })
}

fn endpoint_username(spec: &EndpointSpec) -> Option<&str> {
    match spec {
        EndpointSpec::Proton(spec) => Some(&spec.username),
        EndpointSpec::StaticWireGuard(_) => None,
    }
}

fn endpoint_for_server(server: &PhysicalServer) -> String {
    server
        .entry_ip
        .clone()
        .or_else(|| server.domain.clone())
        .unwrap_or_else(|| server.name.clone())
}

fn stable_server_id(server: &PhysicalServer) -> String {
    if server.id.is_empty() {
        server.name.clone()
    } else {
        server.id.clone()
    }
}

fn record_runtime_error(
    context: &RuntimeContext,
    username: Option<&str>,
    outbound_tag: Option<&str>,
    event_type: &str,
    error: &anyhow::Error,
) {
    if let Ok(store) = StateStore::open(context) {
        let details = serde_json::to_string(&json!({ "error": error.to_string() })).ok();
        let _ = store.record_event(username, outbound_tag, event_type, details.as_deref());
    }
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
