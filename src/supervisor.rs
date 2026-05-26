use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{error, warn};

use crate::accounts::ProtonAccountRegistry;
use crate::api::{
    CertificateRequest, CertificateResponse, PersistentCertificateFeatures, ProtonAccessToken,
    ProtonApiClient,
};
use crate::config::{AppConfig, RenderConfig, RuntimeContext, TopologyConfig, read_json};
use crate::crypto::generate_key_material;
use crate::filter::{ServerFilter, select_target};
use crate::health::{HealthMonitor, HealthStatus, ProbeResult};
use crate::model::{LogicalServer, PhysicalServer, ProtonLogicalResponse};
use crate::proton::{
    CachedAccessToken, PROTON_WIREGUARD_ADDRESS_V4, PROTON_WIREGUARD_KEEPALIVE_INTERVAL,
    ensure_account_access_token, proton_wireguard_assigned_ips,
};
use crate::provider::{
    PROTON_PROVIDER, ProvidersConfig, WireGuardEndpointOverrides, WireGuardServerFilter,
    resolve_wireguard_endpoint, select_wireguard_server,
};
use crate::provider_discovery::resolve_wireguard_provider_catalog;
use crate::session::UserSession;
use crate::singbox_adapter::default_allowed_ips;
use crate::state::{
    HealthRecord, OutboundCertificateUpdate, StateStore, WireGuardEndpointStateUpdate,
    topology_state_file, write_state_file,
};
use crate::supervisor_render::{
    account_sessions, canonicalize_proton_accounts, endpoint_specs, render_and_deploy,
    rendered_output_path, template_path, topology_output_path,
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
    pub session_keepalive_interval: Option<Duration>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProtonEndpointSpec {
    pub(crate) tag: String,
    pub(crate) account: String,
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
    pub(crate) pre_shared_key: Option<String>,
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
    pub(crate) proton_accounts: ProtonAccountRegistry,
    pub(crate) template: Value,
    pub(crate) specs: Vec<EndpointSpec>,
    pub(crate) sessions: BTreeMap<String, UserSession>,
    pub(crate) options: SupervisorOptions,
    pub(crate) token_states: Arc<BTreeMap<String, Arc<Mutex<CachedAccessToken>>>>,
}

pub async fn run_supervisor(
    context: &RuntimeContext,
    config: &AppConfig,
    mut options: SupervisorOptions,
) -> Result<()> {
    config.providers.validate()?;
    config.auth.validate()?;
    let template_path = template_path(&config.render);
    let template: Value = read_json(&template_path)?;
    let mut specs = endpoint_specs(&template)?;
    if specs.is_empty() {
        anyhow::bail!("run requires at least one provider endpoint in the template");
    }
    let proton_in_use = specs
        .iter()
        .any(|spec| matches!(spec, EndpointSpec::Proton(_)));
    let proton_accounts = if proton_in_use {
        ProtonAccountRegistry::from_auth(&config.auth)?
    } else {
        ProtonAccountRegistry::default()
    };
    if proton_in_use {
        canonicalize_proton_accounts(&mut specs, &proton_accounts)?;
    }
    let sessions = if proton_in_use {
        account_sessions(&proton_accounts)?
    } else {
        BTreeMap::new()
    };
    let token_states = sessions
        .keys()
        .map(|account| {
            (
                account.clone(),
                Arc::new(Mutex::new(CachedAccessToken::default())),
            )
        })
        .collect();

    let raw_ip = match options.raw_ip.take() {
        Some(ip) => ip,
        None => HealthMonitor::acquire_baseline().await?,
    };
    let options = SupervisorOptions {
        raw_ip: Some(raw_ip),
        session_keepalive_interval: (config.run.session_keepalive_interval_secs > 0)
            .then(|| Duration::from_secs(config.run.session_keepalive_interval_secs)),
        ..options
    };
    let runtime = SupervisorRuntime {
        context: context.clone(),
        render: config.render.clone(),
        topology: config.topology.clone(),
        providers: config.providers.clone(),
        proton_accounts,
        template,
        specs,
        sessions,
        options,
        token_states: Arc::new(token_states),
    };

    if let Some(account) = topology_account_name(&runtime) {
        refresh_topology(&runtime, &account).await?;
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

    if let Some(account) = topology_account_name(&runtime) {
        let topology_runtime = runtime.clone();
        let topology_tx = deploy_tx.clone();
        tokio::spawn(async move { topology_loop(topology_runtime, account, topology_tx).await });
    }

    for spec in runtime.specs.iter().cloned() {
        let outbound_runtime = runtime.clone();
        let outbound_tx = deploy_tx.clone();
        tokio::spawn(async move { outbound_loop(outbound_runtime, spec, outbound_tx).await });
    }
    if runtime.options.session_keepalive_interval.is_some() {
        for account in runtime.sessions.keys().cloned() {
            let keepalive_runtime = runtime.clone();
            tokio::spawn(async move {
                session_keepalive_loop(keepalive_runtime, account).await;
            });
        }
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

async fn topology_loop(runtime: SupervisorRuntime, account: String, deploy_tx: mpsc::Sender<()>) {
    loop {
        sleep(runtime.options.interval).await;
        match refresh_topology(&runtime, &account).await {
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
                let username = endpoint_username(&runtime, &spec);
                record_runtime_error(
                    &runtime.context,
                    username,
                    Some(spec.tag()),
                    "outbound_cycle_failed",
                    &error,
                );
            }
        }
        sleep(runtime.options.interval).await;
    }
}

async fn session_keepalive_loop(runtime: SupervisorRuntime, account_name: String) {
    let Some(interval) = runtime.options.session_keepalive_interval else {
        return;
    };

    loop {
        sleep(interval).await;
        if let Err(error) = keepalive_proton_session(&runtime, &account_name).await {
            warn!(account = %account_name, %error, "Proton session keepalive failed");
            let username = runtime
                .proton_accounts
                .get(&account_name)
                .map(|account| account.username.as_str());
            record_runtime_error(
                &runtime.context,
                username,
                None,
                "proton_session_keepalive_failed",
                &error,
            );
        }
    }
}

async fn keepalive_proton_session(runtime: &SupervisorRuntime, account_name: &str) -> Result<()> {
    let access_token = access_token_for_account(runtime, account_name).await?;
    let api = ProtonApiClient::from_context(&runtime.context)?;
    let _ = api.list_sessions(&access_token).await?;
    Ok(())
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
        .get(&spec.account)
        .with_context(|| format!("missing configured Proton account {}", spec.account))?;
    let selected = select_target(&topology, &spec.filter, session)?;
    let access_token = access_token_for_account(runtime, &spec.account).await?;
    let cert_changed = ensure_certificate(
        runtime,
        spec,
        &session.username,
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
        Some(&session.username),
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
        Some(&session.username),
        Some(&spec.tag),
        "health_recovery_requested",
        Some(&details),
    )?;
    ensure_certificate(
        runtime,
        spec,
        &session.username,
        &selected.physical,
        &access_token,
        true,
    )
    .await?;
    Ok(true)
}

async fn process_static_wireguard_endpoint(
    runtime: &SupervisorRuntime,
    spec: &StaticWireGuardEndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    let state_changed =
        ensure_static_wireguard_endpoint_state(runtime, spec, force_refresh).await?;
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
    ensure_static_wireguard_endpoint_state(runtime, spec, true).await
}

async fn ensure_static_wireguard_endpoint_state(
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
    let provider = resolve_wireguard_provider_catalog(provider).await?;
    let store = StateStore::open(&runtime.context)?;
    let current = store.load_wireguard_endpoint_state(&spec.tag)?;
    let avoid_server_id = force_reselect
        .then(|| current.as_ref().map(|state| state.server_id.as_str()))
        .flatten();
    let selected = select_wireguard_server(&provider, &spec.filter, avoid_server_id)?;
    let resolved = resolve_wireguard_endpoint(
        &provider,
        &selected,
        &WireGuardEndpointOverrides {
            local_address: spec.local_address.clone(),
            allowed_ips: spec.allowed_ips.clone(),
            pre_shared_key: spec.pre_shared_key.clone(),
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
                && state.pre_shared_key == resolved.pre_shared_key
                && state.assigned_ips == resolved.assigned_ips
                && state.allowed_ips == resolved.allowed_ips
                && state.persistent_keepalive_interval == resolved.persistent_keepalive_interval
                && state.reserved == resolved.reserved
        })
        .unwrap_or(false);
    if unchanged {
        return Ok(false);
    }

    let generated_key_material = current.is_none().then(generate_key_material);
    let private_key_base64 = generated_key_material
        .as_ref()
        .map(|material| Cow::Borrowed(material.private_key_base64.as_str()))
        .or_else(|| {
            current
                .as_ref()
                .map(|state| Cow::Borrowed(state.private_key.as_str()))
        })
        .context("missing WireGuard private key state")?;
    let public_key_base64 = generated_key_material
        .as_ref()
        .map(|material| Cow::Borrowed(material.public_key_base64.as_str()))
        .or_else(|| {
            current
                .as_ref()
                .map(|state| Cow::Borrowed(state.public_key.as_str()))
        })
        .context("missing WireGuard public key state")?;
    store.store_wireguard_endpoint_state(WireGuardEndpointStateUpdate {
        outbound_tag: &spec.tag,
        provider: &resolved.provider,
        identity: None,
        server_id: &resolved.server_id,
        server_name: &resolved.server_name,
        endpoint: &resolved.endpoint,
        peer_public_key: &resolved.peer_public_key,
        pre_shared_key: resolved.pre_shared_key.as_deref(),
        private_key: &private_key_base64,
        public_key: &public_key_base64,
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
    let monitor = HealthMonitor::new(raw_ip.to_owned(), runtime.options.interval)?;
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
    username: &str,
    server: &PhysicalServer,
    access_token: &ProtonAccessToken,
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
            let assigned_ips = state
                .assigned_ip
                .clone()
                .map(|assigned_ip| vec![assigned_ip])
                .unwrap_or_else(proton_wireguard_assigned_ips);
            let allowed_ips = default_allowed_ips();
            store.store_wireguard_endpoint_state(WireGuardEndpointStateUpdate {
                outbound_tag: &spec.tag,
                provider: PROTON_PROVIDER,
                identity: Some(username),
                server_id: &state.server_id,
                server_name: &state.server_name,
                endpoint: &state.endpoint,
                peer_public_key: &state.peer_public_key,
                pre_shared_key: None,
                private_key: &state.private_key,
                public_key: &state.public_key,
                assigned_ips: &assigned_ips,
                allowed_ips: &allowed_ips,
                persistent_keepalive_interval: Some(PROTON_WIREGUARD_KEEPALIVE_INTERVAL),
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
    let generated_key_material = if rotate_key {
        Some(generate_key_material())
    } else {
        None
    };
    let private_key_base64 = generated_key_material
        .as_ref()
        .map(|material| Cow::Borrowed(material.private_key_base64.as_str()))
        .or_else(|| {
            current
                .as_ref()
                .map(|state| Cow::Borrowed(state.private_key.as_str()))
        })
        .context("missing outbound certificate private key state")?;
    let public_key_base64 = generated_key_material
        .as_ref()
        .map(|material| Cow::Borrowed(material.public_key_base64.as_str()))
        .or_else(|| {
            current
                .as_ref()
                .map(|state| Cow::Borrowed(state.public_key.as_str()))
        })
        .context("missing outbound certificate public key state")?;

    let api = ProtonApiClient::from_context(&runtime.context)?;
    let should_extend_expiry = current
        .as_ref()
        .and_then(|state| state.profile_id.as_deref())
        .is_some();
    let request = CertificateRequest::persistent_wireguard(
        &*public_key_base64,
        &runtime.context.proton_client.device_name,
        proton_persistent_certificate_features(server)?,
        should_extend_expiry,
    )?;
    let certificate = match api.get_certificate(access_token, &request).await {
        Ok(certificate) => certificate,
        Err(error) => {
            store.store_outbound_certificate_failure(username, &spec.tag, &error.to_string())?;
            return Err(error);
        }
    };
    let current_profile_id = certificate.profile_id.as_deref().or_else(|| {
        current
            .as_ref()
            .and_then(|state| state.profile_id.as_deref())
    });
    let expected_assigned_ip = certificate.assigned_ip.as_deref().or_else(|| {
        current
            .as_ref()
            .and_then(|state| state.assigned_ip.as_deref())
    });
    let expected_endpoint = certificate
        .endpoint
        .as_deref()
        .or_else(|| current.as_ref().map(|state| state.endpoint.as_str()));
    let profile_id = resolve_profile_id_for_extension(
        &api,
        access_token,
        current_profile_id,
        Some(&public_key_base64),
        expected_assigned_ip,
        expected_endpoint,
    )
    .await;
    persist_certificate(
        &store,
        spec,
        username,
        server,
        &private_key_base64,
        &public_key_base64,
        &certificate,
        profile_id.as_deref(),
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn persist_certificate(
    store: &StateStore,
    spec: &ProtonEndpointSpec,
    username: &str,
    server: &PhysicalServer,
    private_key_base64: &str,
    public_key_base64: &str,
    certificate: &CertificateResponse,
    profile_id: Option<&str>,
) -> Result<()> {
    let endpoint = server.proton_wireguard_endpoint().with_context(|| {
        format!(
            "Proton topology entry {} did not include a usable WireGuard endpoint",
            server.name
        )
    })?;
    let peer_public_key = server
        .public_key
        .as_deref()
        .or(certificate.peer_public_key.as_deref())
        .context("Proton certificate and server topology did not include peer public key")?;
    let assigned_ip = PROTON_WIREGUARD_ADDRESS_V4;
    store.store_outbound_certificate_success(OutboundCertificateUpdate {
        outbound_tag: &spec.tag,
        username,
        profile_id,
        server_id: &stable_server_id(server),
        server_name: &server.name,
        endpoint: &endpoint,
        peer_public_key,
        private_key: private_key_base64,
        public_key: public_key_base64,
        assigned_ip,
        expires_at_ms: certificate.expiration_time_ms()? as i64,
        refresh_at_ms: certificate.refresh_time_ms()? as i64,
    })
}

async fn resolve_profile_id_for_extension(
    api: &ProtonApiClient,
    access_token: &ProtonAccessToken,
    current_profile_id: Option<&str>,
    expected_public_key_base64: Option<&str>,
    expected_assigned_ip: Option<&str>,
    expected_endpoint: Option<&str>,
) -> Option<String> {
    if let Some(profile_id) = current_profile_id {
        return Some(profile_id.to_string());
    }

    let profiles = match api.list_persistent_certificates(access_token).await {
        Ok(profiles) => profiles,
        Err(error) => {
            warn!(%error, "failed to list persistent Proton certificate profiles for extension lookup");
            return None;
        }
    };

    profiles
        .into_iter()
        .find(|profile| {
            if profile.profile_id.is_none() {
                return false;
            }

            let matches_public_key = expected_public_key_base64
                .is_some_and(|public_key| profile.matches_client_public_key(public_key));
            if matches_public_key {
                return true;
            }

            match (expected_assigned_ip, expected_endpoint) {
                (Some(assigned_ip), Some(endpoint)) => {
                    profile.assigned_ip.as_deref() == Some(assigned_ip)
                        && profile.endpoint.as_deref() == Some(endpoint)
                }
                (Some(assigned_ip), None) => profile.assigned_ip.as_deref() == Some(assigned_ip),
                (None, Some(endpoint)) => profile.endpoint.as_deref() == Some(endpoint),
                (None, None) => false,
            }
        })
        .and_then(|profile| profile.profile_id)
}

fn proton_persistent_certificate_features(
    server: &PhysicalServer,
) -> Result<PersistentCertificateFeatures> {
    let peer_name = server.name.clone();
    let peer_ip = proton_persistent_peer_ip(server)?;
    let peer_public_key = server
        .public_key
        .as_deref()
        .context("Proton topology server is missing peer public key")?;
    Ok(PersistentCertificateFeatures::proton(
        peer_name,
        peer_ip,
        peer_public_key,
    ))
}

fn proton_persistent_peer_ip(server: &PhysicalServer) -> Result<String> {
    if let Some(peer_ip) = server
        .entry_per_protocol
        .get("WireGuardUDP")
        .and_then(|entry| entry.ipv4.clone())
    {
        return Ok(peer_ip);
    }

    if let Some(peer_ip) = server.entry_ip.clone() {
        return Ok(peer_ip);
    }

    if let Some(peer_ip) = server.exit_ip.clone() {
        return Ok(peer_ip);
    }

    server
        .domain
        .clone()
        .context("Proton topology server is missing a usable peer IP")
}
async fn refresh_topology(runtime: &SupervisorRuntime, account_name: &str) -> Result<()> {
    let output = topology_output_path(&runtime.context, &runtime.render);
    let account = runtime.proton_accounts.get_required(account_name)?;
    let token = access_token_for_account(runtime, account_name).await?;
    let api = ProtonApiClient::from_context(&runtime.context)?;
    match api
        .get_logicals(
            &token,
            runtime.topology.country.as_deref(),
            runtime.topology.netzone.as_deref(),
        )
        .await
    {
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
                Some(&account.username),
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

async fn access_token_for_account(
    runtime: &SupervisorRuntime,
    account_name: &str,
) -> Result<ProtonAccessToken> {
    if let Some(access_token) = &runtime.options.access_token {
        if runtime.proton_accounts.len() > 1 {
            anyhow::bail!(
                "--access-token/PSO_PROTON_ACCESS_TOKEN cannot be shared across multiple Proton accounts; configure per-account credentials or stored sessions"
            );
        }
        return Ok(ProtonAccessToken::new(
            access_token.clone(),
            stored_uid_for_account(runtime, account_name),
        ));
    }

    let token_state = runtime
        .token_states
        .get(account_name)
        .with_context(|| format!("missing token state for account {account_name}"))?;
    let mut token_state = token_state.lock().await;
    let account = runtime.proton_accounts.get_required(account_name)?;
    ensure_account_access_token(&runtime.context, account, &mut token_state)
        .await
        .with_context(|| {
            format!(
                "failed to obtain Proton access token for account {}",
                account.name
            )
        })
}

fn topology_account_name(runtime: &SupervisorRuntime) -> Option<String> {
    runtime
        .topology
        .account
        .clone()
        .or_else(|| first_proton_account_name(&runtime.specs))
}

fn first_proton_account_name(specs: &[EndpointSpec]) -> Option<String> {
    specs.iter().find_map(|spec| match spec {
        EndpointSpec::Proton(spec) => Some(spec.account.clone()),
        EndpointSpec::StaticWireGuard(_) => None,
    })
}

fn endpoint_username<'a>(
    runtime: &'a SupervisorRuntime,
    spec: &'a EndpointSpec,
) -> Option<&'a str> {
    match spec {
        EndpointSpec::Proton(spec) => runtime
            .proton_accounts
            .get(&spec.account)
            .map(|account| account.username.as_str()),
        EndpointSpec::StaticWireGuard(_) => None,
    }
}

fn stored_uid_for_account(runtime: &SupervisorRuntime, account_name: &str) -> Option<String> {
    let account = runtime.proton_accounts.get(account_name)?;
    StateStore::open(&runtime.context)
        .ok()?
        .load_proton_session(&account.username)
        .ok()
        .map(|state| state.uid)
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
