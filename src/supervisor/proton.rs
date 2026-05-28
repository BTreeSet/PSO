use anyhow::{Context, Result};
use serde_json::json;
use tracing::warn;

use super::{
    ProtonEndpointSpec, SupervisorRuntime, loops::probe_endpoint_once, topology::load_topology,
    util::stable_server_id,
};
use crate::api::{
    CertificateRequest, CertificateResponse, PersistentCertificateFeatures, ProtonAccessToken,
    ProtonApiClient,
};
use crate::config::RuntimeContext;
use crate::crypto::generate_key_material;
use crate::current_time_ms;
use crate::filter::select_target;
use crate::health::HealthStatus;
use crate::model::PhysicalServer;
use crate::proton::{
    CachedAccessToken, ConfiguredLoginOptions, PROTON_WIREGUARD_ADDRESS_V4,
    PROTON_WIREGUARD_KEEPALIVE_INTERVAL, ensure_user_access_token, login_configured_user,
    persist_proton_session, proton_wireguard_assigned_ips,
};
use crate::singbox_adapter::default_allowed_ips;
use crate::state::{OutboundCertificateUpdate, StateStore, WireGuardEndpointStateUpdate};
use crate::supervisor_render::rendered_output_path;
use crate::users::ProtonUser;

const MAX_CERT_FAILURES_BEFORE_KEY_ROTATION: i64 = 4;

pub(crate) async fn keepalive_proton_session(
    runtime: &SupervisorRuntime,
    username: &str,
) -> Result<()> {
    let access_token = access_token_for_username(runtime, username).await?;
    let api = ProtonApiClient::from_context(&runtime.context)?;
    let _ = api.list_sessions(&access_token).await?;
    Ok(())
}

pub(crate) async fn access_token_for_username(
    runtime: &SupervisorRuntime,
    username: &str,
) -> Result<ProtonAccessToken> {
    if let Some(access_token) = &runtime.options.access_token {
        if runtime.proton_users.len() > 1 {
            anyhow::bail!(
                "--access-token/PSO_PROTON_ACCESS_TOKEN cannot be shared across multiple Proton usernames; configure per-username credentials or stored sessions"
            );
        }
        return Ok(ProtonAccessToken::new(
            access_token.clone(),
            super::util::stored_uid_for_username(&runtime.context, &runtime.proton_users, username),
        ));
    }

    let token_state = runtime
        .token_states
        .get(username)
        .with_context(|| format!("missing token state for username {username}"))?;
    let mut token_state = token_state.lock().await;
    let user = runtime.proton_users.get_required(username)?;
    ensure_user_access_token(&runtime.context, user, &mut token_state)
        .await
        .with_context(|| {
            format!(
                "failed to obtain Proton access token for username {}",
                user.username
            )
        })
}

pub(crate) async fn bootstrap_proton_session(
    runtime: &SupervisorRuntime,
    user: &ProtonUser,
    cache: &mut CachedAccessToken,
) -> Result<()> {
    user.ensure_can_login_headless()
        .with_context(|| format!("Proton user '{}' cannot recover headlessly", user.username))?;

    let tokens = login_configured_user(
        &runtime.context,
        user,
        ConfiguredLoginOptions {
            password_override: None,
            password_file_override: None,
            totp_override: None,
            no_prompt_override: true,
            human_verification_token: None,
            debug_http: false,
        },
    )
    .await
    .with_context(|| format!("failed to recover Proton session for {}", user.username))?;

    persist_proton_session(&runtime.context, &user.username, None, &tokens)?;
    cache.store(&tokens, tokens.uid.as_deref());
    Ok(())
}

pub(crate) async fn process_proton_endpoint(
    runtime: &SupervisorRuntime,
    spec: &ProtonEndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    let topology = load_topology(&runtime.context, &runtime.render, &runtime.topology)?;
    let session = runtime
        .sessions
        .get(&spec.username)
        .with_context(|| format!("missing configured Proton username {}", spec.username))?;
    let selected = select_target(&topology, &spec.filter, session)?;
    let access_token = access_token_for_username(runtime, &spec.username).await?;
    let cert_changed = ensure_certificate(
        &runtime.context,
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
        &runtime.context,
        &runtime.options,
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
        &runtime.context,
        spec,
        &session.username,
        &selected.physical,
        &access_token,
        true,
    )
    .await?;
    Ok(true)
}

pub(crate) async fn ensure_certificate(
    context: &RuntimeContext,
    spec: &ProtonEndpointSpec,
    username: &str,
    server: &PhysicalServer,
    access_token: &ProtonAccessToken,
    force_refresh: bool,
) -> Result<bool> {
    let store = StateStore::open(context)?;
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
                provider: crate::provider::PROTON_PROVIDER,
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
    let private_key_base64: &str = generated_key_material
        .as_ref()
        .map(|material| material.private_key_base64.as_str())
        .or_else(|| current.as_ref().map(|state| state.private_key.as_str()))
        .context("missing outbound certificate private key state")?;
    let public_key_base64: &str = generated_key_material
        .as_ref()
        .map(|material| material.public_key_base64.as_str())
        .or_else(|| current.as_ref().map(|state| state.public_key.as_str()))
        .context("missing outbound certificate public key state")?;

    let api = ProtonApiClient::from_context(context)?;
    let should_extend_expiry = current
        .as_ref()
        .and_then(|state| state.profile_id.as_deref())
        .is_some();
    let request = CertificateRequest::persistent_wireguard(
        public_key_base64,
        &context.proton_client.device_name,
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
        Some(public_key_base64),
        expected_assigned_ip,
        expected_endpoint,
    )
    .await;
    persist_certificate(
        &store,
        spec,
        username,
        server,
        private_key_base64,
        public_key_base64,
        &certificate,
        profile_id.as_deref(),
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_certificate(
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

pub(crate) async fn resolve_profile_id_for_extension(
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

pub(crate) fn proton_persistent_certificate_features(
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

pub(crate) fn proton_persistent_peer_ip(server: &PhysicalServer) -> Result<String> {
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
