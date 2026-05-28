use anyhow::{Context, Result};
use serde_json::json;

use super::{StaticWireGuardEndpointSpec, SupervisorRuntime, loops::probe_endpoint_once};
use crate::crypto::generate_key_material;
use crate::provider::{
    WireGuardEndpointOverrides, resolve_wireguard_endpoint, select_wireguard_server,
};
use crate::provider_discovery::resolve_wireguard_provider_catalog;
use crate::state::{StateStore, WireGuardEndpointStateUpdate};
use crate::supervisor_render::rendered_output_path;

pub(crate) async fn process_static_wireguard_endpoint(
    runtime: &SupervisorRuntime,
    spec: &StaticWireGuardEndpointSpec,
    force_refresh: bool,
) -> Result<bool> {
    let state_changed = ensure_static_wireguard_endpoint_state(
        &runtime.context,
        &runtime.providers,
        spec,
        force_refresh,
    )
    .await?;
    if state_changed || !rendered_output_path(&runtime.context, &runtime.render).exists() {
        return Ok(true);
    }

    let store = StateStore::open(&runtime.context)?;
    let probe = probe_endpoint_once(
        &runtime.context,
        &runtime.options,
        None,
        &spec.tag,
        spec.health_proxy_url.as_deref(),
    )
    .await?;

    if probe.status == crate::health::HealthStatus::Healthy {
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
    ensure_static_wireguard_endpoint_state(&runtime.context, &runtime.providers, spec, true).await
}

pub(crate) async fn ensure_static_wireguard_endpoint_state(
    context: &crate::config::RuntimeContext,
    providers: &crate::provider::ProvidersConfig,
    spec: &StaticWireGuardEndpointSpec,
    force_reselect: bool,
) -> Result<bool> {
    let provider = providers
        .wireguard_provider(&spec.provider)
        .with_context(|| {
            format!(
                "template endpoint {} references unknown WireGuard provider '{}'",
                spec.tag, spec.provider
            )
        })?;
    let provider = resolve_wireguard_provider_catalog(provider).await?;
    let store = StateStore::open(context)?;
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
    let private_key_base64: &str = generated_key_material
        .as_ref()
        .map(|material| material.private_key_base64.as_str())
        .or_else(|| current.as_ref().map(|state| state.private_key.as_str()))
        .context("missing WireGuard private key state")?;
    let public_key_base64: &str = generated_key_material
        .as_ref()
        .map(|material| material.public_key_base64.as_str())
        .or_else(|| current.as_ref().map(|state| state.public_key.as_str()))
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
        private_key: private_key_base64,
        public_key: public_key_base64,
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
