use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::config::{RenderConfig, RuntimeContext};
use crate::deploy::{DeployPlan, deploy_with_sighup, validate_singbox_config};
use crate::filter::ServerFilter;
use crate::process::resolve_singbox_pid;
use crate::provider::{PROTON_PROVIDER, WireGuardServerFilter, normalize_provider_name};
use crate::session::UserSession;
use crate::singbox_adapter::split_endpoint;
use crate::state::{StateStore, WireGuardEndpointState};
use crate::supervisor::{
    EndpointSpec, ProtonEndpointSpec, StaticWireGuardEndpointSpec, SupervisorRuntime,
};
use crate::users::ProtonUserRegistry;

pub(crate) async fn render_and_deploy(runtime: &SupervisorRuntime) -> Result<()> {
    let rendered = render_from_state(&runtime.template, &runtime.context, &runtime.specs)?;

    let output_path = rendered_output_path(&runtime.context, &runtime.render);
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let rendered_text = serde_json::to_string_pretty(&rendered)?;
    std::fs::write(&output_path, &rendered_text)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    let config_hash = hex::encode(Sha256::digest(rendered_text.as_bytes()));
    let outbound_tags_json = serde_json::to_string(
        &runtime
            .specs
            .iter()
            .map(EndpointSpec::tag)
            .collect::<Vec<_>>(),
    )?;

    let store = StateStore::open(&runtime.context)?;
    let active_config = runtime.render.active_config.clone();
    if runtime.render.dry_run.unwrap_or(false) {
        let active_config_label = active_config
            .as_ref()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| "validation-only".to_string());
        store.record_config_deployment(
            &config_hash,
            &outbound_tags_json,
            &active_config_label,
            true,
            None,
        )?;
        return Ok(());
    }

    let singbox_bin = runtime
        .render
        .singbox_bin
        .clone()
        .unwrap_or_else(|| PathBuf::from("sing-box"));
    validate_singbox_config(&singbox_bin, &output_path).await?;
    if let Some(active_config) = active_config {
        let singbox_pid = match runtime.render.singbox_pid {
            Some(pid) => pid,
            None => resolve_singbox_pid(&singbox_bin, "singbox_pid")?,
        };
        deploy_with_sighup(&DeployPlan {
            singbox_bin,
            rendered_tmp: output_path.clone(),
            active_config: active_config.clone(),
            singbox_pid,
        })
        .await?;
        store.record_config_deployment(
            &config_hash,
            &outbound_tags_json,
            &active_config.to_string_lossy(),
            true,
            None,
        )?;
        info!(path = %active_config.display(), "deployed coalesced sing-box config");
    } else {
        store.record_config_deployment(
            &config_hash,
            &outbound_tags_json,
            &output_path.to_string_lossy(),
            true,
            None,
        )?;
        info!(path = %output_path.display(), "rendered coalesced sing-box config");
    }
    Ok(())
}

pub(crate) fn endpoint_specs(template: &Value) -> Result<Vec<EndpointSpec>> {
    let mut specs = Vec::new();
    let mut seen = BTreeSet::new();
    for section in ["endpoints", "outbounds"] {
        let Some(entries) = template.get(section).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            let object = entry
                .as_object()
                .ok_or_else(|| anyhow!("{section} entries must be JSON objects"))?;
            let Some(provider) = object.get("provider").and_then(Value::as_str) else {
                continue;
            };
            let provider = normalize_provider_name(provider);
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("provider wireguard entry is missing tag"))?
                .to_string();
            if !seen.insert(tag.clone()) {
                anyhow::bail!("duplicate provider wireguard tag {tag}");
            }

            let health_proxy_url = object
                .get("health")
                .and_then(|value| value.get("proxy_url"))
                .and_then(Value::as_str)
                .or_else(|| object.get("health_proxy_url").and_then(Value::as_str))
                .map(ToOwned::to_owned);

            if provider == PROTON_PROVIDER {
                specs.push(EndpointSpec::Proton(parse_proton_spec(
                    object,
                    tag,
                    health_proxy_url,
                )?));
            } else {
                specs.push(EndpointSpec::StaticWireGuard(parse_static_spec(
                    object,
                    provider,
                    tag,
                    health_proxy_url,
                )?));
            }
        }
    }
    Ok(specs)
}

fn parse_proton_spec(
    object: &Map<String, Value>,
    tag: String,
    health_proxy_url: Option<String>,
) -> Result<ProtonEndpointSpec> {
    let username = object
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proton wireguard entry {tag} is missing username"))?
        .to_string();
    let filter: ServerFilter = serde_json::from_value(
        object
            .get("filter")
            .cloned()
            .ok_or_else(|| anyhow!("proton wireguard entry {tag} is missing filter"))?,
    )
    .with_context(|| format!("invalid filter for proton wireguard entry {tag}"))?;

    Ok(ProtonEndpointSpec {
        tag,
        username,
        filter,
        health_proxy_url,
    })
}

fn parse_static_spec(
    object: &Map<String, Value>,
    provider: String,
    tag: String,
    health_proxy_url: Option<String>,
) -> Result<StaticWireGuardEndpointSpec> {
    let filter = match object.get("filter") {
        Some(value) => serde_json::from_value::<WireGuardServerFilter>(value.clone())
            .with_context(|| format!("invalid filter for {provider} wireguard entry {tag}"))?,
        None => WireGuardServerFilter::default(),
    };
    let local_address = optional_string_array(object, "local_address")?;
    let allowed_ips = optional_string_array(object, "allowed_ips")?;
    let pre_shared_key = optional_string(object, "pre_shared_key")?;
    let persistent_keepalive_interval = object
        .get("persistent_keepalive_interval")
        .and_then(Value::as_u64)
        .map(u16::try_from)
        .transpose()
        .with_context(|| format!("persistent_keepalive_interval is invalid for {tag}"))?;
    let reserved = match object.get("reserved") {
        Some(value) => {
            let bytes: Vec<u8> = serde_json::from_value(value.clone())
                .with_context(|| format!("reserved must be a 3-byte array for {tag}"))?;
            if bytes.len() != 3 {
                anyhow::bail!("reserved must be a 3-byte array for {tag}");
            }
            Some(bytes)
        }
        None => None,
    };

    Ok(StaticWireGuardEndpointSpec {
        tag,
        provider,
        filter,
        local_address,
        allowed_ips,
        pre_shared_key,
        persistent_keepalive_interval,
        reserved,
        health_proxy_url,
    })
}

pub(crate) fn proton_user_sessions(
    registry: &ProtonUserRegistry,
) -> Result<BTreeMap<String, UserSession>> {
    if registry.is_empty() {
        anyhow::bail!("Proton endpoints require auth.proton.users to declare usernames and tiers")
    }
    Ok(registry.sessions())
}

pub(crate) fn validate_proton_user_bindings(
    specs: &[EndpointSpec],
    registry: &ProtonUserRegistry,
) -> Result<()> {
    let mut assigned_usernames = BTreeSet::new();
    for spec in specs {
        let EndpointSpec::Proton(spec) = spec else {
            continue;
        };
        let user = registry.get_required(&spec.username)?;
        if !assigned_usernames.insert(user.username.clone()) {
            anyhow::bail!(
                "Proton username '{}' is assigned to more than one endpoint; provision one username per active Proton endpoint",
                user.username
            );
        }
    }
    Ok(())
}

pub(crate) fn template_path(config: &RenderConfig) -> PathBuf {
    config
        .template
        .clone()
        .unwrap_or_else(|| PathBuf::from("config.template.json"))
}

pub(crate) fn topology_output_path(context: &RuntimeContext, config: &RenderConfig) -> PathBuf {
    config
        .topology
        .clone()
        .unwrap_or_else(|| context.state_dir.join("logicals.json"))
}

pub(crate) fn rendered_output_path(context: &RuntimeContext, config: &RenderConfig) -> PathBuf {
    config
        .output
        .clone()
        .unwrap_or_else(|| context.state_dir.join("rendered.config.json.tmp"))
}

fn wireguard_states_by_tag(
    context: &RuntimeContext,
    specs: &[EndpointSpec],
) -> Result<BTreeMap<String, WireGuardEndpointState>> {
    let store = StateStore::open(context)?;
    specs
        .iter()
        .map(|spec| {
            let tag = spec.tag();
            let state = store
                .load_wireguard_endpoint_state(tag)?
                .with_context(|| format!("missing WireGuard endpoint state for {tag}"))?;
            Ok((tag.to_string(), state))
        })
        .collect()
}

pub(crate) fn render_from_state(
    template: &Value,
    context: &RuntimeContext,
    specs: &[EndpointSpec],
) -> Result<Value> {
    let mut rendered = template.clone();
    let states = wireguard_states_by_tag(context, specs)?;
    hydrate_wireguard_entries(&mut rendered, &states)?;
    Ok(rendered)
}

fn hydrate_wireguard_entries(
    rendered: &mut Value,
    states: &BTreeMap<String, WireGuardEndpointState>,
) -> Result<()> {
    for section in ["endpoints", "outbounds"] {
        let Some(entries) = rendered.get_mut(section).and_then(Value::as_array_mut) else {
            continue;
        };
        for entry in entries {
            let Some(object) = entry.as_object_mut() else {
                continue;
            };
            if object.get("provider").and_then(Value::as_str).is_none() {
                continue;
            }
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("provider wireguard entry is missing tag"))?;
            let state = states
                .get(tag)
                .with_context(|| format!("missing WireGuard endpoint state for {tag}"))?;
            apply_wireguard_endpoint_state(object, state)?;
        }
    }
    Ok(())
}

fn apply_wireguard_endpoint_state(
    object: &mut Map<String, Value>,
    state: &WireGuardEndpointState,
) -> Result<()> {
    let (peer_address, peer_port) = split_endpoint(&state.endpoint)?;
    object.remove("provider");
    object.remove("user");
    object.remove("username");
    object.remove("identity");
    object.remove("filter");
    object.remove("health");
    object.remove("health_proxy_url");
    object.remove("server");
    object.remove("server_port");
    object.remove("local_address");
    object.remove("allowed_ips");
    object.remove("reserved");
    object.remove("peer_public_key");
    object.remove("pre_shared_key");
    object.entry("system").or_insert(Value::Bool(false));
    object
        .entry("mtu")
        .or_insert(Value::Number(state.mtu.into()));
    object.insert(
        "address".into(),
        Value::Array(
            state
                .assigned_ips
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    object.insert(
        "private_key".into(),
        Value::String(state.private_key.clone()),
    );
    let mut peer = json!({
        "address": peer_address,
        "port": peer_port,
        "public_key": state.peer_public_key,
        "allowed_ips": state.allowed_ips
    });
    if let Some(pre_shared_key) = &state.pre_shared_key {
        peer["pre_shared_key"] = Value::String(pre_shared_key.clone());
    }
    if let Some(keepalive) = state.persistent_keepalive_interval {
        peer["persistent_keepalive_interval"] = Value::Number(keepalive.into());
    }
    if let Some(reserved) = &state.reserved {
        peer["reserved"] = Value::Array(
            reserved
                .iter()
                .map(|value| Value::Number((*value).into()))
                .collect(),
        );
    }
    object.insert("peers".into(), Value::Array(vec![peer]));
    Ok(())
}

fn optional_string_array(object: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    match object.get(key) {
        None => Ok(Vec::new()),
        Some(Value::String(value)) => Ok(vec![value.clone()]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("{key} entries must be strings"))
            })
            .collect(),
        Some(_) => anyhow::bail!("{key} must be a string or string array"),
    }
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => anyhow::bail!("{key} must be a string"),
    }
}
