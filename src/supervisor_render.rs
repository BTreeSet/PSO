use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::config::{RenderConfig, RuntimeContext, SessionEntry};
use crate::deploy::{DeployPlan, deploy_with_sighup, validate_singbox_config};
use crate::filter::ServerFilter;
use crate::process::{find_process_pid, find_process_pid_by_exe};
use crate::session::UserSession;
use crate::singbox_adapter::{default_allowed_ips, split_endpoint};
use crate::state::{OutboundCertificateState, StateStore};
use crate::supervisor::{ProtonEndpointSpec, SupervisorRuntime};

pub(crate) async fn render_and_deploy(runtime: &SupervisorRuntime) -> Result<()> {
    let mut rendered = runtime.template.clone();
    let states = certificate_states_by_tag(&runtime.context, &runtime.specs)?;
    hydrate_wireguard_entries(&mut rendered, &states)?;

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
            .map(|spec| spec.tag.as_str())
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
            None => resolve_singbox_pid(&singbox_bin)?,
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

pub(crate) fn proton_endpoint_specs(template: &Value) -> Result<Vec<ProtonEndpointSpec>> {
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
            if object.get("provider").and_then(Value::as_str) != Some("proton") {
                continue;
            }
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("proton wireguard entry is missing tag"))?
                .to_string();
            if !seen.insert(tag.clone()) {
                anyhow::bail!("duplicate proton wireguard tag {tag}");
            }
            let username = object
                .get("user")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("proton wireguard entry {tag} is missing user"))?
                .to_string();
            let filter: ServerFilter = serde_json::from_value(
                object
                    .get("filter")
                    .cloned()
                    .ok_or_else(|| anyhow!("proton wireguard entry {tag} is missing filter"))?,
            )
            .with_context(|| format!("invalid filter for proton wireguard entry {tag}"))?;
            let health_proxy_url = object
                .get("health")
                .and_then(|value| value.get("proxy_url"))
                .and_then(Value::as_str)
                .or_else(|| object.get("health_proxy_url").and_then(Value::as_str))
                .map(ToOwned::to_owned);
            specs.push(ProtonEndpointSpec {
                tag,
                username,
                filter,
                health_proxy_url,
            });
        }
    }
    Ok(specs)
}

pub(crate) fn session_map(entries: &[SessionEntry]) -> Result<BTreeMap<String, UserSession>> {
    if entries.is_empty() {
        anyhow::bail!("run requires render.sessions to declare account tiers")
    }
    Ok(entries
        .iter()
        .map(|entry| {
            (
                entry.username.clone(),
                UserSession::new(entry.username.clone(), entry.tier.clone()),
            )
        })
        .collect())
}

pub(crate) fn ensure_sessions_exist(
    specs: &[ProtonEndpointSpec],
    sessions: &BTreeMap<String, UserSession>,
) -> Result<()> {
    for spec in specs {
        if !sessions.contains_key(&spec.username) {
            anyhow::bail!(
                "template endpoint {} uses {}, but render.sessions has no tier for that account",
                spec.tag,
                spec.username
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

fn certificate_states_by_tag(
    context: &RuntimeContext,
    specs: &[ProtonEndpointSpec],
) -> Result<BTreeMap<String, OutboundCertificateState>> {
    let store = StateStore::open(context)?;
    specs
        .iter()
        .map(|spec| {
            let state = store
                .load_outbound_certificate(&spec.tag)?
                .with_context(|| format!("missing certificate state for {}", spec.tag))?;
            Ok((spec.tag.clone(), state))
        })
        .collect()
}

fn hydrate_wireguard_entries(
    rendered: &mut Value,
    states: &BTreeMap<String, OutboundCertificateState>,
) -> Result<()> {
    for section in ["endpoints", "outbounds"] {
        let Some(entries) = rendered.get_mut(section).and_then(Value::as_array_mut) else {
            continue;
        };
        for entry in entries {
            let Some(object) = entry.as_object_mut() else {
                continue;
            };
            if object.get("provider").and_then(Value::as_str) != Some("proton") {
                continue;
            }
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("proton wireguard entry is missing tag"))?;
            let state = states
                .get(tag)
                .with_context(|| format!("missing certificate state for {tag}"))?;
            apply_wireguard_endpoint_state(object, state)?;
        }
    }
    Ok(())
}

fn apply_wireguard_endpoint_state(
    object: &mut Map<String, Value>,
    state: &OutboundCertificateState,
) -> Result<()> {
    let (peer_address, peer_port) = split_endpoint(&state.endpoint)?;
    object.remove("provider");
    object.remove("user");
    object.remove("filter");
    object.remove("health");
    object.remove("health_proxy_url");
    object.remove("server");
    object.remove("server_port");
    object.remove("local_address");
    object.remove("peer_public_key");
    object.entry("system").or_insert(Value::Bool(false));
    object.entry("mtu").or_insert(Value::Number(1408.into()));
    object.insert(
        "address".into(),
        Value::Array(vec![Value::String(
            state
                .assigned_ip
                .clone()
                .context("certificate state is missing assigned IP")?,
        )]),
    );
    object.insert(
        "private_key".into(),
        Value::String(state.private_key.clone()),
    );
    object.insert(
        "peers".into(),
        json!([{
            "address": peer_address,
            "port": peer_port,
            "public_key": state.peer_public_key,
            "allowed_ips": default_allowed_ips(),
            "persistent_keepalive_interval": 25
        }]),
    );
    Ok(())
}

fn resolve_singbox_pid(singbox_bin: &Path) -> Result<i32> {
    match find_process_pid_by_exe(singbox_bin) {
        Ok(Some(pid)) => Ok(pid),
        Ok(None) => find_process_pid("sing-box").with_context(|| {
            format!(
                "sing-box process was not found for executable {}; pass singbox_pid to target an explicit process",
                singbox_bin.display()
            )
        }),
        Err(error) => find_process_pid("sing-box").with_context(|| {
            format!(
                "failed to match sing-box executable path ({error:#}); pass singbox_pid to target an explicit process"
            )
        }),
    }
}
