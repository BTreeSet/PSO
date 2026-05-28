use anyhow::{Context, Result};
use serde_json::json;

use super::SupervisorRuntime;
use crate::api::ProtonApiClient;
use crate::model::{LogicalServer, ProtonLogicalResponse};
use crate::state::{StateStore, topology_state_file, write_state_file};
use crate::supervisor_render::topology_output_path;

pub(crate) async fn refresh_topology(runtime: &SupervisorRuntime, username: &str) -> Result<()> {
    let output = topology_output_path(&runtime.context, &runtime.render);
    let user = runtime.proton_users.get_required(username)?;
    let token = super::proton::access_token_for_username(runtime, username).await?;
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
                Some(&user.username),
                None,
                "topology_refreshed",
                None,
            )?;
        }
        Err(error) => {
            load_topology(&runtime.context, &runtime.render, &runtime.topology).with_context(
                || format!("topology fetch failed and no usable fallback was found: {error:#}"),
            )?;
            tracing::warn!(%error, "using existing topology state after fetch failure");
        }
    }
    Ok(())
}

pub(crate) fn load_topology(
    context: &crate::config::RuntimeContext,
    render: &crate::config::RenderConfig,
    topology: &crate::config::TopologyConfig,
) -> Result<Vec<LogicalServer>> {
    let primary = topology_output_path(context, render);
    let state = topology_state_file(context);
    let fallback = topology.fallback_topology.as_ref();
    for path in [Some(&primary), Some(&state), fallback]
        .into_iter()
        .flatten()
    {
        if path.exists() {
            let response: ProtonLogicalResponse = crate::config::read_json(path)?;
            return Ok(response.into_servers());
        }
    }
    anyhow::bail!("no topology file is available for supervisor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProtonClientProfile, RenderConfig, RuntimeContext, TopologyConfig};
    use crate::state::topology_state_file;
    use std::fs;
    use std::path::Path;

    fn runtime_context(state_dir: &Path) -> RuntimeContext {
        RuntimeContext {
            api_base_url: "https://example.invalid/api".into(),
            state_dir: state_dir.to_path_buf(),
            proton_client: ProtonClientProfile::default(),
        }
    }

    fn write_logicals(path: &Path, name: &str) {
        let value = serde_json::json!({
            "LogicalServers": [{
                "Name": name,
                "ExitCountry": "US"
            }]
        });
        fs::write(path, serde_json::to_string(&value).unwrap()).unwrap();
    }

    #[test]
    fn load_topology_prefers_primary_then_state_then_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");
        let context = runtime_context(&state_dir);
        let render = RenderConfig {
            topology: Some(primary.clone()),
            ..Default::default()
        };
        let topology = TopologyConfig {
            fallback_topology: Some(fallback.clone()),
            ..Default::default()
        };
        let state = topology_state_file(&context);

        write_logicals(&primary, "primary");
        write_logicals(&state, "state");
        write_logicals(&fallback, "fallback");

        let servers = load_topology(&context, &render, &topology).unwrap();
        assert_eq!(servers[0].name, "primary");

        fs::remove_file(&primary).unwrap();
        let servers = load_topology(&context, &render, &topology).unwrap();
        assert_eq!(servers[0].name, "state");

        fs::remove_file(&state).unwrap();
        let servers = load_topology(&context, &render, &topology).unwrap();
        assert_eq!(servers[0].name, "fallback");
    }
}
