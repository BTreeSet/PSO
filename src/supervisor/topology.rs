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
