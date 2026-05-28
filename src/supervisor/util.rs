use super::EndpointSpec;
use crate::config::RuntimeContext;
use crate::model::PhysicalServer;
use crate::state::StateStore;
use crate::users::ProtonUserRegistry;

pub(crate) fn topology_username(
    topology: &crate::config::TopologyConfig,
    specs: &[EndpointSpec],
) -> Option<String> {
    topology
        .username
        .clone()
        .or_else(|| first_proton_username(specs))
}

pub(crate) fn first_proton_username(specs: &[EndpointSpec]) -> Option<String> {
    specs.iter().find_map(|spec| match spec {
        EndpointSpec::Proton(spec) => Some(spec.username.clone()),
        EndpointSpec::StaticWireGuard(_) => None,
    })
}

pub(crate) fn endpoint_username(spec: &EndpointSpec) -> Option<&str> {
    match spec {
        EndpointSpec::Proton(spec) => Some(spec.username.as_str()),
        EndpointSpec::StaticWireGuard(_) => None,
    }
}

pub(crate) fn stored_uid_for_username(
    context: &RuntimeContext,
    proton_users: &ProtonUserRegistry,
    username: &str,
) -> Option<String> {
    let username = if proton_users.len() == 1 {
        proton_users.first_username().unwrap_or(username)
    } else {
        username
    };
    StateStore::open(context)
        .ok()?
        .load_proton_session(username)
        .ok()
        .map(|state| state.uid)
}

pub(crate) fn stable_server_id(server: &PhysicalServer) -> String {
    if server.id.is_empty() {
        server.name.clone()
    } else {
        server.id.clone()
    }
}

pub(crate) fn record_runtime_error(
    context: &RuntimeContext,
    username: Option<&str>,
    outbound_tag: Option<&str>,
    event_type: &str,
    error: &anyhow::Error,
) {
    if let Ok(store) = StateStore::open(context) {
        let details =
            serde_json::to_string(&serde_json::json!({ "error": error.to_string() })).ok();
        let _ = store.record_event(username, outbound_tag, event_type, details.as_deref());
    }
}
