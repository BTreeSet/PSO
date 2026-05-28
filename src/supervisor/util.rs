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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TopologyConfig;
    use crate::filter::{ServerFilter, SortMode};
    use crate::model::PhysicalServer;
    use crate::provider::WireGuardServerFilter;
    use std::collections::BTreeMap;

    fn proton_spec(username: &str) -> EndpointSpec {
        EndpointSpec::Proton(super::super::ProtonEndpointSpec {
            tag: "proton-outbound".into(),
            username: username.into(),
            filter: ServerFilter {
                country: None,
                city: None,
                tier: None,
                features: None,
                max_load: None,
                status: None,
                sort_by: SortMode::LoadAsc,
            },
            health_proxy_url: None,
        })
    }

    fn wireguard_spec() -> EndpointSpec {
        EndpointSpec::StaticWireGuard(super::super::StaticWireGuardEndpointSpec {
            tag: "wireguard-outbound".into(),
            provider: "provider".into(),
            filter: WireGuardServerFilter {
                country: None,
                city: None,
                region: None,
                server: None,
                features: Vec::new(),
                max_load: None,
                status: None,
                sort_by: Default::default(),
            },
            local_address: Vec::new(),
            allowed_ips: Vec::new(),
            pre_shared_key: None,
            persistent_keepalive_interval: None,
            reserved: None,
            health_proxy_url: None,
        })
    }

    fn physical_server(id: &str, name: &str) -> PhysicalServer {
        PhysicalServer {
            id: id.into(),
            name: name.into(),
            entry_ip: None,
            entry_ipv6: None,
            entry_per_protocol: BTreeMap::new(),
            exit_ip: None,
            domain: None,
            label: None,
            status: 1,
            load: None,
            public_key: None,
            generation: None,
            services_down: None,
            services_down_reason: None,
        }
    }

    #[test]
    fn topology_username_prefers_explicit_config() {
        let topology = TopologyConfig {
            username: Some("alice".into()),
            ..Default::default()
        };

        let username = topology_username(&topology, &[proton_spec("bob")]);

        assert_eq!(username.as_deref(), Some("alice"));
    }

    #[test]
    fn topology_username_falls_back_to_first_proton_user() {
        let topology = TopologyConfig::default();

        let username = topology_username(&topology, &[wireguard_spec(), proton_spec("bob")]);

        assert_eq!(username.as_deref(), Some("bob"));
    }

    #[test]
    fn endpoint_username_distinguishes_endpoint_types() {
        assert_eq!(endpoint_username(&proton_spec("bob")), Some("bob"));
        assert_eq!(endpoint_username(&wireguard_spec()), None);
    }

    #[test]
    fn stable_server_id_prefers_non_empty_id() {
        let server = physical_server("server-id", "server-name");

        assert_eq!(stable_server_id(&server), "server-id");
    }

    #[test]
    fn stable_server_id_falls_back_to_name() {
        let server = physical_server("", "server-name");

        assert_eq!(stable_server_id(&server), "server-name");
    }
}
