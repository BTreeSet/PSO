use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value, json};

use crate::filter::{ServerFilter, select_target};
use crate::model::LogicalServer;
use crate::provisioning::WireGuardProvisioner;
use crate::session::SessionStore;

pub fn hydrate_template(
    template: &Value,
    sessions: &SessionStore,
    topology: &[LogicalServer],
    provisioner: &impl WireGuardProvisioner,
) -> Result<Value> {
    let mut rendered = template.clone();
    let outbounds = rendered
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("template must contain an outbounds array"))?;

    for outbound in outbounds {
        hydrate_outbound(outbound, sessions, topology, provisioner)?;
    }

    Ok(rendered)
}

fn hydrate_outbound(
    outbound: &mut Value,
    sessions: &SessionStore,
    topology: &[LogicalServer],
    provisioner: &impl WireGuardProvisioner,
) -> Result<()> {
    let object = outbound
        .as_object_mut()
        .ok_or_else(|| anyhow!("outbound entries must be JSON objects"))?;

    let provider = object.get("provider").and_then(Value::as_str);
    if provider != Some("proton") {
        return Ok(());
    }

    let tag = object
        .get("tag")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proton outbound is missing tag"))?
        .to_string();
    let username = object
        .get("account")
        .or_else(|| object.get("user"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("proton outbound {tag} is missing account"))?
        .to_string();
    let filter_value = object
        .get("filter")
        .cloned()
        .ok_or_else(|| anyhow!("proton outbound {tag} is missing filter"))?;
    let filter: ServerFilter = serde_json::from_value(filter_value)
        .with_context(|| format!("invalid filter for proton outbound {tag}"))?;

    let session = sessions.get(&username)?;
    let selected = select_target(topology, &filter, &session)?;
    let credentials = provisioner.provision(&session, &tag, &selected.physical)?;

    object.remove("provider");
    object.remove("user");
    object.remove("filter");
    object.insert(
        "address".into(),
        Value::Array(credentials.address.into_iter().map(Value::String).collect()),
    );
    insert_string(object, "private_key", credentials.private_key);
    object.entry("system").or_insert(Value::Bool(false));
    object.entry("mtu").or_insert(Value::Number(1408.into()));
    object.insert(
        "peers".into(),
        json!([{
            "address": credentials.peer_address,
            "port": credentials.peer_port,
            "public_key": credentials.peer_public_key,
            "allowed_ips": credentials.allowed_ips,
            "persistent_keepalive_interval": 25
        }]),
    );

    Ok(())
}

fn insert_string(object: &mut Map<String, Value>, key: &str, value: String) {
    object.insert(key.to_string(), Value::String(value));
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::{LogicalServer, PhysicalServer};
    use crate::provisioning::LocalKeyProvisioner;
    use crate::session::{SessionStore, UserSession};

    #[test]
    fn strips_control_plane_keys_and_injects_wireguard_fields() {
        let template = json!({
            "outbounds": [{
                "type": "wireguard",
                "tag": "proton-free-jp",
                "provider": "proton",
                "account": "bob@example.com",
                "filter": { "country": ["JP"], "tier": "Free" }
            }]
        });
        let sessions = SessionStore::new();
        sessions.insert(UserSession::new("bob@example.com", "Free"));
        let rendered = hydrate_template(
            &template,
            &sessions,
            &[LogicalServer {
                id: "jp-free".into(),
                name: "JP-FREE#1".into(),
                entry_country: Some("JP".into()),
                exit_country: "JP".into(),
                domain: None,
                city: None,
                region: None,
                tier: 0,
                features: 0,
                load: 10,
                score: 1.0,
                status: 1,
                servers: vec![PhysicalServer {
                    id: "jp-physical".into(),
                    name: "jp-physical".into(),
                    entry_ip: Some("198.51.100.10".into()),
                    entry_ipv6: None,
                    exit_ip: None,
                    domain: None,
                    label: None,
                    status: 1,
                    load: Some(10),
                    public_key: Some("peer-key".into()),
                    generation: None,
                    services_down: Some(0),
                    services_down_reason: None,
                }],
            }],
            &LocalKeyProvisioner::default(),
        )
        .unwrap();

        let outbound = &rendered["outbounds"][0];
        assert!(outbound.get("provider").is_none());
        assert_eq!(outbound["address"][0], "10.2.0.2/32");
        assert_eq!(outbound["peers"][0]["address"], "198.51.100.10");
        assert_eq!(outbound["peers"][0]["port"], 51820);
        assert_eq!(outbound["peers"][0]["public_key"], "peer-key");
        assert!(outbound["private_key"].as_str().unwrap().len() > 40);
    }
}
