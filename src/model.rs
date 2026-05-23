use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct LogicalServer {
    #[serde(alias = "ID", alias = "Id", default)]
    pub id: String,
    #[serde(alias = "Name", default)]
    pub name: String,
    #[serde(alias = "EntryCountry", alias = "entry_country", default)]
    pub entry_country: Option<String>,
    #[serde(alias = "ExitCountry", alias = "exit_country")]
    pub exit_country: String,
    #[serde(alias = "Domain", default)]
    pub domain: Option<String>,
    #[serde(alias = "City", default)]
    pub city: Option<String>,
    #[serde(alias = "Region", default)]
    pub region: Option<String>,
    #[serde(alias = "Tier", default)]
    pub tier: u8,
    #[serde(alias = "Features", default)]
    pub features: u64,
    #[serde(alias = "Load", default)]
    pub load: u8,
    #[serde(alias = "Score", default)]
    pub score: f64,
    #[serde(alias = "Status", default = "default_status")]
    pub status: i32,
    #[serde(alias = "Servers", default)]
    pub servers: Vec<PhysicalServer>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PhysicalServer {
    #[serde(alias = "ID", alias = "Id", default)]
    pub id: String,
    #[serde(alias = "Name", default)]
    pub name: String,
    #[serde(alias = "EntryIP", alias = "entry_ip", default)]
    pub entry_ip: Option<String>,
    #[serde(alias = "EntryIPv6", alias = "entry_ipv6", default)]
    pub entry_ipv6: Option<String>,
    #[serde(alias = "ExitIP", alias = "exit_ip", default)]
    pub exit_ip: Option<String>,
    #[serde(alias = "Domain", default)]
    pub domain: Option<String>,
    #[serde(alias = "Label", default)]
    pub label: Option<String>,
    #[serde(alias = "Status", default = "default_status")]
    pub status: i32,
    #[serde(alias = "Load", default)]
    pub load: Option<u8>,
    #[serde(alias = "X25519PublicKey", alias = "PublicKey", default)]
    pub public_key: Option<String>,
    #[serde(alias = "Generation", default)]
    pub generation: Option<u64>,
    #[serde(alias = "ServicesDown", default)]
    pub services_down: Option<u64>,
    #[serde(alias = "ServicesDownReason", default)]
    pub services_down_reason: Option<String>,
}

pub fn default_status() -> i32 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ProtonLogicalResponse {
    Bare(Vec<LogicalServer>),
    Wrapped {
        #[serde(alias = "LogicalServers")]
        logical_servers: Vec<LogicalServer>,
    },
}

impl ProtonLogicalResponse {
    pub fn into_servers(self) -> Vec<LogicalServer> {
        match self {
            Self::Bare(servers) => servers,
            Self::Wrapped { logical_servers } => logical_servers,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn decodes_proton_logicals_payload_shape() {
        let response: ProtonLogicalResponse = serde_json::from_value(json!({
            "LogicalServers": [{
                "Name": "NL-FREE#15",
                "EntryCountry": "NL",
                "ExitCountry": "NL",
                "Domain": "node-nl-05.protonvpn.net",
                "Tier": 0,
                "Features": 16,
                "City": "Amsterdam",
                "Score": 4.99,
                "ID": "logical-id",
                "Status": 1,
                "Load": 89,
                "Servers": [{
                    "EntryIP": "89.39.107.113",
                    "EntryIPv6": "2a00:7c80:0:3ad::10",
                    "ExitIP": "89.39.107.113",
                    "Domain": "node-nl-05.protonvpn.net",
                    "ID": "physical-id",
                    "Label": "0",
                    "X25519PublicKey": "UIV6mDfDCun6PrjT7kFrpl02eEwqIa/piXoSKm1ybBU=",
                    "Generation": 0,
                    "Status": 1,
                    "ServicesDown": 0,
                    "ServicesDownReason": null
                }]
            }]
        }))
        .unwrap();

        let servers = response.into_servers();
        assert_eq!(
            servers[0].domain.as_deref(),
            Some("node-nl-05.protonvpn.net")
        );
        assert_eq!(
            servers[0].servers[0].entry_ipv6.as_deref(),
            Some("2a00:7c80:0:3ad::10")
        );
        assert_eq!(servers[0].servers[0].services_down, Some(0));
    }
}
