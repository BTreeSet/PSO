use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct LogicalServer {
    #[serde(alias = "ID", alias = "Id", default)]
    pub id: String,
    #[serde(alias = "Name", default)]
    pub name: String,
    #[serde(alias = "ExitCountry", alias = "exit_country")]
    pub exit_country: String,
    #[serde(alias = "City", default)]
    pub city: Option<String>,
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
