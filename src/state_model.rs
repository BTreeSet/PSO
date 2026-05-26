use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtonSessionState {
    pub uid: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccountRow {
    pub account_key: String,
    pub username: String,
    pub updated_at: i64,
    pub has_proton_session: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeEventRow {
    pub id: i64,
    pub occurred_at: i64,
    pub username: Option<String>,
    pub outbound_tag: Option<String>,
    pub event_type: String,
    pub details_json: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthCheckRow {
    pub id: i64,
    pub occurred_at: i64,
    pub username: Option<String>,
    pub outbound_tag: Option<String>,
    pub status: String,
    pub raw_ip: String,
    pub returned_ip: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct OutboundCertificateState {
    pub outbound_tag: String,
    pub username: String,
    pub profile_id: Option<String>,
    pub server_id: String,
    pub server_name: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub private_key: String,
    pub public_key: String,
    pub assigned_ip: Option<String>,
    pub expires_at_ms: Option<i64>,
    pub refresh_at_ms: Option<i64>,
    pub consecutive_failures: i64,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct OutboundCertificateUpdate<'a> {
    pub outbound_tag: &'a str,
    pub username: &'a str,
    pub profile_id: Option<&'a str>,
    pub server_id: &'a str,
    pub server_name: &'a str,
    pub endpoint: &'a str,
    pub peer_public_key: &'a str,
    pub private_key: &'a str,
    pub public_key: &'a str,
    pub assigned_ip: &'a str,
    pub expires_at_ms: i64,
    pub refresh_at_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateRow {
    pub outbound_tag: String,
    pub username: String,
    pub profile_id: Option<String>,
    pub server_name: String,
    pub endpoint: String,
    pub assigned_ip: Option<String>,
    pub expires_at_ms: Option<i64>,
    pub refresh_at_ms: Option<i64>,
    pub consecutive_failures: i64,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct WireGuardEndpointState {
    pub outbound_tag: String,
    pub provider: String,
    pub identity: Option<String>,
    pub server_id: String,
    pub server_name: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub pre_shared_key: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub assigned_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<Vec<u8>>,
    pub mtu: u16,
    pub expires_at_ms: Option<i64>,
    pub refresh_at_ms: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct WireGuardEndpointStateUpdate<'a> {
    pub outbound_tag: &'a str,
    pub provider: &'a str,
    pub identity: Option<&'a str>,
    pub server_id: &'a str,
    pub server_name: &'a str,
    pub endpoint: &'a str,
    pub peer_public_key: &'a str,
    pub pre_shared_key: Option<&'a str>,
    pub private_key: &'a str,
    pub public_key: &'a str,
    pub assigned_ips: &'a [String],
    pub allowed_ips: &'a [String],
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<&'a [u8]>,
    pub mtu: u16,
    pub expires_at_ms: Option<i64>,
    pub refresh_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WireGuardEndpointRow {
    pub outbound_tag: String,
    pub provider: String,
    pub identity: Option<String>,
    pub server_name: String,
    pub endpoint: String,
    pub assigned_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<Vec<u8>>,
    pub refresh_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub struct HealthRecord<'a> {
    pub username: Option<&'a str>,
    pub outbound_tag: Option<&'a str>,
    pub status: &'a str,
    pub raw_ip: &'a str,
    pub returned_ip: Option<&'a str>,
    pub reason: &'a str,
}
