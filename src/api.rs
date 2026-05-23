use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::model::{LogicalServer, ProtonLogicalResponse};

#[derive(Clone, Debug)]
pub struct ProtonApiClient {
    base_url: String,
    client: Client,
}

impl ProtonApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(30))
            .user_agent("PSO/0.1 Rust-Control-Plane")
            .build()?;

        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        })
    }

    pub async fn get_certificate(
        &self,
        access_token: &str,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse> {
        let url = format!("{}/vpn/certificate", self.base_url);
        let response = self
            .client
            .post(url)
            .bearer_auth(access_token)
            .json(request)
            .send()
            .await
            .context("failed to send Proton certificate request")?
            .error_for_status()
            .context("Proton certificate request failed")?;

        response
            .json::<CertificateResponse>()
            .await
            .context("failed to decode Proton certificate response")
    }

    pub async fn get_logicals(&self, access_token: &str) -> Result<Vec<LogicalServer>> {
        let url = format!("{}/vpn/logicals", self.base_url);
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .query(&[("WithState", "true"), ("Protocols", "wireguard")])
            .send()
            .await
            .context("failed to send Proton logicals request")?
            .error_for_status()
            .context("Proton logicals request failed")?;

        Ok(response
            .json::<ProtonLogicalResponse>()
            .await
            .context("failed to decode Proton logicals response")?
            .into_servers())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateRequest {
    pub client_public_key: String,
    pub algorithm: String,
    pub device_model: String,
    pub purpose: String,
    pub protocols: Vec<String>,
}

impl CertificateRequest {
    pub fn wireguard_session(client_public_key: impl Into<String>) -> Self {
        Self {
            client_public_key: client_public_key.into(),
            algorithm: "EC".into(),
            device_model: "PSO-Rust-Control-Plane".into(),
            purpose: "session".into(),
            protocols: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CertificateResponse {
    #[serde(alias = "Certificate", alias = "certificate")]
    pub certificate: String,
    #[serde(
        alias = "ExpirationTimeMs",
        alias = "expirationTimeMs",
        alias = "expiration_time_ms"
    )]
    pub expiration_time_ms: u64,
    #[serde(
        alias = "RefreshTimeMs",
        alias = "refreshTimeMs",
        alias = "refresh_time_ms"
    )]
    pub refresh_time_ms: u64,
    #[serde(
        alias = "AssignedIP",
        alias = "AssignedIp",
        alias = "assignedIp",
        alias = "assigned_ip"
    )]
    pub assigned_ip: String,
    #[serde(alias = "Endpoint", alias = "endpoint")]
    pub endpoint: Option<String>,
    #[serde(
        alias = "PeerPublicKey",
        alias = "peerPublicKey",
        alias = "peer_public_key"
    )]
    pub peer_public_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_certificate_request_like_proton_client() {
        let request = CertificateRequest::wireguard_session("public-key");
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["ClientPublicKey"], "public-key");
        assert_eq!(value["Algorithm"], "EC");
        assert_eq!(value["Purpose"], "session");
    }

    #[test]
    fn accepts_common_certificate_response_shapes() {
        let response: CertificateResponse = serde_json::from_value(json!({
            "Certificate": "cert-pem",
            "ExpirationTimeMs": 2000,
            "RefreshTimeMs": 1000,
            "AssignedIP": "10.2.0.2/32",
            "Endpoint": "203.0.113.10:443"
        }))
        .unwrap();

        assert_eq!(response.certificate, "cert-pem");
        assert_eq!(response.assigned_ip, "10.2.0.2/32");
        assert_eq!(response.endpoint.as_deref(), Some("203.0.113.10:443"));
    }
}
