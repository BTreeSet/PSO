use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::api::CertificateResponse;
use crate::crypto::KeyMaterial;
use crate::model::PhysicalServer;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SingboxWireGuardEndpoint {
    #[serde(rename = "type")]
    pub outbound_type: String,
    pub tag: String,
    pub system: bool,
    pub mtu: u16,
    pub address: Vec<String>,
    pub private_key: String,
    pub peers: Vec<SingboxWireGuardPeer>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SingboxWireGuardPeer {
    pub address: String,
    pub port: u16,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_interval: Option<u16>,
}

pub fn build_wireguard_endpoint(
    tag: impl Into<String>,
    key_material: &KeyMaterial,
    certificate: &CertificateResponse,
    selected_server: &PhysicalServer,
) -> Result<SingboxWireGuardEndpoint> {
    let endpoint = certificate
        .endpoint
        .as_deref()
        .or(selected_server.entry_ip.as_deref())
        .or(selected_server.domain.as_deref())
        .ok_or_else(|| anyhow!("selected server has no endpoint"))?;
    let (server, server_port) = split_endpoint(endpoint)?;
    let peer_public_key = certificate
        .peer_public_key
        .clone()
        .or(selected_server.public_key.clone())
        .ok_or_else(|| anyhow!("selected server has no WireGuard peer public key"))?;

    Ok(SingboxWireGuardEndpoint {
        outbound_type: "wireguard".into(),
        tag: tag.into(),
        system: false,
        mtu: 1408,
        address: vec![certificate.assigned_ip.clone()],
        private_key: key_material.private_key_base64.clone(),
        peers: vec![SingboxWireGuardPeer {
            address: server,
            port: server_port,
            public_key: peer_public_key,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive_interval: Some(25),
        }],
    })
}

pub fn default_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

pub fn split_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Ok((endpoint.to_string(), 443));
    };

    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid endpoint port in '{endpoint}'"))?;
    Ok((host.trim_matches(['[', ']']).to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_endpoint_with_default_port() {
        assert_eq!(
            split_endpoint("203.0.113.10:51820").unwrap(),
            ("203.0.113.10".into(), 51820)
        );
        assert_eq!(
            split_endpoint("203.0.113.10").unwrap(),
            ("203.0.113.10".into(), 443)
        );
    }

    #[test]
    fn builds_singbox_111_endpoint_shape() {
        let key_material = KeyMaterial {
            private_key_base64: "private".into(),
            public_key_base64: "public".into(),
        };
        let certificate = CertificateResponse {
            certificate: "cert".into(),
            expiration_time_ms: 2,
            refresh_time_ms: 1,
            assigned_ip: "10.2.0.2/32".into(),
            endpoint: Some("203.0.113.10:51820".into()),
            peer_public_key: Some("peer".into()),
        };
        let server = PhysicalServer {
            id: "server".into(),
            name: "server".into(),
            entry_ip: None,
            entry_ipv6: None,
            exit_ip: None,
            domain: None,
            label: None,
            status: 1,
            load: None,
            public_key: None,
            generation: None,
            services_down: Some(0),
            services_down_reason: None,
        };

        let endpoint =
            build_wireguard_endpoint("wg", &key_material, &certificate, &server).expect("endpoint");
        assert_eq!(endpoint.address, vec!["10.2.0.2/32"]);
        assert_eq!(endpoint.peers[0].address, "203.0.113.10");
        assert_eq!(endpoint.peers[0].port, 51820);
        assert_eq!(endpoint.peers[0].allowed_ips, default_allowed_ips());
    }
}
