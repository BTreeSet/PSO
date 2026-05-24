use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::crypto::KeyMaterial;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SingboxWireGuardEndpoint {
    #[serde(rename = "type")]
    pub outbound_type: String,
    pub tag: String,
    pub system: bool,
    pub mtu: u16,
    pub address: Vec<String>,
    pub private_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub peers: Vec<SingboxWireGuardPeer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<i32>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SingboxWireGuardPeer {
    pub address: String,
    pub port: u16,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_interval: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Vec<u8>>,
}

pub fn build_wireguard_endpoint(
    tag: impl Into<String>,
    key_material: &KeyMaterial,
    endpoint: &str,
    peer_public_key: &str,
    address: &[String],
    persistent_keepalive_interval: Option<u16>,
    reserved: Option<&[u8]>,
) -> Result<SingboxWireGuardEndpoint> {
    let (server, server_port) = split_endpoint(endpoint)?;

    Ok(SingboxWireGuardEndpoint {
        outbound_type: "wireguard".into(),
        tag: tag.into(),
        system: false,
        mtu: 1408,
        address: address.to_vec(),
        private_key: key_material.private_key_base64.clone(),
        listen_port: None,
        peers: vec![SingboxWireGuardPeer {
            address: server,
            port: server_port,
            public_key: peer_public_key.to_string(),
            pre_shared_key: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive_interval,
            reserved: reserved.map(|value| value.to_vec()),
        }],
        udp_timeout: None,
        workers: None,
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
        let address = vec!["10.2.0.2/32".to_string()];

        let endpoint = build_wireguard_endpoint(
            "wg",
            &key_material,
            "203.0.113.10:51820",
            "peer",
            &address,
            Some(60),
            Some(&[1, 2, 3]),
        )
        .expect("endpoint");
        assert_eq!(endpoint.address, vec!["10.2.0.2/32"]);
        assert_eq!(endpoint.peers[0].address, "203.0.113.10");
        assert_eq!(endpoint.peers[0].port, 51820);
        assert_eq!(endpoint.peers[0].allowed_ips, default_allowed_ips());
        assert_eq!(endpoint.peers[0].persistent_keepalive_interval, Some(60));
        assert_eq!(endpoint.peers[0].reserved, Some(vec![1, 2, 3]));
    }
}
