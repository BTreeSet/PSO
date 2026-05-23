use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::api::CertificateResponse;
use crate::crypto::KeyMaterial;
use crate::model::PhysicalServer;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SingboxWireGuardOutbound {
    #[serde(rename = "type")]
    pub outbound_type: String,
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub local_address: Vec<String>,
    pub private_key: String,
    pub peer_public_key: String,
}

pub fn build_wireguard_outbound(
    tag: impl Into<String>,
    key_material: &KeyMaterial,
    certificate: &CertificateResponse,
    selected_server: &PhysicalServer,
) -> Result<SingboxWireGuardOutbound> {
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
        .unwrap_or_else(|| certificate.certificate.clone());

    Ok(SingboxWireGuardOutbound {
        outbound_type: "wireguard".into(),
        tag: tag.into(),
        server,
        server_port,
        local_address: vec![certificate.assigned_ip.clone()],
        private_key: key_material.private_key_base64.clone(),
        peer_public_key,
    })
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
}
