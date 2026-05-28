use anyhow::{Result, anyhow};

use crate::crypto::generate_key_material;
use crate::model::PhysicalServer;
use crate::proton::PROTON_WIREGUARD_ADDRESS_V4;
use crate::session::UserSession;
use crate::singbox_adapter::{default_allowed_ips, split_endpoint};

#[derive(Clone, Debug, PartialEq)]
pub struct WireGuardCredentials {
    pub peer_address: String,
    pub peer_port: u16,
    pub address: Vec<String>,
    pub private_key: String,
    pub peer_public_key: String,
    pub allowed_ips: Vec<String>,
}

pub trait WireGuardProvisioner {
    fn provision(
        &self,
        session: &UserSession,
        outbound_tag: &str,
        server: &PhysicalServer,
    ) -> Result<WireGuardCredentials>;
}

#[derive(Clone, Debug)]
pub struct LocalKeyProvisioner {
    address: Vec<String>,
}

impl Default for LocalKeyProvisioner {
    fn default() -> Self {
        Self {
            address: vec![PROTON_WIREGUARD_ADDRESS_V4.into()],
        }
    }
}

impl LocalKeyProvisioner {
    pub fn with_address(mut self, address: Vec<String>) -> Self {
        self.address = address;
        self
    }
}

impl WireGuardProvisioner for LocalKeyProvisioner {
    fn provision(
        &self,
        _session: &UserSession,
        outbound_tag: &str,
        server: &PhysicalServer,
    ) -> Result<WireGuardCredentials> {
        let key_material = generate_key_material();
        let endpoint = server
            .proton_wireguard_endpoint()
            .ok_or_else(|| anyhow!("selected server for {outbound_tag} has no endpoint"))?;
        let peer_public_key = server.public_key.clone().ok_or_else(|| {
            anyhow!("selected server for {outbound_tag} has no WireGuard public key")
        })?;
        let (peer_address, peer_port) = split_endpoint(&endpoint)?;

        Ok(WireGuardCredentials {
            peer_address,
            peer_port,
            address: self.address.clone(),
            private_key: key_material.private_key_base64,
            peer_public_key,
            allowed_ips: default_allowed_ips(),
        })
    }
}
