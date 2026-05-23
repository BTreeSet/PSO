use anyhow::{Result, anyhow};

use crate::crypto::generate_key_material;
use crate::model::PhysicalServer;
use crate::session::UserSession;

#[derive(Clone, Debug, PartialEq)]
pub struct WireGuardCredentials {
    pub server: String,
    pub local_address: Vec<String>,
    pub private_key: String,
    pub peer_public_key: String,
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
    local_address: Vec<String>,
    default_port: u16,
}

impl Default for LocalKeyProvisioner {
    fn default() -> Self {
        Self {
            local_address: vec!["10.2.0.2/32".into()],
            default_port: 51820,
        }
    }
}

impl LocalKeyProvisioner {
    pub fn with_local_address(mut self, local_address: Vec<String>) -> Self {
        self.local_address = local_address;
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
            .entry_ip
            .as_deref()
            .or(server.domain.as_deref())
            .ok_or_else(|| anyhow!("selected server for {outbound_tag} has no endpoint"))?;
        let peer_public_key = server.public_key.clone().ok_or_else(|| {
            anyhow!("selected server for {outbound_tag} has no WireGuard public key")
        })?;

        Ok(WireGuardCredentials {
            server: format!("{endpoint}:{}", self.default_port),
            local_address: self.local_address.clone(),
            private_key: key_material.private_key_base64,
            peer_public_key,
        })
    }
}
