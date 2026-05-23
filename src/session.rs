use std::collections::HashMap;

use anyhow::{Result, anyhow};
use parking_lot::RwLock;

use crate::model::PhysicalServer;

#[derive(Clone, Debug)]
pub struct ActiveOutbound {
    pub tag: String,
    pub cert_info: CertInfo,
    pub server_details: PhysicalServer,
    pub expires_at_ms: u64,
    pub refresh_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct CertInfo {
    pub certificate_pem: String,
    pub private_key: String,
}

#[derive(Clone, Debug)]
pub struct UserSession {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub account_tier: String,
    pub active_connections: Vec<ActiveOutbound>,
}

impl UserSession {
    pub fn new(username: impl Into<String>, account_tier: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            access_token: String::new(),
            refresh_token: String::new(),
            account_tier: account_tier.into(),
            active_connections: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SessionStore {
    inner: RwLock<HashMap<String, UserSession>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, session: UserSession) {
        self.inner.write().insert(session.username.clone(), session);
    }

    pub fn get(&self, username: &str) -> Result<UserSession> {
        self.inner
            .read()
            .get(username)
            .cloned()
            .ok_or_else(|| anyhow!("no session found for user '{username}'"))
    }

    pub fn upsert_outbound(&self, username: &str, outbound: ActiveOutbound) -> Result<()> {
        let mut sessions = self.inner.write();
        let session = sessions
            .get_mut(username)
            .ok_or_else(|| anyhow!("no session found for user '{username}'"))?;

        if let Some(existing) = session
            .active_connections
            .iter_mut()
            .find(|connection| connection.tag == outbound.tag)
        {
            *existing = outbound;
        } else {
            session.active_connections.push(outbound);
        }

        Ok(())
    }
}
