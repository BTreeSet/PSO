use std::fs;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::config::RuntimeContext;
mod certificates;
mod observability;
mod paths;
mod schema;
mod session;
mod support;
mod users;
mod wireguard;

pub use crate::state_model::{
    CertificateRow, HealthCheckRow, HealthRecord, OutboundCertificateState,
    OutboundCertificateUpdate, ProtonSessionState, RuntimeEventRow, UserRow, WireGuardEndpointRow,
    WireGuardEndpointState, WireGuardEndpointStateUpdate,
};
pub use paths::{state_db_file, topology_state_file, username_state_key, write_state_file};

pub struct StateStore {
    connection: Connection,
}

impl StateStore {
    pub fn open(context: &RuntimeContext) -> Result<Self> {
        fs::create_dir_all(&context.state_dir)
            .with_context(|| format!("failed to create {}", context.state_dir.display()))?;
        let connection = Connection::open(state_db_file(context))?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_sessions_events_and_health_in_sqlite() {
        let temp = tempfile::tempdir().unwrap();
        let context = RuntimeContext {
            api_base_url: "http://localhost".into(),
            state_dir: temp.path().into(),
            proton_client: crate::config::ProtonClientProfile::default(),
        };
        let store = StateStore::open(&context).unwrap();

        store
            .store_proton_session("alice@example.com", "uid", "refresh")
            .unwrap();
        let session = store.load_proton_session("alice@example.com").unwrap();
        assert_eq!(session.uid, "uid");
        assert_eq!(session.refresh_token, "refresh");

        store
            .record_health(HealthRecord {
                username: Some("alice@example.com"),
                outbound_tag: Some("proton-wg"),
                status: "Healthy",
                raw_ip: "198.51.100.1",
                returned_ip: Some("203.0.113.10"),
                reason: "ok",
            })
            .unwrap();

        let health_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM health_checks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(health_count, 1);

        store
            .store_outbound_certificate_success(OutboundCertificateUpdate {
                outbound_tag: "proton-wg",
                username: "alice@example.com",
                profile_id: Some("profile-1"),
                server_id: "server-1",
                server_name: "Server 1",
                endpoint: "203.0.113.10:51820",
                peer_public_key: "peer",
                private_key: "private",
                public_key: "public",
                assigned_ip: "10.2.0.2/32",
                expires_at_ms: 2,
                refresh_at_ms: 1,
            })
            .unwrap();
        let cert = store
            .load_outbound_certificate("proton-wg")
            .unwrap()
            .unwrap();
        assert_eq!(cert.username, "alice@example.com");
        assert_eq!(cert.profile_id.as_deref(), Some("profile-1"));
        assert_eq!(cert.private_key, "private");
        assert_eq!(store.list_certificates(10).unwrap().len(), 1);
        assert_eq!(store.list_users().unwrap().len(), 1);

        assert!(
            store
                .load_proton_session_optional("bob@example.com")
                .unwrap()
                .is_none()
        );
    }
}
