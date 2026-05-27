use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use super::support::collect_rows;
use super::support::unix_timestamp;
use super::{
    CertificateRow, OutboundCertificateState, OutboundCertificateUpdate, StateStore,
    WireGuardEndpointStateUpdate, username_state_key,
};
use crate::proton::PROTON_WIREGUARD_KEEPALIVE_INTERVAL;
use crate::provider::PROTON_PROVIDER;
use crate::singbox_adapter::default_allowed_ips;

impl StateStore {
    pub fn load_outbound_certificate(
        &self,
        outbound_tag: &str,
    ) -> Result<Option<OutboundCertificateState>> {
        self.connection
            .query_row(
                "SELECT outbound_tag, username, profile_id, server_id, server_name, endpoint,
                        peer_public_key, private_key, public_key, assigned_ip, expires_at_ms,
                        refresh_at_ms, consecutive_failures, last_error, updated_at
                 FROM outbound_certificates
                 WHERE outbound_tag = ?1",
                params![outbound_tag],
                |row| {
                    Ok(OutboundCertificateState {
                        outbound_tag: row.get(0)?,
                        username: row.get(1)?,
                        profile_id: row.get(2)?,
                        server_id: row.get(3)?,
                        server_name: row.get(4)?,
                        endpoint: row.get(5)?,
                        peer_public_key: row.get(6)?,
                        private_key: row.get(7)?,
                        public_key: row.get(8)?,
                        assigned_ip: row.get(9)?,
                        expires_at_ms: row.get(10)?,
                        refresh_at_ms: row.get(11)?,
                        consecutive_failures: row.get(12)?,
                        last_error: row.get(13)?,
                        updated_at: row.get(14)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn store_outbound_certificate_success(
        &self,
        update: OutboundCertificateUpdate<'_>,
    ) -> Result<()> {
        let username_key = username_state_key(update.username);
        let now = unix_timestamp()?;
        self.upsert_user(&username_key, update.username, now)?;
        self.connection.execute(
            "INSERT INTO outbound_certificates
                             (outbound_tag, username_key, username, profile_id, server_id, server_name, endpoint,
                peer_public_key, private_key, public_key, assigned_ip, expires_at_ms,
                refresh_at_ms, consecutive_failures, last_error, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, NULL, ?14)
             ON CONFLICT(outbound_tag) DO UPDATE SET
               username_key = excluded.username_key,
               username = excluded.username,
                             profile_id = COALESCE(excluded.profile_id, outbound_certificates.profile_id),
               server_id = excluded.server_id,
               server_name = excluded.server_name,
               endpoint = excluded.endpoint,
               peer_public_key = excluded.peer_public_key,
               private_key = excluded.private_key,
               public_key = excluded.public_key,
               assigned_ip = excluded.assigned_ip,
               expires_at_ms = excluded.expires_at_ms,
               refresh_at_ms = excluded.refresh_at_ms,
               consecutive_failures = 0,
               last_error = NULL,
               updated_at = excluded.updated_at",
            params![
                update.outbound_tag,
                username_key,
                update.username,
                update.profile_id,
                update.server_id,
                update.server_name,
                update.endpoint,
                update.peer_public_key,
                update.private_key,
                update.public_key,
                update.assigned_ip,
                update.expires_at_ms,
                update.refresh_at_ms,
                now
            ],
        )?;
        let assigned_ips = vec![update.assigned_ip.to_owned()];
        let allowed_ips = default_allowed_ips();
        self.upsert_wireguard_endpoint_state(&WireGuardEndpointStateUpdate {
            outbound_tag: update.outbound_tag,
            provider: PROTON_PROVIDER,
            identity: Some(update.username),
            server_id: update.server_id,
            server_name: update.server_name,
            endpoint: update.endpoint,
            peer_public_key: update.peer_public_key,
            pre_shared_key: None,
            private_key: update.private_key,
            public_key: update.public_key,
            assigned_ips: &assigned_ips,
            allowed_ips: &allowed_ips,
            persistent_keepalive_interval: Some(PROTON_WIREGUARD_KEEPALIVE_INTERVAL),
            reserved: None,
            mtu: 1408,
            expires_at_ms: Some(update.expires_at_ms),
            refresh_at_ms: Some(update.refresh_at_ms),
        })?;
        self.record_event(
            Some(update.username),
            Some(update.outbound_tag),
            "certificate_state_updated",
            None,
        )
    }

    pub fn store_outbound_certificate_failure(
        &self,
        username: &str,
        outbound_tag: &str,
        error: &str,
    ) -> Result<()> {
        let username_key = username_state_key(username);
        let now = unix_timestamp()?;
        self.upsert_user(&username_key, username, now)?;
        self.connection.execute(
            "UPDATE outbound_certificates
             SET consecutive_failures = consecutive_failures + 1,
                 last_error = ?2,
                 updated_at = ?3
             WHERE outbound_tag = ?1",
            params![outbound_tag, error, now],
        )?;
        self.record_event(
            Some(username),
            Some(outbound_tag),
            "certificate_refresh_failed",
            Some(&serde_json::to_string(
                &serde_json::json!({ "error": error }),
            )?),
        )
    }

    pub fn list_certificates(&self, limit: usize) -> Result<Vec<CertificateRow>> {
        let mut statement = self.connection.prepare(
            "SELECT outbound_tag, username, profile_id, server_name, endpoint, assigned_ip,
                    expires_at_ms, refresh_at_ms, consecutive_failures, last_error, updated_at
             FROM outbound_certificates
             ORDER BY updated_at DESC, outbound_tag ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(CertificateRow {
                outbound_tag: row.get(0)?,
                username: row.get(1)?,
                profile_id: row.get(2)?,
                server_name: row.get(3)?,
                endpoint: row.get(4)?,
                assigned_ip: row.get(5)?,
                expires_at_ms: row.get(6)?,
                refresh_at_ms: row.get(7)?,
                consecutive_failures: row.get(8)?,
                last_error: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?;
        collect_rows(rows)
    }
}
