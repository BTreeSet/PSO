use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::config::RuntimeContext;
pub use crate::state_model::{
    AccountRow, CertificateRow, HealthCheckRow, HealthRecord, OutboundCertificateState,
    OutboundCertificateUpdate, RuntimeEventRow, VpnSessionState,
};

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

    pub fn store_vpn_session(&self, username: &str, uid: &str, refresh_token: &str) -> Result<()> {
        let account_key = user_state_key(username);
        let now = unix_timestamp()?;
        self.upsert_account(&account_key, username, now)?;
        self.connection.execute(
            "INSERT INTO vpn_sessions (account_key, uid, refresh_token, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_key) DO UPDATE SET
               uid = excluded.uid,
               refresh_token = excluded.refresh_token,
               updated_at = excluded.updated_at",
            params![account_key, uid, refresh_token, now],
        )?;
        self.record_event(Some(username), None, "vpn_session_updated", None)
    }

    pub fn load_vpn_session(&self, username: &str) -> Result<VpnSessionState> {
        let account_key = user_state_key(username);
        self.connection
            .query_row(
                "SELECT uid, refresh_token FROM vpn_sessions WHERE account_key = ?1",
                params![account_key],
                |row| {
                    Ok(VpnSessionState {
                        uid: row.get(0)?,
                        refresh_token: row.get(1)?,
                    })
                },
            )
            .optional()?
            .with_context(|| format!("VPN session state was not found for {username}"))
    }

    pub fn record_event(
        &self,
        username: Option<&str>,
        outbound_tag: Option<&str>,
        event_type: &str,
        details_json: Option<&str>,
    ) -> Result<()> {
        let account_key = username.map(user_state_key);
        if let (Some(account_key), Some(username)) = (&account_key, username) {
            self.upsert_account(account_key, username, unix_timestamp()?)?;
        }
        self.connection.execute(
            "INSERT INTO runtime_events
               (occurred_at, account_key, outbound_tag, event_type, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                unix_timestamp()?,
                account_key,
                outbound_tag,
                event_type,
                details_json
            ],
        )?;
        Ok(())
    }

    pub fn record_health(&self, record: HealthRecord<'_>) -> Result<()> {
        let account_key = record.username.map(user_state_key);
        if let (Some(account_key), Some(username)) = (&account_key, record.username) {
            self.upsert_account(account_key, username, unix_timestamp()?)?;
        }
        self.connection.execute(
            "INSERT INTO health_checks
               (occurred_at, account_key, outbound_tag, status, raw_ip, returned_ip, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                unix_timestamp()?,
                account_key,
                record.outbound_tag,
                record.status,
                record.raw_ip,
                record.returned_ip,
                record.reason
            ],
        )?;
        Ok(())
    }

    pub fn load_outbound_certificate(
        &self,
        outbound_tag: &str,
    ) -> Result<Option<OutboundCertificateState>> {
        self.connection
            .query_row(
                "SELECT outbound_tag, username, server_id, server_name, endpoint, peer_public_key,
                        private_key, public_key, assigned_ip, expires_at_ms, refresh_at_ms,
                        consecutive_failures, last_error, updated_at
                 FROM outbound_certificates
                 WHERE outbound_tag = ?1",
                params![outbound_tag],
                |row| {
                    Ok(OutboundCertificateState {
                        outbound_tag: row.get(0)?,
                        username: row.get(1)?,
                        server_id: row.get(2)?,
                        server_name: row.get(3)?,
                        endpoint: row.get(4)?,
                        peer_public_key: row.get(5)?,
                        private_key: row.get(6)?,
                        public_key: row.get(7)?,
                        assigned_ip: row.get(8)?,
                        expires_at_ms: row.get(9)?,
                        refresh_at_ms: row.get(10)?,
                        consecutive_failures: row.get(11)?,
                        last_error: row.get(12)?,
                        updated_at: row.get(13)?,
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
        let account_key = user_state_key(update.username);
        let now = unix_timestamp()?;
        self.upsert_account(&account_key, update.username, now)?;
        self.connection.execute(
            "INSERT INTO outbound_certificates
               (outbound_tag, account_key, username, server_id, server_name, endpoint,
                peer_public_key, private_key, public_key, assigned_ip, expires_at_ms,
                refresh_at_ms, consecutive_failures, last_error, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, NULL, ?13)
             ON CONFLICT(outbound_tag) DO UPDATE SET
               account_key = excluded.account_key,
               username = excluded.username,
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
                account_key,
                update.username,
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
        let account_key = user_state_key(username);
        let now = unix_timestamp()?;
        self.upsert_account(&account_key, username, now)?;
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

    pub fn record_config_deployment(
        &self,
        config_hash: &str,
        outbound_tags_json: &str,
        active_config: &str,
        success: bool,
        error: Option<&str>,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO config_deployments
               (deployed_at, config_hash, outbound_tags_json, active_config, success, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                unix_timestamp()?,
                config_hash,
                outbound_tags_json,
                active_config,
                success,
                error
            ],
        )?;
        Ok(())
    }

    pub fn list_accounts(&self) -> Result<Vec<AccountRow>> {
        let mut statement = self.connection.prepare(
            "SELECT a.account_key, a.username, a.updated_at, s.account_key IS NOT NULL
             FROM accounts a
             LEFT JOIN vpn_sessions s ON s.account_key = a.account_key
             ORDER BY a.updated_at DESC, a.username ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AccountRow {
                account_key: row.get(0)?,
                username: row.get(1)?,
                updated_at: row.get(2)?,
                has_vpn_session: row.get(3)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<RuntimeEventRow>> {
        let mut statement = self.connection.prepare(
            "SELECT e.id, e.occurred_at, a.username, e.outbound_tag, e.event_type, e.details_json
             FROM runtime_events e
             LEFT JOIN accounts a ON a.account_key = e.account_key
             ORDER BY e.occurred_at DESC, e.id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(RuntimeEventRow {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                username: row.get(2)?,
                outbound_tag: row.get(3)?,
                event_type: row.get(4)?,
                details_json: row.get(5)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn list_health_checks(&self, limit: usize) -> Result<Vec<HealthCheckRow>> {
        let mut statement = self.connection.prepare(
            "SELECT h.id, h.occurred_at, a.username, h.outbound_tag, h.status,
                    h.raw_ip, h.returned_ip, h.reason
             FROM health_checks h
             LEFT JOIN accounts a ON a.account_key = h.account_key
             ORDER BY h.occurred_at DESC, h.id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(HealthCheckRow {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                username: row.get(2)?,
                outbound_tag: row.get(3)?,
                status: row.get(4)?,
                raw_ip: row.get(5)?,
                returned_ip: row.get(6)?,
                reason: row.get(7)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn list_certificates(&self, limit: usize) -> Result<Vec<CertificateRow>> {
        let mut statement = self.connection.prepare(
            "SELECT outbound_tag, username, server_name, endpoint, assigned_ip,
                    expires_at_ms, refresh_at_ms, consecutive_failures, last_error, updated_at
             FROM outbound_certificates
             ORDER BY updated_at DESC, outbound_tag ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(CertificateRow {
                outbound_tag: row.get(0)?,
                username: row.get(1)?,
                server_name: row.get(2)?,
                endpoint: row.get(3)?,
                assigned_ip: row.get(4)?,
                expires_at_ms: row.get(5)?,
                refresh_at_ms: row.get(6)?,
                consecutive_failures: row.get(7)?,
                last_error: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        collect_rows(rows)
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS accounts (
               account_key TEXT PRIMARY KEY,
               username TEXT NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS vpn_sessions (
               account_key TEXT PRIMARY KEY REFERENCES accounts(account_key) ON DELETE CASCADE,
               uid TEXT NOT NULL,
               refresh_token TEXT NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS runtime_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               occurred_at INTEGER NOT NULL,
               account_key TEXT REFERENCES accounts(account_key) ON DELETE SET NULL,
               outbound_tag TEXT,
               event_type TEXT NOT NULL,
               details_json TEXT
             );
             CREATE TABLE IF NOT EXISTS health_checks (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               occurred_at INTEGER NOT NULL,
               account_key TEXT REFERENCES accounts(account_key) ON DELETE SET NULL,
               outbound_tag TEXT,
               status TEXT NOT NULL,
               raw_ip TEXT NOT NULL,
               returned_ip TEXT,
               reason TEXT NOT NULL
             );
                         CREATE TABLE IF NOT EXISTS outbound_certificates (
                             outbound_tag TEXT PRIMARY KEY,
                             account_key TEXT NOT NULL REFERENCES accounts(account_key) ON DELETE CASCADE,
                             username TEXT NOT NULL,
                             server_id TEXT NOT NULL,
                             server_name TEXT NOT NULL,
                             endpoint TEXT NOT NULL,
                             peer_public_key TEXT NOT NULL,
                             private_key TEXT NOT NULL,
                             public_key TEXT NOT NULL,
                             assigned_ip TEXT,
                             expires_at_ms INTEGER,
                             refresh_at_ms INTEGER,
                             consecutive_failures INTEGER NOT NULL DEFAULT 0,
                             last_error TEXT,
                             updated_at INTEGER NOT NULL
                         );
                         CREATE TABLE IF NOT EXISTS config_deployments (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             deployed_at INTEGER NOT NULL,
                             config_hash TEXT NOT NULL,
                             outbound_tags_json TEXT NOT NULL,
                             active_config TEXT NOT NULL,
                             success INTEGER NOT NULL,
                             error TEXT
                         );
             CREATE INDEX IF NOT EXISTS idx_events_account_time
               ON runtime_events(account_key, occurred_at);
             CREATE INDEX IF NOT EXISTS idx_health_account_outbound_time
                             ON health_checks(account_key, outbound_tag, occurred_at);
                         CREATE INDEX IF NOT EXISTS idx_certificates_account
                             ON outbound_certificates(account_key, outbound_tag);
                         CREATE INDEX IF NOT EXISTS idx_config_deployments_time
                             ON config_deployments(deployed_at);",
        )?;
        Ok(())
    }

    fn upsert_account(&self, account_key: &str, username: &str, updated_at: i64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO accounts (account_key, username, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(account_key) DO UPDATE SET
               username = excluded.username,
               updated_at = excluded.updated_at",
            params![account_key, username, updated_at],
        )?;
        Ok(())
    }
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn topology_state_file(context: &RuntimeContext) -> PathBuf {
    context.state_dir.join("logicals.json")
}

pub fn state_db_file(context: &RuntimeContext) -> PathBuf {
    context.state_dir.join("pso.sqlite3")
}

pub fn user_state_key(username: &str) -> String {
    hex::encode(Sha256::digest(username.as_bytes()))
}

pub fn write_state_file(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn unix_timestamp() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_state_key_is_path_safe_and_opaque() {
        let key = user_state_key("alice@example.com");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|character| character.is_ascii_hexdigit()));
        assert!(!key.contains("alice"));
        assert!(!key.contains('@'));
    }

    #[test]
    fn stores_sessions_events_and_health_in_sqlite() {
        let temp = tempfile::tempdir().unwrap();
        let context = RuntimeContext {
            api_base_url: "http://localhost".into(),
            state_dir: temp.path().into(),
        };
        let store = StateStore::open(&context).unwrap();

        store
            .store_vpn_session("alice@example.com", "uid", "refresh")
            .unwrap();
        let session = store.load_vpn_session("alice@example.com").unwrap();
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
        assert_eq!(cert.private_key, "private");
        assert_eq!(store.list_certificates(10).unwrap().len(), 1);
    }
}
