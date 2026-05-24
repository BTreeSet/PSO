use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::RuntimeContext;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnSessionState {
    pub uid: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug)]
pub struct HealthRecord<'a> {
    pub username: Option<&'a str>,
    pub outbound_tag: Option<&'a str>,
    pub status: &'a str,
    pub raw_ip: &'a str,
    pub returned_ip: Option<&'a str>,
    pub reason: &'a str,
}

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
             CREATE INDEX IF NOT EXISTS idx_events_account_time
               ON runtime_events(account_key, occurred_at);
             CREATE INDEX IF NOT EXISTS idx_health_account_outbound_time
               ON health_checks(account_key, outbound_tag, occurred_at);",
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
    }
}
