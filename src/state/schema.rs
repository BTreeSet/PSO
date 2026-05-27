use anyhow::{Result, bail};

use super::StateStore;

impl StateStore {
    pub(super) fn migrate(&self) -> Result<()> {
        if self.legacy_state_schema_exists()? {
            bail!("legacy state database detected; delete pso.sqlite3 and log in again");
        }

        self.connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
                         CREATE TABLE IF NOT EXISTS users (
                             username_key TEXT PRIMARY KEY,
               username TEXT NOT NULL,
               updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS vpn_sessions (
                             username_key TEXT PRIMARY KEY REFERENCES users(username_key) ON DELETE CASCADE,
               uid TEXT NOT NULL,
               refresh_token TEXT NOT NULL,
               updated_at INTEGER NOT NULL
             );
                         CREATE TABLE IF NOT EXISTS proton_cookies (
                                                         username_key TEXT NOT NULL REFERENCES users(username_key) ON DELETE CASCADE,
                             cookie_name TEXT NOT NULL,
                             cookie_domain TEXT NOT NULL,
                             cookie_path TEXT NOT NULL,
                             cookie_value TEXT NOT NULL,
                             host_only INTEGER NOT NULL,
                             secure INTEGER NOT NULL,
                             http_only INTEGER NOT NULL,
                             same_site TEXT,
                             expires_at_ms INTEGER,
                             created_at INTEGER NOT NULL,
                             updated_at INTEGER NOT NULL,
                             PRIMARY KEY (username_key, cookie_name, cookie_domain, cookie_path)
                         );
             CREATE TABLE IF NOT EXISTS runtime_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               occurred_at INTEGER NOT NULL,
                             username_key TEXT REFERENCES users(username_key) ON DELETE SET NULL,
               outbound_tag TEXT,
               event_type TEXT NOT NULL,
               details_json TEXT
             );
             CREATE TABLE IF NOT EXISTS health_checks (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               occurred_at INTEGER NOT NULL,
                             username_key TEXT REFERENCES users(username_key) ON DELETE SET NULL,
               outbound_tag TEXT,
               status TEXT NOT NULL,
               raw_ip TEXT NOT NULL,
               returned_ip TEXT,
               reason TEXT NOT NULL
             );
                         CREATE TABLE IF NOT EXISTS outbound_certificates (
                             outbound_tag TEXT PRIMARY KEY,
                                                         username_key TEXT NOT NULL REFERENCES users(username_key) ON DELETE CASCADE,
                             username TEXT NOT NULL,
                             profile_id TEXT,
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
                         CREATE TABLE IF NOT EXISTS wireguard_endpoint_states (
                             outbound_tag TEXT PRIMARY KEY,
                             provider TEXT NOT NULL,
                             identity TEXT,
                             server_id TEXT NOT NULL,
                             server_name TEXT NOT NULL,
                             endpoint TEXT NOT NULL,
                             peer_public_key TEXT NOT NULL,
                             pre_shared_key TEXT,
                             private_key TEXT NOT NULL,
                             public_key TEXT NOT NULL,
                             assigned_ips_json TEXT NOT NULL,
                             allowed_ips_json TEXT NOT NULL,
                             persistent_keepalive_interval INTEGER,
                             reserved_json TEXT,
                             mtu INTEGER NOT NULL,
                             expires_at_ms INTEGER,
                             refresh_at_ms INTEGER,
                             updated_at INTEGER NOT NULL
                         );
                         CREATE INDEX IF NOT EXISTS idx_events_username_time
                             ON runtime_events(username_key, occurred_at);
                         CREATE INDEX IF NOT EXISTS idx_proton_cookies_username_domain_path
                             ON proton_cookies(username_key, cookie_domain, cookie_path, cookie_name);
                         CREATE INDEX IF NOT EXISTS idx_health_username_outbound_time
                                                         ON health_checks(username_key, outbound_tag, occurred_at);
                                                 CREATE INDEX IF NOT EXISTS idx_certificates_username
                                                         ON outbound_certificates(username_key, outbound_tag);
                         CREATE INDEX IF NOT EXISTS idx_wireguard_provider
                             ON wireguard_endpoint_states(provider, updated_at);
                         CREATE INDEX IF NOT EXISTS idx_config_deployments_time
                             ON config_deployments(deployed_at);",
        )?;
        self.ensure_text_column("wireguard_endpoint_states", "pre_shared_key")?;
        self.ensure_text_column("outbound_certificates", "profile_id")?;
        Ok(())
    }

    fn legacy_state_schema_exists(&self) -> Result<bool> {
        let users_exists = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'
            )",
            [],
            |row| row.get(0),
        )?;
        if users_exists {
            return Ok(false);
        }

        let legacy_sessions_exist = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vpn_sessions'
            )",
            [],
            |row| row.get(0),
        )?;
        Ok(legacy_sessions_exist)
    }

    fn ensure_text_column(&self, table: &str, column: &str) -> Result<()> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut statement = self.connection.prepare(&pragma)?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        let exists = columns
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .any(|name| name == column);
        if !exists {
            let alter = format!("ALTER TABLE {table} ADD COLUMN {column} TEXT");
            self.connection.execute(&alter, [])?;
        }
        Ok(())
    }
}
