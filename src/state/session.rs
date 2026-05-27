use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use super::support::{collect_rows, unix_timestamp};
use super::{ProtonSessionRow, ProtonSessionState, StateStore, username_state_key};

impl StateStore {
    pub fn store_proton_session(
        &self,
        username: &str,
        uid: &str,
        refresh_token: &str,
    ) -> Result<()> {
        let username_key = username_state_key(username);
        let now = unix_timestamp()?;
        self.upsert_user(&username_key, username, now)?;
        self.connection.execute(
            "INSERT INTO vpn_sessions (username_key, uid, refresh_token, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(username_key) DO UPDATE SET
               uid = excluded.uid,
               refresh_token = excluded.refresh_token,
               updated_at = excluded.updated_at",
            params![username_key, uid, refresh_token, now],
        )?;
        self.record_event(Some(username), None, "proton_session_updated", None)
    }

    pub fn load_proton_session_optional(
        &self,
        username: &str,
    ) -> Result<Option<ProtonSessionState>> {
        let username_key = username_state_key(username);
        self.connection
            .query_row(
                "SELECT uid, refresh_token FROM vpn_sessions WHERE username_key = ?1",
                params![username_key],
                |row| {
                    Ok(ProtonSessionState {
                        uid: row.get(0)?,
                        refresh_token: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn load_proton_session(&self, username: &str) -> Result<ProtonSessionState> {
        self.load_proton_session_optional(username)?
            .with_context(|| format!("Proton session state was not found for {username}"))
    }

    pub fn list_proton_sessions(&self, limit: usize) -> Result<Vec<ProtonSessionRow>> {
        let mut statement = self.connection.prepare(
            "SELECT s.username_key, a.username, s.uid, s.refresh_token, s.updated_at
             FROM vpn_sessions s
               LEFT JOIN users a ON a.username_key = s.username_key
             ORDER BY s.updated_at DESC, a.username ASC, s.username_key ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(ProtonSessionRow {
                username_key: row.get(0)?,
                username: row.get(1)?,
                uid: row.get(2)?,
                refresh_token: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn load_username_by_uid(&self, uid: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT a.username
                 FROM vpn_sessions s
                   INNER JOIN users a ON a.username_key = s.username_key
                 WHERE s.uid = ?1",
                params![uid],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
}
