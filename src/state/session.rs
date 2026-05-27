use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use super::support::unix_timestamp;
use super::{ProtonSessionState, StateStore, username_state_key};

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
}
