use rusqlite::params;

use super::support::collect_rows;
use super::{StateStore, UserRow};

impl StateStore {
    pub(super) fn upsert_user(
        &self,
        username_key: &str,
        username: &str,
        updated_at: i64,
    ) -> anyhow::Result<()> {
        self.connection.execute(
            "INSERT INTO users (username_key, username, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(username_key) DO UPDATE SET
               username = excluded.username,
               updated_at = excluded.updated_at",
            params![username_key, username, updated_at],
        )?;
        Ok(())
    }

    pub fn list_users(&self) -> anyhow::Result<Vec<UserRow>> {
        let mut statement = self.connection.prepare(
            "SELECT a.username_key, a.username, a.updated_at, s.username_key IS NOT NULL
             FROM users a
             LEFT JOIN vpn_sessions s ON s.username_key = a.username_key
             ORDER BY a.updated_at DESC, a.username ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(UserRow {
                username_key: row.get(0)?,
                username: row.get(1)?,
                updated_at: row.get(2)?,
                has_proton_session: row.get(3)?,
            })
        })?;
        collect_rows(rows)
    }
}
