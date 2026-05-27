use rusqlite::params;

use super::support::{collect_rows, unix_timestamp};
use super::{HealthCheckRow, HealthRecord, RuntimeEventRow, StateStore, username_state_key};

impl StateStore {
    pub fn record_event(
        &self,
        username: Option<&str>,
        outbound_tag: Option<&str>,
        event_type: &str,
        details_json: Option<&str>,
    ) -> anyhow::Result<()> {
        let username_key = username.map(username_state_key);
        if let (Some(username_key), Some(username)) = (&username_key, username) {
            self.upsert_user(username_key, username, unix_timestamp()?)?;
        }
        self.connection.execute(
            "INSERT INTO runtime_events
               (occurred_at, username_key, outbound_tag, event_type, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                unix_timestamp()?,
                username_key,
                outbound_tag,
                event_type,
                details_json
            ],
        )?;
        Ok(())
    }

    pub fn record_health(&self, record: HealthRecord<'_>) -> anyhow::Result<()> {
        let username_key = record.username.map(username_state_key);
        if let (Some(username_key), Some(username)) = (&username_key, record.username) {
            self.upsert_user(username_key, username, unix_timestamp()?)?;
        }
        self.connection.execute(
            "INSERT INTO health_checks
               (occurred_at, username_key, outbound_tag, status, raw_ip, returned_ip, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                unix_timestamp()?,
                username_key,
                record.outbound_tag,
                record.status,
                record.raw_ip,
                record.returned_ip,
                record.reason
            ],
        )?;
        Ok(())
    }

    pub fn record_config_deployment(
        &self,
        config_hash: &str,
        outbound_tags_json: &str,
        active_config: &str,
        success: bool,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
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

    pub fn list_events(&self, limit: usize) -> anyhow::Result<Vec<RuntimeEventRow>> {
        let mut statement = self.connection.prepare(
            "SELECT e.id, e.occurred_at, a.username, e.outbound_tag, e.event_type, e.details_json
             FROM runtime_events e
               LEFT JOIN users a ON a.username_key = e.username_key
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

    pub fn list_health_checks(&self, limit: usize) -> anyhow::Result<Vec<HealthCheckRow>> {
        let mut statement = self.connection.prepare(
            "SELECT h.id, h.occurred_at, a.username, h.outbound_tag, h.status,
                    h.raw_ip, h.returned_ip, h.reason
             FROM health_checks h
               LEFT JOIN users a ON a.username_key = h.username_key
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
}
