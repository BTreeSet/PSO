use anyhow::Result;

use super::support::collect_rows;
use super::{
    ForeignKeyViolationRow, PersistenceIntegrityReport, PersistenceSummary,
    PersistenceTableSummary, StateStore,
};

const TABLE_SUMMARIES: &[(&str, &str)] = &[
    ("users", "updated_at"),
    ("vpn_sessions", "updated_at"),
    ("proton_cookies", "updated_at"),
    ("runtime_events", "occurred_at"),
    ("health_checks", "occurred_at"),
    ("outbound_certificates", "updated_at"),
    ("config_deployments", "deployed_at"),
    ("wireguard_endpoint_states", "updated_at"),
];

impl StateStore {
    pub fn persistence_summary(&self) -> Result<PersistenceSummary> {
        let foreign_keys_enabled: i64 =
            self.connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;

        let mut tables = Vec::with_capacity(TABLE_SUMMARIES.len());
        for &(table, timestamp_column) in TABLE_SUMMARIES {
            let sql = format!("SELECT COUNT(*), MAX({timestamp_column}) FROM {table}");
            let (row_count, latest_at): (i64, Option<i64>) =
                self.connection
                    .query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?)))?;
            tables.push(PersistenceTableSummary {
                table,
                row_count,
                latest_at,
            });
        }

        Ok(PersistenceSummary {
            foreign_keys_enabled: foreign_keys_enabled != 0,
            tables,
        })
    }

    pub fn integrity_report(&self) -> Result<PersistenceIntegrityReport> {
        let mut integrity_statement = self.connection.prepare("PRAGMA integrity_check")?;
        let integrity_rows = integrity_statement.query_map([], |row| row.get(0))?;
        let integrity_check = collect_rows(integrity_rows)?;

        let mut foreign_key_statement = self.connection.prepare("PRAGMA foreign_key_check")?;
        let foreign_key_rows = foreign_key_statement.query_map([], |row| {
            Ok(ForeignKeyViolationRow {
                table: row.get(0)?,
                rowid: row.get(1)?,
                parent: row.get(2)?,
                fkid: row.get(3)?,
            })
        })?;
        let foreign_key_violations = collect_rows(foreign_key_rows)?;

        Ok(PersistenceIntegrityReport {
            integrity_check,
            foreign_key_violations,
        })
    }
}
