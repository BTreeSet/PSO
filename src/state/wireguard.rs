use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use super::support::{collect_rows, decode_json_column, unix_timestamp};
use super::{
    StateStore, WireGuardEndpointRow, WireGuardEndpointState, WireGuardEndpointStateUpdate,
};

impl StateStore {
    pub fn load_wireguard_endpoint_state(
        &self,
        outbound_tag: &str,
    ) -> Result<Option<WireGuardEndpointState>> {
        self.connection
            .query_row(
                "SELECT outbound_tag, provider, identity, server_id, server_name, endpoint,
                        peer_public_key, pre_shared_key, private_key, public_key,
                        assigned_ips_json, allowed_ips_json, persistent_keepalive_interval,
                        reserved_json, mtu, expires_at_ms, refresh_at_ms, updated_at
                 FROM wireguard_endpoint_states
                 WHERE outbound_tag = ?1",
                params![outbound_tag],
                |row| {
                    let assigned_ips_json: String = row.get(10)?;
                    let allowed_ips_json: String = row.get(11)?;
                    let reserved_json: Option<String> = row.get(13)?;
                    Ok(WireGuardEndpointState {
                        outbound_tag: row.get(0)?,
                        provider: row.get(1)?,
                        identity: row.get(2)?,
                        server_id: row.get(3)?,
                        server_name: row.get(4)?,
                        endpoint: row.get(5)?,
                        peer_public_key: row.get(6)?,
                        pre_shared_key: row.get(7)?,
                        private_key: row.get(8)?,
                        public_key: row.get(9)?,
                        assigned_ips: decode_json_column(&assigned_ips_json, 10)?,
                        allowed_ips: decode_json_column(&allowed_ips_json, 11)?,
                        persistent_keepalive_interval: row.get(12)?,
                        reserved: reserved_json
                            .as_deref()
                            .map(|json| decode_json_column(json, 13))
                            .transpose()?,
                        mtu: row.get(14)?,
                        expires_at_ms: row.get(15)?,
                        refresh_at_ms: row.get(16)?,
                        updated_at: row.get(17)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn store_wireguard_endpoint_state(
        &self,
        update: WireGuardEndpointStateUpdate<'_>,
    ) -> Result<()> {
        self.upsert_wireguard_endpoint_state(&update)?;
        self.record_event(
            update.identity,
            Some(update.outbound_tag),
            "wireguard_endpoint_state_updated",
            Some(&serde_json::to_string(&serde_json::json!({
                "provider": update.provider,
                "server_id": update.server_id,
                "server_name": update.server_name,
                "endpoint": update.endpoint,
            }))?),
        )
    }

    pub fn list_wireguard_endpoints(&self, limit: usize) -> Result<Vec<WireGuardEndpointRow>> {
        let mut statement = self.connection.prepare(
            "SELECT outbound_tag, provider, identity, server_name, endpoint, assigned_ips_json,
                    allowed_ips_json, persistent_keepalive_interval, reserved_json,
                    refresh_at_ms, expires_at_ms, updated_at
             FROM wireguard_endpoint_states
             ORDER BY updated_at DESC, outbound_tag ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            let assigned_ips_json: String = row.get(5)?;
            let allowed_ips_json: String = row.get(6)?;
            let reserved_json: Option<String> = row.get(8)?;
            Ok(WireGuardEndpointRow {
                outbound_tag: row.get(0)?,
                provider: row.get(1)?,
                identity: row.get(2)?,
                server_name: row.get(3)?,
                endpoint: row.get(4)?,
                assigned_ips: decode_json_column(&assigned_ips_json, 5)?,
                allowed_ips: decode_json_column(&allowed_ips_json, 6)?,
                persistent_keepalive_interval: row.get(7)?,
                reserved: reserved_json
                    .as_deref()
                    .map(|json| decode_json_column(json, 8))
                    .transpose()?,
                refresh_at_ms: row.get(9)?,
                expires_at_ms: row.get(10)?,
                updated_at: row.get(11)?,
            })
        })?;
        collect_rows(rows)
    }

    pub(super) fn upsert_wireguard_endpoint_state(
        &self,
        update: &WireGuardEndpointStateUpdate<'_>,
    ) -> Result<()> {
        let assigned_ips_json = serde_json::to_string(update.assigned_ips)?;
        let allowed_ips_json = serde_json::to_string(update.allowed_ips)?;
        let reserved_json = update.reserved.map(serde_json::to_string).transpose()?;
        self.connection.execute(
            "INSERT INTO wireguard_endpoint_states
               (outbound_tag, provider, identity, server_id, server_name, endpoint,
                     peer_public_key, pre_shared_key, private_key, public_key, assigned_ips_json,
                     allowed_ips_json, persistent_keepalive_interval, reserved_json, mtu,
                     expires_at_ms, refresh_at_ms, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
             ON CONFLICT(outbound_tag) DO UPDATE SET
               provider = excluded.provider,
               identity = excluded.identity,
               server_id = excluded.server_id,
               server_name = excluded.server_name,
               endpoint = excluded.endpoint,
               peer_public_key = excluded.peer_public_key,
                    pre_shared_key = excluded.pre_shared_key,
               private_key = excluded.private_key,
               public_key = excluded.public_key,
               assigned_ips_json = excluded.assigned_ips_json,
               allowed_ips_json = excluded.allowed_ips_json,
               persistent_keepalive_interval = excluded.persistent_keepalive_interval,
               reserved_json = excluded.reserved_json,
               mtu = excluded.mtu,
               expires_at_ms = excluded.expires_at_ms,
               refresh_at_ms = excluded.refresh_at_ms,
               updated_at = excluded.updated_at",
            params![
                update.outbound_tag,
                update.provider,
                update.identity,
                update.server_id,
                update.server_name,
                update.endpoint,
                update.peer_public_key,
                update.pre_shared_key,
                update.private_key,
                update.public_key,
                assigned_ips_json,
                allowed_ips_json,
                update.persistent_keepalive_interval,
                reserved_json,
                update.mtu,
                update.expires_at_ms,
                update.refresh_at_ms,
                unix_timestamp()?
            ],
        )?;
        Ok(())
    }
}
