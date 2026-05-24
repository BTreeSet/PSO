use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::singbox_adapter::default_allowed_ips;

pub const PROTON_PROVIDER: &str = "proton";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct KnownWireGuardProvider {
    pub name: &'static str,
    pub mode: &'static str,
    pub notes: &'static str,
}

pub const KNOWN_WIREGUARD_PROVIDERS: &[KnownWireGuardProvider] = &[
    KnownWireGuardProvider {
        name: "proton",
        mode: "dynamic-api",
        notes: "Proton SRP auth, VPN session refresh, logical topology fetch, and certificate registration are implemented natively.",
    },
    KnownWireGuardProvider {
        name: "airvpn",
        mode: "static-wireguard-catalog",
        notes: "Declare WireGuard endpoints, ports, peer public keys, and assigned tunnel addresses in providers.wireguard.",
    },
    KnownWireGuardProvider {
        name: "fastestvpn",
        mode: "static-wireguard-catalog",
        notes: "Declare provider-issued WireGuard endpoint metadata in providers.wireguard.",
    },
    KnownWireGuardProvider {
        name: "ivpn",
        mode: "static-wireguard-catalog",
        notes: "Supports alternate WireGuard ports when supplied in the provider catalog.",
    },
    KnownWireGuardProvider {
        name: "mullvad",
        mode: "static-wireguard-catalog",
        notes: "Supports peer reserved bytes for providers that require them.",
    },
    KnownWireGuardProvider {
        name: "nordvpn",
        mode: "static-wireguard-catalog",
        notes: "Declare NordLynx/WireGuard endpoint metadata from provider-issued configuration.",
    },
    KnownWireGuardProvider {
        name: "surfshark",
        mode: "static-wireguard-catalog",
        notes: "Declare WireGuard endpoint metadata and use template filters for country/city/server selection.",
    },
    KnownWireGuardProvider {
        name: "windscribe",
        mode: "static-wireguard-catalog",
        notes: "Supports alternate WireGuard ports when supplied in the provider catalog.",
    },
    KnownWireGuardProvider {
        name: "custom",
        mode: "static-wireguard-catalog",
        notes: "Use for any WireGuard-capable provider when endpoint, peer public key, and assigned tunnel address are known.",
    },
    KnownWireGuardProvider {
        name: "cyberghost",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied; OpenVPN-only features are excluded.",
    },
    KnownWireGuardProvider {
        name: "pia",
        mode: "static-wireguard-catalog",
        notes: "Private Internet Access can be modeled from provider-issued WireGuard endpoint metadata.",
    },
    KnownWireGuardProvider {
        name: "privatevpn",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied.",
    },
    KnownWireGuardProvider {
        name: "purevpn",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied.",
    },
    KnownWireGuardProvider {
        name: "torguard",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied.",
    },
    KnownWireGuardProvider {
        name: "vpnunlimited",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied.",
    },
    KnownWireGuardProvider {
        name: "vyprvpn",
        mode: "static-wireguard-catalog",
        notes: "Supported when provider-issued WireGuard endpoint metadata is supplied.",
    },
];

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProvidersConfig {
    pub wireguard: Vec<WireGuardProviderConfig>,
}

impl ProvidersConfig {
    pub fn wireguard_provider(&self, name: &str) -> Option<&WireGuardProviderConfig> {
        let normalized = normalize_provider_name(name);
        self.wireguard
            .iter()
            .find(|provider| normalize_provider_name(&provider.name) == normalized)
    }

    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        for provider in &self.wireguard {
            let name = normalize_provider_name(&provider.name);
            if name.is_empty() {
                anyhow::bail!("providers.wireguard entries must have a non-empty name");
            }
            if name == PROTON_PROVIDER {
                anyhow::bail!(
                    "provider name 'proton' is reserved for PSO's native Proton integration"
                );
            }
            if !names.insert(name.clone()) {
                anyhow::bail!("duplicate WireGuard provider catalog '{name}'");
            }
            if provider.servers.is_empty() {
                anyhow::bail!(
                    "WireGuard provider catalog '{name}' must contain at least one server"
                );
            }
            for server in &provider.servers {
                server.validate(&provider.name)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct WireGuardProviderConfig {
    pub name: String,
    pub default_port: Option<u16>,
    pub local_address: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub servers: Vec<WireGuardServerConfig>,
}

impl Default for WireGuardProviderConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            default_port: Some(51820),
            local_address: Vec::new(),
            allowed_ips: default_allowed_ips(),
            persistent_keepalive_interval: Some(25),
            servers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct WireGuardServerConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub endpoint_port: Option<u16>,
    pub public_key: Option<String>,
    pub load: Option<u8>,
    pub status: Option<i32>,
    pub features: Vec<String>,
    pub local_address: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<[u8; 3]>,
}

impl WireGuardServerConfig {
    fn validate(&self, provider_name: &str) -> Result<()> {
        if self
            .endpoint
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            anyhow::bail!(
                "WireGuard provider catalog '{provider_name}' contains a server without endpoint"
            );
        }
        if self
            .public_key
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            anyhow::bail!(
                "WireGuard provider catalog '{provider_name}' contains server {} without public_key",
                self.display_name()
            );
        }
        Ok(())
    }

    pub fn stable_id(&self) -> String {
        self.id
            .as_deref()
            .or(self.name.as_deref())
            .or(self.endpoint.as_deref())
            .unwrap_or("wireguard-server")
            .to_string()
    }

    pub fn display_name(&self) -> String {
        self.name
            .as_deref()
            .or(self.id.as_deref())
            .or(self.endpoint.as_deref())
            .unwrap_or("wireguard-server")
            .to_string()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WireGuardServerFilter {
    pub country: Option<StringMatch>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub server: Option<String>,
    pub features: Vec<String>,
    pub max_load: Option<u8>,
    pub status: Option<i32>,
    pub sort_by: WireGuardSortMode,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StringMatch {
    One(String),
    Many(Vec<String>),
}

impl StringMatch {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(expected) => expected.eq_ignore_ascii_case(value),
            Self::Many(expected) => expected.iter().any(|item| item.eq_ignore_ascii_case(value)),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireGuardSortMode {
    #[default]
    LoadAsc,
    NameAsc,
}

#[derive(Clone, Debug, Default)]
pub struct WireGuardEndpointOverrides {
    pub local_address: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireGuardEndpointResolution {
    pub provider: String,
    pub server_id: String,
    pub server_name: String,
    pub endpoint: String,
    pub peer_public_key: String,
    pub assigned_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_interval: Option<u16>,
    pub reserved: Option<Vec<u8>>,
}

pub fn known_wireguard_providers() -> &'static [KnownWireGuardProvider] {
    KNOWN_WIREGUARD_PROVIDERS
}

pub fn normalize_provider_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn select_wireguard_server(
    provider: &WireGuardProviderConfig,
    filter: &WireGuardServerFilter,
    avoid_server_id: Option<&str>,
) -> Result<WireGuardServerConfig> {
    let mut candidates = provider
        .servers
        .iter()
        .filter(|server| wireguard_server_matches(server, filter))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| match filter.sort_by {
        WireGuardSortMode::LoadAsc => left
            .load
            .unwrap_or(u8::MAX)
            .cmp(&right.load.unwrap_or(u8::MAX))
            .then_with(|| left.display_name().cmp(&right.display_name())),
        WireGuardSortMode::NameAsc => left.display_name().cmp(&right.display_name()),
    });

    if let Some(avoid_server_id) = avoid_server_id
        && candidates.len() > 1
        && let Some(index) = candidates
            .iter()
            .position(|server| server.stable_id() == avoid_server_id)
    {
        candidates.rotate_left(index + 1);
    }

    candidates.into_iter().next().ok_or_else(|| {
        anyhow!(
            "no WireGuard server in provider catalog '{}' matched the requested filter",
            provider.name
        )
    })
}

pub fn resolve_wireguard_endpoint(
    provider: &WireGuardProviderConfig,
    server: &WireGuardServerConfig,
    overrides: &WireGuardEndpointOverrides,
) -> Result<WireGuardEndpointResolution> {
    let raw_endpoint = server
        .endpoint
        .as_deref()
        .context("WireGuard server is missing endpoint")?;
    let endpoint = endpoint_with_port(
        raw_endpoint,
        server
            .endpoint_port
            .or(provider.default_port)
            .unwrap_or(51820),
    )?;
    let peer_public_key = server
        .public_key
        .clone()
        .context("WireGuard server is missing public_key")?;
    let assigned_ips = first_non_empty([
        overrides.local_address.as_slice(),
        server.local_address.as_slice(),
        provider.local_address.as_slice(),
    ])
    .ok_or_else(|| {
        anyhow!(
            "WireGuard provider '{}' server {} requires local_address in the template, server, or provider catalog",
            provider.name,
            server.display_name()
        )
    })?
    .to_vec();
    let allowed_ips = first_non_empty([
        overrides.allowed_ips.as_slice(),
        server.allowed_ips.as_slice(),
        provider.allowed_ips.as_slice(),
    ])
    .map(ToOwned::to_owned)
    .unwrap_or_else(default_allowed_ips);
    let reserved = overrides
        .reserved
        .clone()
        .or_else(|| server.reserved.map(|bytes| bytes.to_vec()));
    if let Some(bytes) = &reserved
        && bytes.len() != 3
    {
        anyhow::bail!("WireGuard reserved value must contain exactly 3 bytes");
    }

    Ok(WireGuardEndpointResolution {
        provider: normalize_provider_name(&provider.name),
        server_id: server.stable_id(),
        server_name: server.display_name(),
        endpoint,
        peer_public_key,
        assigned_ips,
        allowed_ips,
        persistent_keepalive_interval: overrides
            .persistent_keepalive_interval
            .or(server.persistent_keepalive_interval)
            .or(provider.persistent_keepalive_interval),
        reserved,
    })
}

fn first_non_empty<'a>(slices: impl IntoIterator<Item = &'a [String]>) -> Option<&'a [String]> {
    slices.into_iter().find(|slice| !slice.is_empty())
}

fn wireguard_server_matches(
    server: &WireGuardServerConfig,
    filter: &WireGuardServerFilter,
) -> bool {
    if let Some(server_filter) = &filter.server {
        let matches_name = server
            .name
            .as_deref()
            .map(|name| name.eq_ignore_ascii_case(server_filter))
            .unwrap_or(false);
        let matches_id = server
            .id
            .as_deref()
            .map(|id| id.eq_ignore_ascii_case(server_filter))
            .unwrap_or(false);
        if !matches_name && !matches_id {
            return false;
        }
    }

    if let Some(country) = &filter.country
        && !server
            .country
            .as_deref()
            .map(|value| country.contains(value))
            .unwrap_or(false)
    {
        return false;
    }

    if let Some(city) = &filter.city
        && !server
            .city
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case(city))
            .unwrap_or(false)
    {
        return false;
    }

    if let Some(region) = &filter.region
        && !server
            .region
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case(region))
            .unwrap_or(false)
    {
        return false;
    }

    if let Some(max_load) = filter.max_load
        && server.load.unwrap_or(0) > max_load
    {
        return false;
    }

    if let Some(status) = filter.status
        && server.status.unwrap_or(1) != status
    {
        return false;
    }

    filter.features.iter().all(|requested| {
        server
            .features
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(requested))
    })
}

fn endpoint_with_port(endpoint: &str, default_port: u16) -> Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        anyhow::bail!("WireGuard endpoint cannot be empty");
    }

    if let Some((host, port)) = parse_explicit_endpoint(endpoint)? {
        return Ok(format_endpoint(&host, port));
    }

    Ok(format_endpoint(
        endpoint.trim_matches(['[', ']']),
        default_port,
    ))
}

fn parse_explicit_endpoint(endpoint: &str) -> Result<Option<(String, u16)>> {
    if let Some(rest) = endpoint.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
    {
        return Ok(Some((host.to_string(), parse_port(endpoint, port)?)));
    }

    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Ok(None);
    };
    if host.contains(':') {
        return Ok(None);
    }
    Ok(Some((host.to_string(), parse_port(endpoint, port)?)))
}

fn parse_port(endpoint: &str, port: &str) -> Result<u16> {
    port.parse::<u16>()
        .map_err(|_| anyhow!("invalid WireGuard endpoint port in '{endpoint}'"))
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_static_wireguard_endpoint_with_provider_defaults() {
        let provider = WireGuardProviderConfig {
            name: "mullvad".into(),
            local_address: vec!["10.64.10.2/32".into()],
            servers: vec![WireGuardServerConfig {
                id: Some("se1".into()),
                name: Some("SE Stockholm 1".into()),
                country: Some("SE".into()),
                endpoint: Some("198.51.100.10".into()),
                public_key: Some("peer".into()),
                reserved: Some([1, 2, 3]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let server = select_wireguard_server(
            &provider,
            &WireGuardServerFilter {
                country: Some(StringMatch::One("SE".into())),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let resolved =
            resolve_wireguard_endpoint(&provider, &server, &WireGuardEndpointOverrides::default())
                .unwrap();

        assert_eq!(resolved.endpoint, "198.51.100.10:51820");
        assert_eq!(resolved.assigned_ips, vec!["10.64.10.2/32"]);
        assert_eq!(resolved.reserved, Some(vec![1, 2, 3]));
    }

    #[test]
    fn cycles_away_from_current_server_when_requested() {
        let provider = WireGuardProviderConfig {
            name: "custom".into(),
            servers: vec![
                WireGuardServerConfig {
                    id: Some("a".into()),
                    endpoint: Some("198.51.100.1".into()),
                    public_key: Some("a-key".into()),
                    load: Some(1),
                    ..Default::default()
                },
                WireGuardServerConfig {
                    id: Some("b".into()),
                    endpoint: Some("198.51.100.2".into()),
                    public_key: Some("b-key".into()),
                    load: Some(2),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let selected =
            select_wireguard_server(&provider, &WireGuardServerFilter::default(), Some("a"))
                .unwrap();
        assert_eq!(selected.stable_id(), "b");
    }
}
