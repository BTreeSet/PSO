use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::Deserialize;

use crate::provider::{WireGuardProviderConfig, WireGuardProviderSource, WireGuardServerConfig};

pub async fn resolve_wireguard_provider_catalog(
    provider: &WireGuardProviderConfig,
) -> Result<WireGuardProviderConfig> {
    let fetched_servers = match provider.source {
        WireGuardProviderSource::Static => return Ok(provider.clone()),
        WireGuardProviderSource::MullvadApi => fetch_mullvad_servers().await,
        WireGuardProviderSource::IvpnApi => fetch_ivpn_servers().await,
        WireGuardProviderSource::SurfsharkApi => fetch_surfshark_servers().await,
    };

    match fetched_servers {
        Ok(servers) if !servers.is_empty() => {
            let mut resolved = provider.clone();
            resolved.servers = servers;
            Ok(resolved)
        }
        Ok(_) if !provider.servers.is_empty() => Ok(provider.clone()),
        Ok(_) => Err(anyhow!(
            "provider '{}' dynamic catalog returned no WireGuard servers",
            provider.name
        )),
        Err(_error) if !provider.servers.is_empty() => Ok(provider.clone()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to resolve dynamic WireGuard catalog for provider '{}'",
                provider.name
            )
        }),
    }
}

async fn fetch_mullvad_servers() -> Result<Vec<WireGuardServerConfig>> {
    let data: Vec<MullvadRelay> = http_client()?
        .get("https://api.mullvad.net/www/relays/all/")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(map_mullvad_servers(data))
}

async fn fetch_ivpn_servers() -> Result<Vec<WireGuardServerConfig>> {
    let data: IvpnApiResponse = http_client()?
        .get("https://api.ivpn.net/v4/servers/stats")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(map_ivpn_servers(data.servers))
}

async fn fetch_surfshark_servers() -> Result<Vec<WireGuardServerConfig>> {
    let client = http_client()?;
    let mut servers_by_host = BTreeMap::new();
    for cluster in ["generic", "double", "static", "obfuscated"] {
        let url = format!("https://api.surfshark.com/v4/server/clusters/{cluster}");
        let response: Vec<SurfsharkServer> = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        for server in map_surfshark_servers(response) {
            let Some(host) = server.endpoint.clone() else {
                continue;
            };
            servers_by_host.entry(host).or_insert(server);
        }
    }
    Ok(servers_by_host.into_values().collect())
}

fn http_client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(30))
        .user_agent("PSO/0.1 Rust-Control-Plane")
        .build()
        .context("failed to build provider discovery HTTP client")
}

fn map_mullvad_servers(data: Vec<MullvadRelay>) -> Vec<WireGuardServerConfig> {
    data.into_iter()
        .filter(|relay| relay.active && !relay.pub_key.trim().is_empty())
        .filter_map(|relay| {
            let endpoint = first_non_empty([relay.ipv4.as_str(), relay.ipv6.as_str()])?;
            let features = mullvad_features(&relay);
            Some(WireGuardServerConfig {
                id: Some(relay.hostname.clone()),
                name: Some(relay.hostname),
                country: Some(relay.country),
                city: Some(relay.city),
                region: None,
                endpoint: Some(endpoint.to_string()),
                endpoint_port: None,
                public_key: Some(relay.pub_key),
                load: None,
                status: Some(1),
                features,
                ..WireGuardServerConfig::default()
            })
        })
        .collect()
}

fn map_ivpn_servers(data: Vec<IvpnServer>) -> Vec<WireGuardServerConfig> {
    data.into_iter()
        .filter_map(|server| {
            let endpoint = server.hostnames.wireguard?;
            let public_key = server.wg_public_key?;
            let (city, region) = split_city_region(&server.city);
            Some(WireGuardServerConfig {
                id: Some(endpoint.clone()),
                name: Some(endpoint.clone()),
                country: Some(server.country),
                city,
                region,
                endpoint: Some(endpoint),
                endpoint_port: None,
                public_key: Some(public_key),
                load: None,
                status: Some(if server.is_active { 1 } else { 0 }),
                features: server
                    .isp
                    .filter(|isp| !isp.trim().is_empty())
                    .map(|isp| vec![isp])
                    .unwrap_or_default(),
                ..WireGuardServerConfig::default()
            })
        })
        .collect()
}

fn map_surfshark_servers(data: Vec<SurfsharkServer>) -> Vec<WireGuardServerConfig> {
    data.into_iter()
        .filter_map(|server| {
            let public_key = server.pub_key?;
            Some(WireGuardServerConfig {
                id: Some(server.connection_name.clone()),
                name: Some(server.connection_name.clone()),
                country: Some(server.country),
                city: Some(server.location),
                region: Some(server.region),
                endpoint: Some(server.connection_name),
                endpoint_port: None,
                public_key: Some(public_key),
                load: None,
                status: Some(1),
                features: Vec::new(),
                ..WireGuardServerConfig::default()
            })
        })
        .collect()
}

fn mullvad_features(relay: &MullvadRelay) -> Vec<String> {
    let mut features = Vec::new();
    if relay.owned {
        features.push("owned".to_string());
    }
    if !relay.provider.trim().is_empty() {
        features.push(relay.provider.clone());
    }
    if !relay.relay_type.trim().is_empty() {
        features.push(relay.relay_type.clone());
    }
    features
}

fn split_city_region(value: &str) -> (Option<String>, Option<String>) {
    match value.split_once(", ") {
        Some((city, region)) => (Some(city.to_string()), Some(region.to_string())),
        None if value.trim().is_empty() => (None, None),
        None => (Some(value.to_string()), None),
    }
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    values.into_iter().find(|value| !value.trim().is_empty())
}

#[derive(Clone, Debug, Deserialize)]
struct MullvadRelay {
    hostname: String,
    #[serde(rename = "country_name")]
    country: String,
    #[serde(rename = "city_name")]
    city: String,
    active: bool,
    owned: bool,
    provider: String,
    #[serde(rename = "ipv4_addr_in")]
    ipv4: String,
    #[serde(rename = "ipv6_addr_in")]
    ipv6: String,
    #[serde(rename = "type")]
    relay_type: String,
    #[serde(rename = "pubkey")]
    pub_key: String,
}

#[derive(Clone, Debug, Deserialize)]
struct IvpnApiResponse {
    servers: Vec<IvpnServer>,
}

#[derive(Clone, Debug, Deserialize)]
struct IvpnServer {
    hostnames: IvpnHostnames,
    #[serde(rename = "is_active")]
    is_active: bool,
    country: String,
    city: String,
    #[serde(rename = "isp")]
    isp: Option<String>,
    #[serde(rename = "wg_public_key")]
    wg_public_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct IvpnHostnames {
    wireguard: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SurfsharkServer {
    #[serde(rename = "connectionName")]
    connection_name: String,
    region: String,
    country: String,
    location: String,
    #[serde(rename = "pubKey")]
    pub_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_mullvad_wireguard_servers() {
        let servers = map_mullvad_servers(vec![MullvadRelay {
            hostname: "se-sto-wg-001".into(),
            country: "Sweden".into(),
            city: "Stockholm".into(),
            active: true,
            owned: true,
            provider: "m247".into(),
            ipv4: "198.51.100.10".into(),
            ipv6: String::new(),
            relay_type: "wireguard".into(),
            pub_key: "peer-key".into(),
        }]);

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].endpoint.as_deref(), Some("198.51.100.10"));
        assert_eq!(servers[0].public_key.as_deref(), Some("peer-key"));
        assert!(servers[0].features.iter().any(|feature| feature == "owned"));
    }

    #[test]
    fn maps_ivpn_wireguard_servers() {
        let servers = map_ivpn_servers(vec![IvpnServer {
            hostnames: IvpnHostnames {
                wireguard: Some("wg.ivpn.example".into()),
            },
            is_active: true,
            country: "Sweden".into(),
            city: "Stockholm, SE".into(),
            isp: Some("ivpn".into()),
            wg_public_key: Some("peer-key".into()),
        }]);

        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].endpoint.as_deref(), Some("wg.ivpn.example"));
        assert_eq!(servers[0].city.as_deref(), Some("Stockholm"));
        assert_eq!(servers[0].region.as_deref(), Some("SE"));
    }

    #[test]
    fn maps_surfshark_wireguard_servers() {
        let servers = map_surfshark_servers(vec![SurfsharkServer {
            connection_name: "ams.prod.surfshark.com".into(),
            region: "Europe".into(),
            country: "Netherlands".into(),
            location: "Amsterdam".into(),
            pub_key: Some("peer-key".into()),
        }]);

        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0].endpoint.as_deref(),
            Some("ams.prod.surfshark.com")
        );
        assert_eq!(servers[0].region.as_deref(), Some("Europe"));
    }
}
