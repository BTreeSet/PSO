use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Proxy};
use tokio::time;
use tracing::{error, info, warn};

#[derive(Clone, Debug, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Dead,
    Leaking,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProbeResult {
    pub status: HealthStatus,
    pub returned_ip: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct HealthMonitor {
    client: Client,
    raw_connection_ip: String,
    interval: Duration,
}

impl HealthMonitor {
    pub fn new(raw_connection_ip: impl Into<String>, interval: Duration) -> Result<Self> {
        Ok(Self {
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            raw_connection_ip: raw_connection_ip.into(),
            interval,
        })
    }

    pub async fn acquire_baseline() -> Result<String> {
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        match probe_cloudflare(&client).await {
            Ok(ip) => Ok(ip),
            Err(_) => probe_ipinfo(&client).await,
        }
        .context("failed to acquire raw connection IP baseline")
    }

    pub async fn probe_once(&self, proxy_url: Option<&str>) -> ProbeResult {
        let client = match proxy_url {
            Some(proxy_url) => match proxied_client(proxy_url) {
                Ok(client) => client,
                Err(error) => {
                    return ProbeResult {
                        status: HealthStatus::Dead,
                        returned_ip: None,
                        reason: error.to_string(),
                    };
                }
            },
            None => self.client.clone(),
        };

        let returned_ip = match probe_cloudflare(&client).await {
            Ok(ip) => Ok(ip),
            Err(primary_error) => probe_ipinfo(&client)
                .await
                .with_context(|| format!("primary Cloudflare probe failed: {primary_error}")),
        };

        match returned_ip {
            Ok(ip) if ip == self.raw_connection_ip => ProbeResult {
                status: HealthStatus::Leaking,
                returned_ip: Some(ip),
                reason: "probe returned the raw connection IP".into(),
            },
            Ok(ip) => ProbeResult {
                status: HealthStatus::Healthy,
                returned_ip: Some(ip),
                reason: "probe returned a non-baseline IP".into(),
            },
            Err(error) => ProbeResult {
                status: HealthStatus::Dead,
                returned_ip: None,
                reason: error.to_string(),
            },
        }
    }

    pub async fn run_loop(&self, outbound_tag: String, proxy_url: Option<String>) -> Result<()> {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            let result = self.probe_once(proxy_url.as_deref()).await;
            match result.status {
                HealthStatus::Healthy => {
                    info!(%outbound_tag, ip = ?result.returned_ip, "outbound healthy")
                }
                HealthStatus::Dead => {
                    warn!(%outbound_tag, reason = %result.reason, "outbound dead")
                }
                HealthStatus::Leaking => {
                    error!(%outbound_tag, ip = ?result.returned_ip, "critical VPN leak detected")
                }
            }
        }
    }
}

fn proxied_client(proxy_url: &str) -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(10))
        .proxy(Proxy::all(proxy_url)?)
        .build()?)
}

async fn probe_cloudflare(client: &Client) -> Result<String> {
    let body = client
        .get("https://cloudflare.com/cdn-cgi/trace")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    parse_cloudflare_trace(&body)
        .ok_or_else(|| anyhow!("Cloudflare trace did not include an ip line"))
}

async fn probe_ipinfo(client: &Client) -> Result<String> {
    Ok(client
        .get("https://ipinfo.io/ip")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?
        .trim()
        .to_string())
}

pub fn parse_cloudflare_trace(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("ip="))
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cloudflare_ip_line() {
        let body = "fl=123\nip=203.0.113.55\nts=123\n";
        assert_eq!(parse_cloudflare_trace(body).unwrap(), "203.0.113.55");
    }
}
