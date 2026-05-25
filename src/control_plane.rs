use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::time;
use tracing::{error, info, warn};

use crate::api::{CertificateRequest, ProtonAccessToken, ProtonApiClient};
use crate::crypto::{KeyMaterial, generate_key_material};
use crate::model::PhysicalServer;
use crate::process::sighup_process;
use crate::proton::{PROTON_WIREGUARD_KEEPALIVE_INTERVAL, proton_wireguard_assigned_ips};
use crate::scheduler::{RefreshDecision, RefreshScheduler};
use crate::singbox_adapter::build_wireguard_endpoint;

#[derive(Clone, Debug)]
pub struct ControlPlaneConfig {
    pub access_token: ProtonAccessToken,
    pub active_config: PathBuf,
    pub singbox_pid: i32,
    pub outbound_tag: String,
    pub device_name: String,
    pub selected_server: PhysicalServer,
}

#[derive(Clone, Debug)]
pub struct CertificateRefreshOutcome {
    pub expiration_time_ms: u64,
    pub refresh_time_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ControlPlane {
    api: ProtonApiClient,
    scheduler: RefreshScheduler,
}

impl ControlPlane {
    pub fn new(api: ProtonApiClient) -> Self {
        Self {
            api,
            scheduler: RefreshScheduler::default(),
        }
    }

    pub async fn run_refresh_loop(&self, config: ControlPlaneConfig) -> Result<()> {
        let mut key_material = generate_key_material();
        let mut expires_at_ms = 0;
        let mut refresh_count = 0;

        loop {
            let request = CertificateRequest::wireguard_session(
                &key_material.public_key_base64,
                &config.device_name,
            );
            let result = self
                .api
                .get_certificate(&config.access_token, &request)
                .await;
            let now_ms = current_time_ms();

            let decision = match result {
                Ok(certificate) => {
                    let endpoint = config
                        .selected_server
                        .proton_wireguard_endpoint()
                        .context("selected server has no Proton WireGuard endpoint")?;
                    let peer_public_key = config
                        .selected_server
                        .public_key
                        .clone()
                        .context("selected server has no WireGuard peer public key")?;
                    let address = proton_wireguard_assigned_ips();
                    let outbound = build_wireguard_endpoint(
                        &config.outbound_tag,
                        &key_material,
                        &endpoint,
                        &peer_public_key,
                        &address,
                        Some(PROTON_WIREGUARD_KEEPALIVE_INTERVAL),
                        None,
                    )?;
                    write_singbox_config(
                        &config.active_config,
                        &json!({ "endpoints": [outbound] }),
                    )?;
                    sighup_process(config.singbox_pid)?;

                    expires_at_ms = certificate.expiration_time_ms()?;
                    refresh_count = 0;
                    info!(tag = %config.outbound_tag, "certificate refreshed and sing-box reloaded");
                    self.scheduler
                        .next_after_success(now_ms, certificate.refresh_time_ms()?)
                }
                Err(error) => {
                    refresh_count += 1;
                    warn!(tag = %config.outbound_tag, %error, refresh_count, "certificate refresh failed");
                    self.scheduler
                        .next_after_failure(now_ms, expires_at_ms, refresh_count, None)
                }
            };

            match decision {
                RefreshDecision::Wait(delay) => time::sleep(delay).await,
                RefreshDecision::Exhausted => {
                    error!(tag = %config.outbound_tag, "refresh retries exhausted; rotating local key material");
                    key_material = generate_key_material();
                    refresh_count = 0;
                    time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    }

    pub async fn refresh_once(
        &self,
        config: &ControlPlaneConfig,
    ) -> Result<CertificateRefreshOutcome> {
        let key_material = generate_key_material();
        let request = CertificateRequest::wireguard_session(
            &key_material.public_key_base64,
            &config.device_name,
        );
        let certificate = self
            .api
            .get_certificate(&config.access_token, &request)
            .await?;
        let endpoint = config
            .selected_server
            .proton_wireguard_endpoint()
            .context("selected server has no Proton WireGuard endpoint")?;
        let peer_public_key = config
            .selected_server
            .public_key
            .clone()
            .context("selected server has no WireGuard peer public key")?;
        let address = proton_wireguard_assigned_ips();
        let outbound = build_wireguard_endpoint(
            &config.outbound_tag,
            &key_material,
            &endpoint,
            &peer_public_key,
            &address,
            Some(PROTON_WIREGUARD_KEEPALIVE_INTERVAL),
            None,
        )?;
        write_singbox_config(&config.active_config, &json!({ "endpoints": [outbound] }))?;
        sighup_process(config.singbox_pid)?;
        info!(tag = %config.outbound_tag, "certificate refreshed and sing-box reloaded");
        Ok(CertificateRefreshOutcome {
            expiration_time_ms: certificate.expiration_time_ms()?,
            refresh_time_ms: certificate.refresh_time_ms()?,
        })
    }
}

pub fn write_singbox_config(path: &PathBuf, value: &serde_json::Value) -> Result<()> {
    let parent = path
        .parent()
        .context("active sing-box config path must have a parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let mut temp_file = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp config in {}", parent.display()))?;
    serde_json::to_writer_pretty(&mut temp_file, value)
        .context("failed to serialize sing-box config")?;
    temp_file
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to persist {}", path.display()))?;
    Ok(())
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[allow(dead_code)]
fn _keep_key_material_send_sync(_: &KeyMaterial) {}
