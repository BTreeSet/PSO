use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::provider::ProvidersConfig;

pub const DEFAULT_API_BASE_URL: &str = "https://api.protonvpn.ch";
pub const DEFAULT_STATE_DIR: &str = "pso-state";

#[derive(Clone, Debug)]
pub struct RuntimeContext {
    pub api_base_url: String,
    pub state_dir: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub api_base_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub providers: ProvidersConfig,
    pub auth: AuthConfig,
    pub topology: TopologyConfig,
    pub render: RenderConfig,
    pub control_plane: ControlPlaneDefaults,
    pub run: RunConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
    pub totp: Option<String>,
    pub no_prompt: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TopologyConfig {
    pub fallback_topology: Option<PathBuf>,
    pub require_live: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct RenderConfig {
    pub template: Option<PathBuf>,
    pub topology: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub active_config: Option<PathBuf>,
    pub singbox_pid: Option<i32>,
    pub singbox_bin: Option<PathBuf>,
    pub sessions: Vec<SessionEntry>,
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionEntry {
    pub username: String,
    pub tier: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ControlPlaneDefaults {
    pub active_config: Option<PathBuf>,
    pub singbox_pid: Option<i32>,
    pub singbox_bin: Option<PathBuf>,
    pub outbound_tag: Option<String>,
    pub endpoint: Option<String>,
    pub peer_public_key: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct RunConfig {
    pub proxy_url: Option<String>,
    pub interval_secs: Option<u64>,
}

pub fn read_optional_config(path: &PathBuf) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    read_json(path)
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}
