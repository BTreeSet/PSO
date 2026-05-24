use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
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
    pub proton: ProtonAuthConfig,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        let mut usernames = std::collections::BTreeSet::new();
        for account in &self.proton.accounts {
            let name = account.name.trim();
            if name.is_empty() {
                bail!("auth.proton.accounts entries must have a non-empty name");
            }
            if !names.insert(name.to_string()) {
                bail!("duplicate Proton account name '{name}'");
            }

            let username = account.username.trim();
            if username.is_empty() {
                bail!("auth.proton.accounts entry '{name}' must have a non-empty username");
            }
            if !usernames.insert(username.to_string()) {
                bail!("duplicate Proton username '{username}' in auth.proton.accounts");
            }

            if account.tier.trim().is_empty() {
                bail!("auth.proton.accounts entry '{name}' must declare a tier");
            }
            if account.password.is_some() && account.password_file.is_some() {
                bail!(
                    "auth.proton.accounts entry '{name}' cannot set both password and password_file"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProtonAuthConfig {
    pub accounts: Vec<ProtonAccountConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProtonAccountConfig {
    pub name: String,
    pub username: String,
    pub tier: String,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
    pub totp: Option<String>,
    pub no_prompt: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TopologyConfig {
    pub account: Option<String>,
    pub country: Option<String>,
    pub netzone: Option<String>,
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
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ControlPlaneDefaults {
    pub account: Option<String>,
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
