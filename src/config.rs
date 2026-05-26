use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::provider::ProvidersConfig;

pub const DEFAULT_API_BASE_URL: &str = "https://account.protonvpn.com/api";
pub const DEFAULT_STATE_DIR: &str = "pso-state";
pub const DEFAULT_PROTON_CLIENT_ID: &str = "android-vpn";
pub const DEFAULT_PROTON_APP_VERSION: &str = "5.18.46.0";
const DEFAULT_PROTON_DEVICE_NAME: &str = "pso-control-plane";

#[derive(Clone, Debug)]
pub struct RuntimeContext {
    pub api_base_url: String,
    pub state_dir: PathBuf,
    pub proton_client: ProtonClientProfile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtonClientProfile {
    pub client_id: String,
    pub app_version: String,
    pub app_version_header: String,
    pub device_name: String,
    pub user_agent: String,
}

impl Default for ProtonClientProfile {
    fn default() -> Self {
        Self::from_auth_config(&ProtonAuthConfig::default())
    }
}

impl ProtonClientProfile {
    pub fn from_auth_config(config: &ProtonAuthConfig) -> Self {
        let client_id = normalize_non_empty(config.client_id.as_deref())
            .unwrap_or_else(|| DEFAULT_PROTON_CLIENT_ID.to_string());
        let app_version = normalize_non_empty(config.app_version.as_deref())
            .unwrap_or_else(|| DEFAULT_PROTON_APP_VERSION.to_string());
        let device_name = normalize_non_empty(config.device_name.as_deref())
            .unwrap_or_else(default_proton_device_name);
        let user_agent = normalize_non_empty(config.user_agent.as_deref())
            .map(sanitize_header_value)
            .unwrap_or_else(|| default_proton_user_agent(&app_version, &device_name));

        Self {
            app_version_header: sanitize_header_value(format!("{client_id}@{app_version}")),
            client_id,
            app_version,
            device_name,
            user_agent,
        }
    }
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
    pub client_id: Option<String>,
    pub app_version: Option<String>,
    pub device_name: Option<String>,
    pub user_agent: Option<String>,
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
    #[serde(default = "default_session_keepalive_interval_secs")]
    pub session_keepalive_interval_secs: u64,
}

fn default_session_keepalive_interval_secs() -> u64 {
    900
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

fn default_proton_device_name() -> String {
    let hostname = std::env::var("HOSTNAME").ok();
    normalize_non_empty(hostname.as_deref())
        .unwrap_or_else(|| DEFAULT_PROTON_DEVICE_NAME.to_string())
}

fn default_proton_user_agent(app_version: &str, device_name: &str) -> String {
    sanitize_header_value(format!("ProtonVPN/{app_version} (Linux; {device_name})"))
}

fn normalize_non_empty(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn sanitize_header_value(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .chars()
        .map(|character| {
            if character.is_ascii() && !character.is_ascii_control() {
                character
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_default_proton_client_profile() {
        let profile = ProtonClientProfile::default();
        assert_eq!(profile.client_id, DEFAULT_PROTON_CLIENT_ID);
        assert_eq!(profile.app_version, DEFAULT_PROTON_APP_VERSION);
        assert_eq!(
            profile.app_version_header,
            format!("{DEFAULT_PROTON_CLIENT_ID}@{DEFAULT_PROTON_APP_VERSION}")
        );
        assert!(profile.user_agent.starts_with("ProtonVPN/5.18.46.0"));
    }

    #[test]
    fn resolves_custom_proton_client_profile() {
        let profile = ProtonClientProfile::from_auth_config(&ProtonAuthConfig {
            client_id: Some("android_tv-vpn".into()),
            app_version: Some("5.18.46.0+os".into()),
            device_name: Some("edge-router".into()),
            user_agent: Some("CustomAgent/1.0\n".into()),
            accounts: Vec::new(),
        });

        assert_eq!(profile.client_id, "android_tv-vpn");
        assert_eq!(profile.app_version, "5.18.46.0+os");
        assert_eq!(profile.app_version_header, "android_tv-vpn@5.18.46.0+os");
        assert_eq!(profile.device_name, "edge-router");
        assert_eq!(profile.user_agent, "CustomAgent/1.0");
    }
}
