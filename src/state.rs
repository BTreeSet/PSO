use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::RuntimeContext;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnSessionState {
    pub uid: String,
    pub refresh_token: String,
}

pub fn topology_state_file(context: &RuntimeContext) -> PathBuf {
    context.state_dir.join("logicals.json")
}

pub fn vpn_session_state_file(context: &RuntimeContext, username: &str) -> PathBuf {
    context
        .state_dir
        .join("users")
        .join(user_state_key(username))
        .join("vpn-session.json")
}

pub fn user_state_key(username: &str) -> String {
    hex::encode(Sha256::digest(username.as_bytes()))
}

pub fn store_vpn_session_state(uid: &str, refresh_token: &str, state_file: &PathBuf) -> Result<()> {
    let state = VpnSessionState {
        uid: uid.to_string(),
        refresh_token: refresh_token.to_string(),
    };
    write_state_file(state_file, &serde_json::to_string(&state)?)
}

pub fn load_vpn_session_state(state_file: &PathBuf) -> Result<VpnSessionState> {
    let state = fs::read_to_string(state_file)
        .with_context(|| format!("failed to read {}", state_file.display()))?;
    serde_json::from_str(&state).context("failed to decode VPN session state")
}

pub fn write_state_file(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_state_key_is_path_safe_and_opaque() {
        let key = user_state_key("alice@example.com");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|character| character.is_ascii_hexdigit()));
        assert!(!key.contains("alice"));
        assert!(!key.contains('@'));
    }
}
