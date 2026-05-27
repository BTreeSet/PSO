use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::RuntimeContext;

pub fn topology_state_file(context: &RuntimeContext) -> PathBuf {
    context.state_dir.join("logicals.json")
}

pub fn state_db_file(context: &RuntimeContext) -> PathBuf {
    context.state_dir.join("pso.sqlite3")
}

pub fn username_state_key(username: &str) -> String {
    hex::encode(Sha256::digest(username.as_bytes()))
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
        let key = username_state_key("alice@example.com");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|character| character.is_ascii_hexdigit()));
        assert!(!key.contains("alice"));
        assert!(!key.contains('@'));
    }
}
