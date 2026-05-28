use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use crate::config::AuthConfig;
use crate::session::UserSession;

#[derive(Clone, Debug, Default)]
pub struct ProtonUserRegistry {
    users: BTreeMap<String, ProtonUser>,
}

impl ProtonUserRegistry {
    pub fn from_auth(auth: &AuthConfig) -> Result<Self> {
        auth.validate()?;

        let mut users = BTreeMap::new();
        for entry in &auth.proton.users {
            let user = ProtonUser {
                username: entry.username.trim().to_string(),
                tier: entry.tier.trim().to_string(),
                password: entry.password.clone(),
                password_file: entry.password_file.clone(),
                totp: entry.totp.clone(),
                no_prompt: entry.no_prompt.unwrap_or(false),
            };
            users.insert(user.username.clone(), user);
        }

        Ok(Self { users })
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn first_username(&self) -> Option<&str> {
        self.users.keys().next().map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProtonUser> {
        self.users.values()
    }

    pub fn get_by_username(&self, username: &str) -> Option<&ProtonUser> {
        self.users.get(username)
    }

    pub fn get_required(&self, username: &str) -> Result<&ProtonUser> {
        self.get_by_username(username)
            .with_context(|| format!("unknown Proton username '{username}'"))
    }

    pub fn resolve_username(&self, username: Option<&str>) -> Result<&ProtonUser> {
        if let Some(username) = username {
            return self.get_required(username);
        }
        if self.users.len() == 1 {
            return self
                .users
                .values()
                .next()
                .context("missing configured Proton username");
        }
        bail!("a Proton username is required; pass --username")
    }

    pub fn sessions(&self) -> BTreeMap<String, UserSession> {
        self.users
            .iter()
            .map(|(username, user)| {
                (
                    username.clone(),
                    UserSession::new(user.username.clone(), user.tier.clone()),
                )
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtonUser {
    pub username: String,
    pub tier: String,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
    pub totp: Option<String>,
    pub no_prompt: bool,
}

impl ProtonUser {
    pub fn password_from_config(&self) -> Result<Option<String>> {
        if let Some(password) = &self.password {
            return Ok(Some(password.clone()));
        }

        match &self.password_file {
            Some(path) => Ok(Some(
                fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            )),
            None => Ok(None),
        }
    }

    pub fn ensure_can_login_headless(&self) -> Result<()> {
        if self.password.is_some() || self.password_file.is_some() {
            return Ok(());
        }
        bail!(
            "Proton user '{}' does not have password or password_file configured for headless login",
            self.username
        )
    }
}

pub fn require_single_user_access_token(
    registry: &ProtonUserRegistry,
    username: Option<&str>,
) -> Result<()> {
    if registry.len() <= 1 || username.is_some() {
        return Ok(());
    }
    Err(anyhow!(
        "a shared access token override only works when exactly one Proton username is in use; configure per-username credentials or stored sessions instead"
    ))
}
