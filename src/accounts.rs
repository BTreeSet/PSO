use std::collections::BTreeMap;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};

use crate::config::AuthConfig;
use crate::session::UserSession;

#[derive(Clone, Debug, Default)]
pub struct ProtonAccountRegistry {
    accounts: BTreeMap<String, ProtonAccount>,
    usernames: BTreeMap<String, String>,
}

impl ProtonAccountRegistry {
    pub fn from_auth(auth: &AuthConfig) -> Result<Self> {
        auth.validate()?;

        let mut accounts = BTreeMap::new();
        let mut usernames = BTreeMap::new();
        for entry in &auth.proton.accounts {
            let account = ProtonAccount {
                name: entry.name.trim().to_string(),
                username: entry.username.trim().to_string(),
                tier: entry.tier.trim().to_string(),
                password: entry.password.clone(),
                password_file: entry.password_file.clone(),
                totp: entry.totp.clone(),
                no_prompt: entry.no_prompt.unwrap_or(false),
            };
            usernames.insert(account.username.clone(), account.name.clone());
            accounts.insert(account.name.clone(), account);
        }

        Ok(Self {
            accounts,
            usernames,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn first_account_name(&self) -> Option<&str> {
        self.accounts.keys().next().map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProtonAccount> {
        self.accounts.values()
    }

    pub fn get(&self, name: &str) -> Option<&ProtonAccount> {
        self.accounts.get(name)
    }

    pub fn get_required(&self, name: &str) -> Result<&ProtonAccount> {
        self.get(name)
            .with_context(|| format!("unknown Proton account '{name}'"))
    }

    pub fn get_by_username(&self, username: &str) -> Option<&ProtonAccount> {
        self.usernames
            .get(username)
            .and_then(|name| self.accounts.get(name))
    }

    pub fn resolve_selector(
        &self,
        account_name: Option<&str>,
        username: Option<&str>,
    ) -> Result<&ProtonAccount> {
        if let Some(account_name) = account_name {
            return self.get_required(account_name);
        }
        if let Some(username) = username {
            return self
                .get_by_username(username)
                .with_context(|| format!("no configured Proton account uses username {username}"));
        }
        if self.accounts.len() == 1 {
            return self
                .accounts
                .values()
                .next()
                .context("missing configured Proton account");
        }
        bail!("a Proton account is required; pass --account or --username");
    }

    pub fn resolve_template_reference(&self, reference: &str) -> Result<&ProtonAccount> {
        self.get(reference)
            .or_else(|| self.get_by_username(reference))
            .with_context(|| format!("template references unknown Proton account '{reference}'"))
    }

    pub fn sessions(&self) -> BTreeMap<String, UserSession> {
        self.accounts
            .iter()
            .map(|(name, account)| {
                (
                    name.clone(),
                    UserSession::new(account.username.clone(), account.tier.clone()),
                )
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtonAccount {
    pub name: String,
    pub username: String,
    pub tier: String,
    pub password: Option<String>,
    pub password_file: Option<std::path::PathBuf>,
    pub totp: Option<String>,
    pub no_prompt: bool,
}

impl ProtonAccount {
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

    pub fn display_name(&self) -> String {
        if self.name == self.username {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.username)
        }
    }

    pub fn ensure_can_login_headless(&self) -> Result<()> {
        if self.password.is_some() || self.password_file.is_some() {
            return Ok(());
        }
        bail!(
            "Proton account '{}' does not have password or password_file configured for headless login",
            self.name
        )
    }
}

pub fn require_single_account_access_token(
    registry: &ProtonAccountRegistry,
    account_name: Option<&str>,
) -> Result<()> {
    if registry.len() <= 1 || account_name.is_some() {
        return Ok(());
    }
    Err(anyhow!(
        "a shared access token override only works when exactly one Proton account is in use; configure per-account credentials or stored sessions instead"
    ))
}
