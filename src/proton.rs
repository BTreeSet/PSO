use anyhow::{Context, Result, bail};

use crate::accounts::ProtonAccount;
use crate::api::{AuthTokens, ProtonApiClient};
use crate::auth::{calculate_srp_proof, resolve_two_factor_code};
use crate::config::RuntimeContext;
use crate::state::{ProtonSessionState, StateStore};

const ACCESS_TOKEN_REFRESH_MARGIN_MS: i64 = 60_000;
pub const PROTON_CLIENT_DEVICE_NAME: &str = "PSO-Rust-Control-Plane";
pub const PROTON_WIREGUARD_ADDRESS_V4: &str = "10.2.0.2/32";
pub const PROTON_WIREGUARD_KEEPALIVE_INTERVAL: u16 = 60;

#[derive(Clone, Debug, Default)]
pub struct CachedAccessToken {
    pub access_token: Option<String>,
    pub expires_at_ms: Option<i64>,
}

impl CachedAccessToken {
    pub fn fresh_token(&self) -> Option<String> {
        let expires_at_ms = self.expires_at_ms?;
        let access_token = self.access_token.as_ref()?;
        (expires_at_ms > current_time_ms() + ACCESS_TOKEN_REFRESH_MARGIN_MS)
            .then(|| access_token.clone())
    }

    pub fn store(&mut self, tokens: &AuthTokens) {
        self.access_token = Some(tokens.access_token.clone());
        self.expires_at_ms = tokens
            .expires_in
            .map(|seconds| current_time_ms() + seconds as i64 * 1000);
    }
}

pub async fn login_with_prompts(
    context: &RuntimeContext,
    username: &str,
    password: String,
    totp_input: Option<String>,
    no_prompt: bool,
    human_verification_token: Option<&str>,
) -> Result<AuthTokens> {
    let api = ProtonApiClient::new(&context.api_base_url)?;
    let info = api.auth_info(username, human_verification_token).await?;
    if info.version != 4 {
        bail!("unsupported Proton SRP auth version {}", info.version);
    }

    let two_factor_input = if info.two_factor.unwrap_or(0) > 0 && totp_input.is_none() && !no_prompt
    {
        Some(rpassword::prompt_password("Proton TOTP: ")?)
    } else if info.two_factor.unwrap_or(0) > 0 && totp_input.is_none() {
        bail!(
            "TOTP is required for this account; pass --totp, configure account.totp, or disable no_prompt"
        )
    } else {
        totp_input
    };
    let totp = two_factor_input
        .as_deref()
        .map(resolve_two_factor_code)
        .transpose()?;

    let proof = calculate_srp_proof(
        username,
        &password,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )?;
    let primary = api
        .authenticate(
            username,
            &proof,
            &info.modulus,
            totp.as_deref(),
            human_verification_token,
        )
        .await?;
    Ok(primary)
}

pub async fn login_configured_account(
    context: &RuntimeContext,
    account: &ProtonAccount,
    password_override: Option<String>,
    totp_override: Option<String>,
    human_verification_token: Option<&str>,
) -> Result<AuthTokens> {
    let password = match password_override {
        Some(password) => password,
        None => match account.password_from_config()? {
            Some(password) => password,
            None if !account.no_prompt => rpassword::prompt_password(format!(
                "Proton password for {}: ",
                account.display_name()
            ))?,
            None => bail!(
                "password is required for Proton account '{}'; set password, password_file, or disable no_prompt for interactive login",
                account.name
            ),
        },
    };

    login_with_prompts(
        context,
        &account.username,
        password,
        totp_override.or_else(|| account.totp.clone()),
        account.no_prompt,
        human_verification_token,
    )
    .await
}

pub async fn refresh_stored_proton_session(
    context: &RuntimeContext,
    state: &ProtonSessionState,
) -> Result<AuthTokens> {
    let api = ProtonApiClient::new(&context.api_base_url)?;
    api.refresh_session(&state.uid, &state.refresh_token).await
}

pub fn persist_proton_session(
    context: &RuntimeContext,
    username: &str,
    state_uid: Option<&str>,
    tokens: &AuthTokens,
) -> Result<()> {
    let uid = tokens
        .uid
        .as_deref()
        .or(state_uid)
        .context("Proton token response did not include UID for session state")?;
    StateStore::open(context)?.store_proton_session(username, uid, &tokens.refresh_token)
}

pub async fn ensure_account_access_token(
    context: &RuntimeContext,
    account: &ProtonAccount,
    cache: &mut CachedAccessToken,
) -> Result<String> {
    if let Some(token) = cache.fresh_token() {
        return Ok(token);
    }

    let store = StateStore::open(context)?;
    match store.load_proton_session(&account.username) {
        Ok(state) => match refresh_stored_proton_session(context, &state).await {
            Ok(tokens) => {
                persist_proton_session(context, &account.username, Some(&state.uid), &tokens)?;
                cache.store(&tokens);
                Ok(tokens.access_token)
            }
            Err(_refresh_error) => {
                if account.no_prompt {
                    account.ensure_can_login_headless()?;
                }
                let tokens = login_configured_account(context, account, None, None, None)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to refresh and then re-login Proton account '{}'",
                            account.name
                        )
                    })?;
                persist_proton_session(context, &account.username, None, &tokens)?;
                cache.store(&tokens);
                Ok(tokens.access_token)
            }
        },
        Err(_) => {
            if account.no_prompt {
                account.ensure_can_login_headless()?;
            }
            let tokens = login_configured_account(context, account, None, None, None).await?;
            persist_proton_session(context, &account.username, None, &tokens)?;
            cache.store(&tokens);
            Ok(tokens.access_token)
        }
    }
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn proton_wireguard_assigned_ips() -> Vec<String> {
    vec![PROTON_WIREGUARD_ADDRESS_V4.to_string()]
}
