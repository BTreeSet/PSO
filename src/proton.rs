use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};

use crate::accounts::ProtonAccount;
use crate::api::{AuthTokens, ProtonAccessToken, ProtonApiClient};
use crate::auth::{calculate_srp_proof, resolve_two_factor_code};
use crate::config::RuntimeContext;
use crate::state::{ProtonSessionState, StateStore};

const ACCESS_TOKEN_REFRESH_MARGIN_MS: i64 = 60_000;
pub const PROTON_WIREGUARD_ADDRESS_V4: &str = "10.2.0.2/32";
pub const PROTON_WIREGUARD_KEEPALIVE_INTERVAL: u16 = 60;

#[derive(Clone, Debug, Default)]
pub struct CachedAccessToken {
    pub access_token: Option<String>,
    pub uid: Option<String>,
    pub expires_at_ms: Option<i64>,
}

impl CachedAccessToken {
    pub fn fresh_token(&self) -> Option<ProtonAccessToken> {
        let expires_at_ms = self.expires_at_ms?;
        let access_token = self.access_token.as_ref()?;
        (expires_at_ms > current_time_ms() + ACCESS_TOKEN_REFRESH_MARGIN_MS)
            .then(|| ProtonAccessToken::new(access_token.clone(), self.uid.clone()))
    }

    pub fn store(&mut self, tokens: &AuthTokens, fallback_uid: Option<&str>) {
        self.access_token = Some(tokens.access_token.clone());
        self.uid = tokens
            .uid
            .clone()
            .or_else(|| fallback_uid.map(ToOwned::to_owned))
            .or_else(|| self.uid.clone());
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
    let api = ProtonApiClient::from_context(context)?;
    let bootstrap = api.create_unauth_session().await?;
    let info = api
        .auth_info(&bootstrap, username, human_verification_token)
        .await?;
    if !matches!(info.version, 3 | 4) {
        bail!("unsupported Proton SRP auth version {}", info.version);
    }

    let proof = calculate_srp_proof(
        info.version,
        username,
        &password,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )?;
    let auth_response = api
        .authenticate(
            &bootstrap,
            username,
            &proof,
            None,
            human_verification_token,
            &info.srp_session,
        )
        .await?;
    verify_server_proof(
        auth_response.server_proof.as_deref(),
        &proof.expected_server_proof,
    )?;

    if auth_response.requires_two_factor() {
        if !auth_response.supports_totp() {
            bail!(
                "Proton account requires a second factor that PSO cannot complete automatically; configure a TOTP-capable account or complete login outside PSO"
            );
        }

        let totp_input = match totp_input {
            Some(value) => value,
            None if !no_prompt => rpassword::prompt_password("Proton TOTP: ")?,
            None => bail!(
                "TOTP is required for this account; pass --totp, configure account.totp, or disable no_prompt"
            ),
        };
        let totp = resolve_two_factor_code(&totp_input)?;
        api.authenticate_two_factor(&auth_response.tokens, &totp)
            .await?;
    }

    Ok(auth_response.tokens)
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
    let api = ProtonApiClient::from_context(context)?;
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
) -> Result<ProtonAccessToken> {
    if let Some(token) = cache.fresh_token() {
        return Ok(token);
    }

    let store = StateStore::open(context)?;
    match store.load_proton_session(&account.username) {
        Ok(state) => match refresh_stored_proton_session(context, &state).await {
            Ok(tokens) => {
                persist_proton_session(context, &account.username, Some(&state.uid), &tokens)?;
                cache.store(&tokens, Some(&state.uid));
                Ok(ProtonAccessToken::from_tokens(&tokens, Some(&state.uid)))
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
                cache.store(&tokens, None);
                Ok(ProtonAccessToken::from_tokens(&tokens, None))
            }
        },
        Err(_) => {
            if account.no_prompt {
                account.ensure_can_login_headless()?;
            }
            let tokens = login_configured_account(context, account, None, None, None).await?;
            persist_proton_session(context, &account.username, None, &tokens)?;
            cache.store(&tokens, None);
            Ok(ProtonAccessToken::from_tokens(&tokens, None))
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

fn verify_server_proof(server_proof: Option<&str>, expected_server_proof: &str) -> Result<()> {
    let server_proof = server_proof.context("Proton auth response did not include ServerProof")?;
    let received = decode_proof(server_proof, "Proton auth response ServerProof")?;
    let expected = decode_proof(expected_server_proof, "generated Proton server proof")?;
    if received != expected {
        bail!("Proton auth response returned an unexpected server proof");
    }
    Ok(())
}

fn decode_proof(value: &str, label: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .with_context(|| format!("invalid {label}"))
}
