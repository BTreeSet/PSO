use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use tracing::warn;

use crate::accounts::ProtonAccount;
use crate::api::{AuthTokens, HumanVerificationChallenge, ProtonAccessToken, ProtonApiClient};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionLoginReason {
    MissingStoredSession,
    RefreshFailure,
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
    mut human_verification_token: Option<String>,
    debug_http: bool,
) -> Result<AuthTokens> {
    let api = if debug_http {
        ProtonApiClient::from_context_with_debug(context, true)?
    } else {
        ProtonApiClient::from_context(context)?
    };
    let bootstrap = api.create_unauth_session().await?;
    let info = loop {
        match api
            .auth_info(&bootstrap, username, human_verification_token.as_deref())
            .await
        {
            Ok(info) => break info,
            Err(error) => {
                let challenge = match error.downcast_ref::<HumanVerificationChallenge>() {
                    Some(challenge) => challenge.clone(),
                    None => return Err(error),
                };
                human_verification_token =
                    Some(prompt_human_verification_token(&challenge, no_prompt)?);
            }
        }
    };
    if !matches!(info.version, 3 | 4) {
        bail!("unsupported Proton SRP auth version {}", info.version);
    }

    if debug_http {
        eprintln!(
            "[pso-debug] auth/info: version={} modulus_chars={} salt_chars={} server_ephemeral_chars={} srp_session_chars={}",
            info.version,
            info.modulus.len(),
            info.salt.len(),
            info.server_ephemeral.len(),
            info.srp_session.len(),
        );
    }

    let proof = calculate_srp_proof(
        info.version,
        username,
        &password,
        &info.salt,
        &info.modulus,
        &info.server_ephemeral,
    )?;
    let auth_response = loop {
        match api
            .authenticate(
                &bootstrap,
                username,
                &proof,
                None,
                human_verification_token.as_deref(),
                &info.srp_session,
            )
            .await
        {
            Ok(response) => break response,
            Err(error) => {
                let challenge = match error.downcast_ref::<HumanVerificationChallenge>() {
                    Some(challenge) => challenge.clone(),
                    None => return Err(error),
                };
                human_verification_token =
                    Some(prompt_human_verification_token(&challenge, no_prompt)?);
            }
        }
    };
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
    human_verification_token: Option<String>,
    debug_http: bool,
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
        debug_http,
    )
    .await
}

fn prompt_human_verification_token(
    challenge: &HumanVerificationChallenge,
    no_prompt: bool,
) -> Result<String> {
    if no_prompt || !io::stdin().is_terminal() {
        bail!(human_verification_headless_error(challenge));
    }

    let mut stderr = io::stderr().lock();
    writeln!(stderr)?;
    if let Some(title) = challenge.title.as_deref() {
        writeln!(stderr, "{title}")?;
    }
    if let Some(description) = challenge.description.as_deref()
        && !description.trim().is_empty()
    {
        writeln!(stderr, "{description}")?;
    }
    writeln!(stderr, "Proton CAPTCHA is required to continue.")?;
    writeln!(
        stderr,
        "Open this URL in a browser and complete the challenge:"
    )?;
    writeln!(stderr, "  {}", challenge.web_url())?;
    if let Some(expires_at) = challenge.expires_at {
        writeln!(stderr, "Challenge expires at UNIX time {expires_at}.")?;
    }
    write!(
        stderr,
        "Paste the resolved verification token from Proton, then press Enter: "
    )?;
    stderr.flush()?;

    let mut token = String::new();
    io::stdin().read_line(&mut token)?;
    let token = token.trim();
    if token.is_empty() {
        bail!("verification token is required after completing the CAPTCHA");
    }

    Ok(token.to_string())
}

fn human_verification_headless_error(challenge: &HumanVerificationChallenge) -> String {
    format!(
        "Proton CAPTCHA is required. Open {} in a browser and complete it, then rerun with --human-verification-token <resolved token>. For a first-time bootstrap, run `pso auth login` once in an interactive terminal so PSO can initialize the stored session database before headless runs.",
        challenge.web_url()
    )
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
    let store = StateStore::open(context)?;
    store_tokens_in_state(&store, username, state_uid, tokens)
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
    match store.load_proton_session_optional(&account.username)? {
        Some(state) => match refresh_stored_proton_session(context, &state).await {
            Ok(tokens) => {
                store_tokens_in_state(&store, &account.username, Some(&state.uid), &tokens)?;
                cache.store(&tokens, Some(&state.uid));
                Ok(ProtonAccessToken::from_tokens(&tokens, Some(&state.uid)))
            }
            Err(refresh_error) => {
                let refresh_error_message = refresh_error.to_string();
                record_session_event(
                    &store,
                    &account.username,
                    "proton_session_refresh_failed",
                    json!({
                        "account": account.name,
                        "error": refresh_error_message,
                    }),
                );
                login_and_store_account_access_token(
                    context,
                    account,
                    cache,
                    Some(&state.uid),
                    SessionLoginReason::RefreshFailure,
                    Some(refresh_error_message.as_str()),
                )
                .await
            }
        },
        None => {
            login_and_store_account_access_token(
                context,
                account,
                cache,
                None,
                SessionLoginReason::MissingStoredSession,
                None,
            )
            .await
        }
    }
}

fn resolve_session_uid<'a>(
    tokens: &'a AuthTokens,
    fallback_uid: Option<&'a str>,
) -> Result<&'a str> {
    tokens
        .uid
        .as_deref()
        .or(fallback_uid)
        .context("Proton token response did not include UID for session state")
}

fn store_tokens_in_state(
    store: &StateStore,
    username: &str,
    state_uid: Option<&str>,
    tokens: &AuthTokens,
) -> Result<()> {
    let uid = resolve_session_uid(tokens, state_uid)?;
    store.store_proton_session(username, uid, &tokens.refresh_token)
}

async fn login_and_store_account_access_token(
    context: &RuntimeContext,
    account: &ProtonAccount,
    cache: &mut CachedAccessToken,
    fallback_uid: Option<&str>,
    reason: SessionLoginReason,
    refresh_error: Option<&str>,
) -> Result<ProtonAccessToken> {
    if account.no_prompt {
        account
            .ensure_can_login_headless()
            .with_context(|| headless_relogin_error(account, reason, refresh_error))?;
    }

    let tokens = login_configured_account(context, account, None, None, None, false)
        .await
        .with_context(|| login_error_context(account, reason, refresh_error))?;
    let store = StateStore::open(context)?;
    store_tokens_in_state(&store, &account.username, fallback_uid, &tokens)?;
    cache.store(&tokens, fallback_uid);

    record_session_event(
        &store,
        &account.username,
        reason.event_type(),
        json!({
            "account": account.name,
            "reason": reason.reason_label(),
        }),
    );

    Ok(ProtonAccessToken::from_tokens(&tokens, fallback_uid))
}

fn headless_relogin_error(
    account: &ProtonAccount,
    reason: SessionLoginReason,
    refresh_error: Option<&str>,
) -> String {
    match reason {
        SessionLoginReason::MissingStoredSession => format!(
            "Proton account '{}' has no stored session and cannot log in headlessly without password or password_file",
            account.name
        ),
        SessionLoginReason::RefreshFailure => format!(
            "stored Proton session refresh failed for account '{}' and headless re-login is unavailable: {}",
            account.name,
            refresh_error.unwrap_or("refresh failed")
        ),
    }
}

fn login_error_context(
    account: &ProtonAccount,
    reason: SessionLoginReason,
    refresh_error: Option<&str>,
) -> String {
    match reason {
        SessionLoginReason::MissingStoredSession => format!(
            "failed to log in Proton account '{}' because no stored session exists",
            account.name
        ),
        SessionLoginReason::RefreshFailure => format!(
            "stored Proton session refresh failed for account '{}' ({}); re-login also failed",
            account.name,
            refresh_error.unwrap_or("refresh failed")
        ),
    }
}

fn record_session_event(
    store: &StateStore,
    username: &str,
    event_type: &str,
    details: serde_json::Value,
) {
    let details_json = match serde_json::to_string(&details) {
        Ok(details_json) => details_json,
        Err(error) => {
            warn!(%error, username = %username, event_type = %event_type, "failed to encode Proton session event details");
            return;
        }
    };

    if let Err(error) = store.record_event(Some(username), None, event_type, Some(&details_json)) {
        warn!(%error, username = %username, event_type = %event_type, "failed to record Proton session event");
    }
}

impl SessionLoginReason {
    fn event_type(self) -> &'static str {
        match self {
            Self::MissingStoredSession => "proton_session_login_succeeded",
            Self::RefreshFailure => "proton_session_relogin_succeeded",
        }
    }

    fn reason_label(self) -> &'static str {
        match self {
            Self::MissingStoredSession => "missing_stored_session",
            Self::RefreshFailure => "refresh_failure",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_access_token_uses_fallback_uid() {
        let mut cache = CachedAccessToken::default();
        let tokens = AuthTokens {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            uid: None,
            token_type: None,
            expires_in: Some(120),
        };

        cache.store(&tokens, Some("uid-from-state"));

        let token = cache.fresh_token().expect("cached token should be fresh");
        assert_eq!(token.access_token, "access");
        assert_eq!(token.uid.as_deref(), Some("uid-from-state"));
    }

    #[test]
    fn cached_access_token_requires_valid_expiry() {
        let mut cache = CachedAccessToken::default();
        let tokens = AuthTokens {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            uid: Some("uid-from-token".into()),
            token_type: None,
            expires_in: Some(0),
        };

        cache.store(&tokens, None);

        assert!(cache.fresh_token().is_none());
    }
}
