use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use reqwest::{
    Client, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;

use crate::auth::SrpProof;
use crate::config::{ProtonClientProfile, RuntimeContext};
use crate::model::{LogicalServer, ProtonLogicalResponse};

const PROTON_LOGICALS_PROTOCOLS: &str = "WireGuardUDP,WireGuardTCP,WireGuardTLS";
const BROWSER_ACCEPT_LANGUAGE: &str = "en-CA,en;q=0.9";
const BROWSER_DNT: &str = "1";
const BROWSER_ORIGIN: &str = "https://account.protonvpn.com";
const BROWSER_PRIORITY: &str = "u=1, i";
const BROWSER_SEC_CH_UA: &str =
    "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"";
const BROWSER_SEC_CH_UA_MOBILE: &str = "?0";
const BROWSER_SEC_CH_UA_PLATFORM: &str = "\"macOS\"";
const BROWSER_SEC_FETCH_DEST: &str = "empty";
const BROWSER_SEC_FETCH_MODE: &str = "cors";
const BROWSER_SEC_FETCH_SITE: &str = "same-origin";
const BROWSER_SEC_GPC: &str = "1";
const BROWSER_LOGIN_REFERER: &str = "https://account.protonvpn.com/login";
const BROWSER_DOWNLOADS_REFERER: &str = "https://account.protonvpn.com/downloads";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtonAccessToken {
    pub access_token: String,
    pub uid: Option<String>,
}

impl ProtonAccessToken {
    pub fn new(access_token: impl Into<String>, uid: Option<String>) -> Self {
        Self {
            access_token: access_token.into(),
            uid,
        }
    }

    pub fn from_tokens(tokens: &AuthTokens, fallback_uid: Option<&str>) -> Self {
        Self::new(
            tokens.access_token.clone(),
            tokens
                .uid
                .clone()
                .or_else(|| fallback_uid.map(ToOwned::to_owned)),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ProtonApiClient {
    base_url: String,
    client: Client,
    client_id: String,
    debug_http: bool,
}

impl ProtonApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_profile(base_url, &ProtonClientProfile::default())
    }

    pub fn from_context(context: &RuntimeContext) -> Result<Self> {
        Self::with_profile(&context.api_base_url, &context.proton_client)
    }

    pub fn from_context_with_debug(context: &RuntimeContext, debug_http: bool) -> Result<Self> {
        Self::with_profile_and_debug(&context.api_base_url, &context.proton_client, debug_http)
    }

    pub fn with_profile(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
    ) -> Result<Self> {
        Self::with_profile_and_debug(base_url, profile, false)
    }

    pub fn with_profile_and_debug(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
        debug_http: bool,
    ) -> Result<Self> {
        let mut default_headers = browser_default_headers();
        default_headers.insert(
            "accept",
            HeaderValue::from_static("application/vnd.protonmail.v1+json"),
        );
        default_headers.insert("x-pm-locale", HeaderValue::from_static("en_US"));
        default_headers.insert(
            "x-pm-appversion",
            HeaderValue::from_str(&profile.app_version_header)
                .context("invalid Proton x-pm-appversion header value")?,
        );
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(30))
            .default_headers(default_headers)
            .user_agent(profile.user_agent.clone())
            .build()?;

        Ok(Self {
            base_url: normalize_api_base_url(base_url.into()),
            client,
            client_id: profile.client_id.clone(),
            debug_http,
        })
    }

    pub async fn get_certificate(
        &self,
        access: &ProtonAccessToken,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse> {
        let url = self.api_url("vpn/v1/certificate");
        send_json_with_retry(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.post(&url), access),
                    BROWSER_DOWNLOADS_REFERER,
                )
                .json(request)
            },
            self.debug_http,
        )
        .await
        .context("Proton certificate request failed")
    }

    pub async fn list_sessions(&self, access: &ProtonAccessToken) -> Result<serde_json::Value> {
        let url = self.api_url("auth/v4/sessions");
        send_json_with_retry(
            || {
                with_browser_referer_headers(
                    self.with_access_token_auth(self.client.get(&url), access),
                    BROWSER_LOGIN_REFERER,
                )
            },
            self.debug_http,
        )
        .await
        .context("Proton sessions listing request failed")
    }

    pub async fn set_session_local_key(
        &self,
        access: &ProtonAccessToken,
        key: impl Into<String>,
    ) -> Result<ApiCodeResponse> {
        let url = self.api_url("auth/v4/sessions/local/key");
        let request = SessionLocalKeyBody { key: key.into() };
        send_json_with_retry(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.put(&url), access),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request)
            },
            self.debug_http,
        )
        .await
        .context("Proton session local key request failed")
    }

    pub async fn set_session_payload(
        &self,
        access: &ProtonAccessToken,
        payload: serde_json::Value,
    ) -> Result<ApiCodeResponse> {
        let url = self.api_url("auth/v4/sessions/payload");
        let request = SessionPayloadBody { payload };
        send_json_with_retry(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.post(&url), access),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request)
            },
            self.debug_http,
        )
        .await
        .context("Proton session payload request failed")
    }

    pub async fn list_persistent_certificates(
        &self,
        access: &ProtonAccessToken,
    ) -> Result<Vec<CertificateResponse>> {
        let url = self.api_url("vpn/v1/certificate/all");
        Ok(send_json_with_retry::<CertificateListResponse, _>(
            || {
                with_browser_referer_headers(
                    self.with_access_token_auth(self.client.get(&url), access),
                    BROWSER_DOWNLOADS_REFERER,
                )
                .query(&[("Mode", "persistent"), ("Offset", "0"), ("Limit", "51")])
            },
            self.debug_http,
        )
        .await
        .context("Proton certificate list request failed")?
        .into_certificates())
    }

    pub async fn get_logicals(
        &self,
        access: &ProtonAccessToken,
        country: Option<&str>,
        netzone: Option<&str>,
    ) -> Result<Vec<LogicalServer>> {
        let url = self.api_url("vpn/v2/logicals");
        Ok(send_json_with_retry::<ProtonLogicalResponse, _>(
            || {
                let mut builder = self
                    .with_access_token_auth(self.client.get(&url), access)
                    .query(&[
                        ("WithEntriesForProtocols", PROTON_LOGICALS_PROTOCOLS),
                        ("WithState", "true"),
                    ]);
                builder = builder.header("x-pm-response-truncation-permitted", "true");
                if let Some(country) = country {
                    builder = builder.header("x-pm-country", country);
                }
                if let Some(netzone) = netzone {
                    builder = builder.header("x-pm-netzone", netzone);
                }
                builder
            },
            self.debug_http,
        )
        .await
        .context("Proton logicals request failed")?
        .into_servers())
    }

    pub async fn create_unauth_session(&self) -> Result<PreAuthSession> {
        let url = self.api_url("auth/v4/sessions");
        send_json_with_retry(
            || {
                with_browser_origin_headers(self.client.post(&url), BROWSER_LOGIN_REFERER)
                    .header("x-enforce-unauthsession", "true")
            },
            self.debug_http,
        )
        .await
        .context("Proton unauthenticated session request failed")
    }

    pub async fn auth_info(
        &self,
        session: &PreAuthSession,
        username: &str,
        human_verification_token: Option<&str>,
    ) -> Result<LoginInfoResponse> {
        let url = self.api_url("core/v4/auth/info");
        let request = LoginInfoBody {
            username: Some(username.to_string()),
            intent: "Auto".into(),
        };
        send_json_with_retry(
            || {
                let mut builder = with_browser_origin_headers(
                    self.with_auth_headers(
                        self.client.post(&url),
                        &session.uid,
                        &session.access_token,
                    ),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request);
                if let Some(token) = human_verification_token {
                    builder = builder.header("X-PM-Human-Verification", token);
                }
                builder
            },
            self.debug_http,
        )
        .await
        .context("Proton auth info request failed")
    }

    pub async fn authenticate(
        &self,
        session: &PreAuthSession,
        username: &str,
        srp: &SrpProof,
        two_factor_code: Option<&str>,
        human_verification_token: Option<&str>,
        srp_session: &str,
    ) -> Result<AuthResponse> {
        let url = self.api_url("core/v4/auth");
        let request = LoginBody {
            username: username.to_string(),
            persistent_cookies: 1,
            client_ephemeral: srp.client_ephemeral.clone(),
            client_proof: srp.client_proof.clone(),
            srp_session: srp_session.to_string(),
            two_factor_code: two_factor_code.map(ToOwned::to_owned),
        };
        send_json_with_retry(
            || {
                let mut builder = with_browser_origin_headers(
                    self.with_auth_headers(
                        self.client.post(&url),
                        &session.uid,
                        &session.access_token,
                    ),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request);
                if let Some(token) = human_verification_token {
                    builder = builder.header("X-PM-Human-Verification", token);
                }
                builder
            },
            self.debug_http,
        )
        .await
        .context("Proton auth request failed")
    }

    pub async fn authenticate_two_factor(
        &self,
        tokens: &AuthTokens,
        two_factor_code: &str,
    ) -> Result<()> {
        let uid = tokens
            .uid
            .as_deref()
            .context("Proton auth response did not include UID for two-factor follow-up")?;
        let url = self.api_url("core/v4/auth/2fa");
        let request = LoginTwoFactorBody {
            two_factor_code: two_factor_code.to_string(),
        };
        let _response: ApiCodeResponse = send_json_with_retry(
            || {
                with_browser_origin_headers(
                    self.with_auth_headers(self.client.post(&url), uid, &tokens.access_token),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request)
            },
            self.debug_http,
        )
        .await
        .context("Proton two-factor auth request failed")?;
        Ok(())
    }

    pub async fn fork_vpn_session(
        &self,
        primary_access: &ProtonAccessToken,
        payload: Option<String>,
    ) -> Result<AuthTokens> {
        let url = self.api_url("auth/v4/sessions/forks");
        let request = SessionForkBody {
            payload: payload.unwrap_or_default(),
            child_client_id: self.client_id.clone(),
            independent: 1,
            user_code: None,
        };

        send_json_with_retry(
            || {
                self.with_access_token_auth(self.client.post(&url), primary_access)
                    .json(&request)
            },
            self.debug_http,
        )
        .await
        .context("Proton session fork request failed")
    }

    pub async fn refresh_session(&self, uid: &str, refresh_token: &str) -> Result<AuthTokens> {
        let url = self.api_url("auth/refresh");
        let request = RefreshSessionBody {
            refresh_token: refresh_token.to_string(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            redirect_uri: "https://protonmail.com".into(),
        };

        send_json_with_retry(
            || {
                self.client
                    .post(&url)
                    .header("x-pm-uid", uid)
                    .json(&request)
            },
            self.debug_http,
        )
        .await
        .context("Proton auth refresh request failed")
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn with_auth_headers(
        &self,
        builder: RequestBuilder,
        uid: &str,
        access_token: &str,
    ) -> RequestBuilder {
        builder.header("x-pm-uid", uid).bearer_auth(access_token)
    }

    fn with_access_token_auth(
        &self,
        builder: RequestBuilder,
        access: &ProtonAccessToken,
    ) -> RequestBuilder {
        let builder = match access.uid.as_deref() {
            Some(uid) => builder.header("x-pm-uid", uid),
            None => builder,
        };
        builder.bearer_auth(&access.access_token)
    }
}

fn normalize_api_base_url(base_url: impl Into<String>) -> String {
    let mut value = base_url.into();
    while value.ends_with('/') {
        value.pop();
    }

    for suffix in ["/core/v4", "/auth/v4", "/vpn/v1", "/vpn/v2", "/auth"] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }

    value
}

fn browser_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "accept-language",
        HeaderValue::from_static(BROWSER_ACCEPT_LANGUAGE),
    );
    headers.insert("dnt", HeaderValue::from_static(BROWSER_DNT));
    headers.insert("priority", HeaderValue::from_static(BROWSER_PRIORITY));
    headers.insert("sec-ch-ua", HeaderValue::from_static(BROWSER_SEC_CH_UA));
    headers.insert(
        "sec-ch-ua-mobile",
        HeaderValue::from_static(BROWSER_SEC_CH_UA_MOBILE),
    );
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_static(BROWSER_SEC_CH_UA_PLATFORM),
    );
    headers.insert(
        "sec-fetch-dest",
        HeaderValue::from_static(BROWSER_SEC_FETCH_DEST),
    );
    headers.insert(
        "sec-fetch-mode",
        HeaderValue::from_static(BROWSER_SEC_FETCH_MODE),
    );
    headers.insert(
        "sec-fetch-site",
        HeaderValue::from_static(BROWSER_SEC_FETCH_SITE),
    );
    headers.insert("sec-gpc", HeaderValue::from_static(BROWSER_SEC_GPC));
    headers
}

fn with_browser_referer_headers(builder: RequestBuilder, referer: &'static str) -> RequestBuilder {
    builder.header("referer", referer)
}

fn with_browser_origin_headers(builder: RequestBuilder, referer: &'static str) -> RequestBuilder {
    builder
        .header("origin", BROWSER_ORIGIN)
        .header("referer", referer)
}

async fn send_json_with_retry<T, F>(mut build: F, debug_http: bool) -> Result<T>
where
    T: DeserializeOwned,
    F: FnMut() -> RequestBuilder,
{
    let mut last_error = None;
    for attempt in 0..3 {
        match build().send().await {
            Ok(response) if has_human_verification(&response) => {
                return decode_response(response, debug_http).await;
            }
            Ok(response) if is_retryable(response.status()) && attempt < 2 => {
                sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
            }
            Ok(response) => return decode_response(response, debug_http).await,
            Err(error) if attempt < 2 => {
                last_error = Some(error);
                sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
            }
            Err(error) => return Err(error).context("failed to send Proton API request"),
        }
    }

    match last_error {
        Some(error) => Err(error).context("failed to send Proton API request"),
        None => bail!("Proton API retry loop ended without a response"),
    }
}

fn is_retryable(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn has_human_verification(response: &Response) -> bool {
    matches!(response.status().as_u16(), 422 | 429)
        && response.headers().contains_key("X-PM-Human-Verification")
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: Response,
    debug_http: bool,
) -> Result<T> {
    let status = response.status();
    let url = response.url().clone();

    if has_human_verification(&response) {
        let challenge = response
            .headers()
            .get("X-PM-Human-Verification")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("challenge")
            .to_string();
        let headers = debug_response_headers(response.headers());
        let body = response.text().await.unwrap_or_default();
        if debug_http {
            bail!(
                "human verification required: challenge={challenge}; url={}; status={}; headers={}; body={body}",
                url,
                status,
                headers,
            );
        }
        bail!(
            "human verification required: solve the Proton challenge and retry with --human-verification-token ({challenge}). Response body: {body}"
        );
    }

    if debug_http && !status.is_success() {
        let headers = debug_response_headers(response.headers());
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Proton API request failed: status={} url={} headers={} body={}",
            status,
            url,
            headers,
            body,
        );
    }

    response
        .error_for_status()
        .context("Proton API request failed")?
        .json::<T>()
        .await
        .context("failed to decode Proton API response")
}

fn debug_response_headers(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for key in [
        "content-type",
        "access",
        "retry-after",
        "x-request-id",
        "x-pm-human-verification",
    ] {
        if let Some(value) = headers.get(key)
            && let Ok(text) = value.to_str()
        {
            parts.push(format!("{key}: {text}"));
        }
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginInfoBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub intent: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PreAuthSession {
    #[serde(alias = "AccessToken")]
    pub access_token: String,
    #[serde(alias = "RefreshToken")]
    pub refresh_token: String,
    #[serde(alias = "UID")]
    pub uid: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LoginInfoResponse {
    #[serde(alias = "Code", default)]
    pub code: Option<u64>,
    #[serde(alias = "Version")]
    pub version: u64,
    #[serde(alias = "Modulus")]
    pub modulus: String,
    #[serde(alias = "ServerEphemeral")]
    pub server_ephemeral: String,
    #[serde(alias = "Salt")]
    pub salt: String,
    #[serde(alias = "SRPSession")]
    pub srp_session: String,
    #[serde(alias = "Username", default)]
    pub username: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginBody {
    pub username: String,
    pub persistent_cookies: u8,
    pub client_ephemeral: String,
    pub client_proof: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginTwoFactorBody {
    pub two_factor_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthTokens {
    #[serde(alias = "AccessToken", alias = "access_token")]
    pub access_token: String,
    #[serde(alias = "RefreshToken", alias = "refresh_token")]
    pub refresh_token: String,
    #[serde(alias = "Uid", alias = "UID", alias = "uid", default)]
    pub uid: Option<String>,
    #[serde(alias = "TokenType", alias = "token_type", default)]
    pub token_type: Option<String>,
    #[serde(alias = "ExpiresIn", alias = "expires_in", default)]
    pub expires_in: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct TwoFactorState {
    #[serde(alias = "Enabled", default)]
    pub enabled: u64,
    #[serde(alias = "TOTP", default)]
    pub totp: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthResponse {
    #[serde(flatten)]
    pub tokens: AuthTokens,
    #[serde(alias = "ServerProof", default)]
    pub server_proof: Option<String>,
    #[serde(alias = "TwoFactor", default)]
    pub two_factor: Option<u64>,
    #[serde(alias = "2FA", default)]
    pub two_factor_state: Option<TwoFactorState>,
}

impl AuthResponse {
    pub fn requires_two_factor(&self) -> bool {
        self.two_factor.unwrap_or(0) > 0
            || self
                .two_factor_state
                .as_ref()
                .map(|state| state.enabled > 0)
                .unwrap_or(false)
    }

    pub fn supports_totp(&self) -> bool {
        self.two_factor_state
            .as_ref()
            .map(|state| state.totp > 0)
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct ApiCodeResponse {
    #[serde(alias = "Code", default)]
    pub code: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SessionForkBody {
    #[serde(rename = "Payload")]
    pub payload: String,
    #[serde(rename = "ChildClientID")]
    pub child_client_id: String,
    #[serde(rename = "Independent")]
    pub independent: u8,
    #[serde(rename = "UserCode", skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshSessionBody {
    pub refresh_token: String,
    pub response_type: String,
    pub grant_type: String,
    #[serde(rename = "RedirectURI")]
    pub redirect_uri: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CertificateRequest {
    #[serde(rename = "ClientPublicKey")]
    pub client_public_key: String,
    #[serde(rename = "DeviceName")]
    pub device_name: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "Features")]
    pub features: CertificateFeatures,
    #[serde(
        rename = "ClientPublicKeyMode",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_public_key_mode: Option<String>,
    #[serde(rename = "Duration", skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    #[serde(rename = "Renew", skip_serializing_if = "Option::is_none")]
    pub renew: Option<bool>,
}

impl CertificateRequest {
    pub fn wireguard_session(
        client_public_key: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            client_public_key: client_public_key.into(),
            device_name: device_name.into(),
            mode: "session".into(),
            features: CertificateFeatures::Empty(Vec::new()),
            client_public_key_mode: Some("EC".into()),
            duration: None,
            renew: None,
        }
    }

    pub fn persistent_wireguard(
        client_public_key: impl Into<String>,
        device_name: impl Into<String>,
        features: PersistentCertificateFeatures,
        renew: bool,
    ) -> Result<Self> {
        let client_public_key = client_public_key.into();
        let client_public_key = if renew {
            pem_encode_x25519_public_key(&client_public_key)?
        } else {
            client_public_key
        };

        Ok(Self {
            client_public_key,
            device_name: device_name.into(),
            mode: "persistent".into(),
            features: CertificateFeatures::Persistent(features),
            client_public_key_mode: None,
            duration: None,
            renew: renew.then_some(true),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CertificateFeatures {
    Empty(Vec<String>),
    Persistent(PersistentCertificateFeatures),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentCertificateFeatures {
    #[serde(rename = "Bouncing")]
    pub bouncing: String,
    #[serde(rename = "PortForwarding")]
    pub port_forwarding: bool,
    #[serde(rename = "SplitTCP")]
    pub split_tcp: bool,
    #[serde(rename = "peerName")]
    pub peer_name: String,
    #[serde(rename = "peerIp")]
    pub peer_ip: String,
    #[serde(rename = "peerPublicKey")]
    pub peer_public_key: String,
    #[serde(rename = "platform")]
    pub platform: String,
}

impl PersistentCertificateFeatures {
    pub fn proton(
        peer_name: impl Into<String>,
        peer_ip: impl Into<String>,
        peer_public_key: impl Into<String>,
    ) -> Self {
        Self {
            bouncing: "0".into(),
            port_forwarding: false,
            split_tcp: true,
            peer_name: peer_name.into(),
            peer_ip: peer_ip.into(),
            peer_public_key: peer_public_key.into(),
            platform: "Android".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SessionLocalKeyBody {
    pub key: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SessionPayloadBody {
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CertificateListResponse {
    Bare(Vec<CertificateResponse>),
    Wrapped {
        #[serde(
            alias = "Certificates",
            alias = "Certificate",
            alias = "Items",
            default
        )]
        certificates: Vec<CertificateResponse>,
    },
}

impl CertificateListResponse {
    pub fn into_certificates(self) -> Vec<CertificateResponse> {
        match self {
            Self::Bare(certificates) => certificates,
            Self::Wrapped { certificates } => certificates,
        }
    }
}

fn pem_encode_x25519_public_key(raw_public_key_base64: &str) -> Result<String> {
    let public_key = general_purpose::STANDARD
        .decode(raw_public_key_base64)
        .context("invalid Proton X25519 public key")?;
    let mut der = Vec::with_capacity(12 + public_key.len());
    der.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ]);
    der.extend_from_slice(&public_key);
    let encoded = general_purpose::STANDARD.encode(der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\r\n{encoded}\r\n-----END PUBLIC KEY-----"
    ))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CertificateResponse {
    #[serde(alias = "Certificate", alias = "certificate")]
    pub certificate: String,
    #[serde(
        default,
        alias = "SerialNumber",
        alias = "serialNumber",
        alias = "serial_number",
        alias = "ProfileID",
        alias = "profileId",
        alias = "profile_id",
        alias = "ID",
        alias = "Id",
        alias = "id"
    )]
    pub profile_id: Option<String>,
    #[serde(
        default,
        alias = "ExpirationTimeMs",
        alias = "expirationTimeMs",
        alias = "expiration_time_ms"
    )]
    expiration_time_ms: Option<u64>,
    #[serde(default, alias = "ExpirationTime", alias = "expiration_time")]
    expiration_time: Option<u64>,
    #[serde(
        default,
        alias = "RefreshTimeMs",
        alias = "refreshTimeMs",
        alias = "refresh_time_ms"
    )]
    refresh_time_ms: Option<u64>,
    #[serde(default, alias = "RefreshTime", alias = "refresh_time")]
    refresh_time: Option<u64>,
    #[serde(
        default,
        alias = "AssignedIP",
        alias = "AssignedIp",
        alias = "assignedIp",
        alias = "assigned_ip"
    )]
    pub assigned_ip: Option<String>,
    #[serde(default, alias = "Endpoint", alias = "endpoint")]
    pub endpoint: Option<String>,
    #[serde(
        default,
        alias = "ClientPublicKey",
        alias = "clientPublicKey",
        alias = "client_public_key"
    )]
    pub client_public_key: Option<String>,
    #[serde(
        default,
        alias = "PeerPublicKey",
        alias = "peerPublicKey",
        alias = "peer_public_key"
    )]
    pub peer_public_key: Option<String>,
}

impl CertificateResponse {
    pub fn expiration_time_ms(&self) -> Result<u64> {
        self.expiration_time_ms
            .or_else(|| {
                self.expiration_time
                    .map(|seconds| seconds.saturating_mul(1000))
            })
            .context(
                "Proton certificate response did not include ExpirationTime or ExpirationTimeMs",
            )
    }

    pub fn refresh_time_ms(&self) -> Result<u64> {
        self.refresh_time_ms
            .or_else(|| {
                self.refresh_time
                    .map(|seconds| seconds.saturating_mul(1000))
            })
            .context("Proton certificate response did not include RefreshTime or RefreshTimeMs")
    }

    pub fn matches_client_public_key(&self, expected_raw_base64: &str) -> bool {
        self.client_public_key
            .as_deref()
            .and_then(extract_raw_x25519_public_key_base64)
            .is_some_and(|profile_key| profile_key == expected_raw_base64)
    }
}

fn extract_raw_x25519_public_key_base64(input: &str) -> Option<String> {
    // SubjectPublicKeyInfo DER prefix for X25519 (OID 1.3.101.112)
    const X25519_DER_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let sanitized = input
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    if sanitized.is_empty() {
        return None;
    }

    let decoded = general_purpose::STANDARD
        .decode(sanitized.as_bytes())
        .ok()?;
    if decoded.len() == 32 {
        return Some(general_purpose::STANDARD.encode(decoded));
    }

    let raw = decoded.strip_prefix(&X25519_DER_PREFIX)?;
    if raw.len() != 32 {
        return None;
    }
    Some(general_purpose::STANDARD.encode(raw))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const DUMMY_X25519_PUBLIC_KEY_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const DUMMY_PEER_PUBLIC_KEY: &str = "dumb-peer-public-key";
    const DUMMY_SESSION_KEY: &str = "dumb-session-key";
    const DUMMY_ENCRYPTED_PAYLOAD: &str = "dumb-encrypted-payload";

    #[test]
    fn browser_default_headers_include_chrome_hints() {
        let headers = browser_default_headers();
        assert_eq!(headers.get("accept-language").unwrap(), "en-CA,en;q=0.9");
        assert_eq!(headers.get("dnt").unwrap(), "1");
        assert_eq!(headers.get("priority").unwrap(), "u=1, i");
        assert_eq!(
            headers.get("sec-ch-ua").unwrap(),
            "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\""
        );
        assert_eq!(headers.get("sec-ch-ua-mobile").unwrap(), "?0");
        assert_eq!(headers.get("sec-ch-ua-platform").unwrap(), "\"macOS\"");
        assert_eq!(headers.get("sec-fetch-dest").unwrap(), "empty");
        assert_eq!(headers.get("sec-fetch-mode").unwrap(), "cors");
        assert_eq!(headers.get("sec-fetch-site").unwrap(), "same-origin");
        assert_eq!(headers.get("sec-gpc").unwrap(), "1");
    }

    #[test]
    fn serializes_certificate_request_like_proton_client() {
        let request = CertificateRequest::wireguard_session("public-key", "PSO-Rust-Control-Plane");
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["ClientPublicKey"], "public-key");
        assert_eq!(value["ClientPublicKeyMode"], "EC");
        assert_eq!(value["DeviceName"], "PSO-Rust-Control-Plane");
        assert_eq!(value["Mode"], "session");
        assert_eq!(value["Features"], json!([]));
        assert!(value.get("Renew").is_none());
    }

    #[test]
    fn serializes_persistent_certificate_request_like_browser_client() {
        let request = CertificateRequest::persistent_wireguard(
            DUMMY_X25519_PUBLIC_KEY_BASE64,
            "f983fc5f-b834-41ae-97c4-ee49e2c46153",
            PersistentCertificateFeatures::proton(
                "DUMMY-FREE#1",
                "198.51.100.10",
                DUMMY_PEER_PUBLIC_KEY,
            ),
            true,
        )
        .unwrap();
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["Mode"], "persistent");
        assert_eq!(value["DeviceName"], "f983fc5f-b834-41ae-97c4-ee49e2c46153");
        assert_eq!(value["Renew"], json!(true));
        assert_eq!(
            value["ClientPublicKey"],
            pem_encode_x25519_public_key(DUMMY_X25519_PUBLIC_KEY_BASE64).unwrap()
        );
        assert_eq!(value["Features"]["Bouncing"], "0");
        assert_eq!(value["Features"]["peerName"], "DUMMY-FREE#1");
        assert_eq!(value["Features"]["peerIp"], "198.51.100.10");
        assert_eq!(value["Features"]["platform"], "Android");
    }

    #[test]
    fn serializes_browser_session_maintenance_bodies_like_proton_client() {
        let local_key = serde_json::to_value(SessionLocalKeyBody {
            key: DUMMY_SESSION_KEY.into(),
        })
        .unwrap();
        assert_eq!(local_key["Key"], DUMMY_SESSION_KEY);

        let payload = serde_json::to_value(SessionPayloadBody {
            payload: json!({
                ".-77VX-aP0iPqoI": DUMMY_ENCRYPTED_PAYLOAD
            }),
        })
        .unwrap();
        assert_eq!(
            payload["Payload"][".-77VX-aP0iPqoI"],
            DUMMY_ENCRYPTED_PAYLOAD
        );
    }

    #[test]
    fn deserializes_certificate_list_response_shapes() {
        let wrapped: CertificateListResponse = serde_json::from_value(json!({
            "Certificates": [{
                "Certificate": "cert-pem",
                "ExpirationTime": 2,
                "RefreshTime": 1,
                "AssignedIP": "10.2.0.2/32"
            }]
        }))
        .unwrap();
        assert_eq!(wrapped.into_certificates().len(), 1);

        let bare: CertificateListResponse = serde_json::from_value(json!([{
            "Certificate": "cert-pem",
            "ExpirationTime": 2,
            "RefreshTime": 1,
            "AssignedIP": "10.2.0.2/32"
        }]))
        .unwrap();
        assert_eq!(bare.into_certificates().len(), 1);
    }

    #[test]
    fn matches_client_public_key_from_pem_profile_shape() {
        // A PEM-wrapped key that matches the raw base64 form from the HAR extension request.
        // The \r\n in Rust string literal → actual CR+LF chars → is_whitespace() strips them.
        let certificate: CertificateResponse = serde_json::from_value(json!({
            "Certificate": "dummy",
            "ExpirationTime": 1,
            "RefreshTime": 1,
            "ClientPublicKey": "-----BEGIN PUBLIC KEY-----\r\nMCowBQYDK2VwAyEAgTaZvmRLXpjg8ajCWICHrp6AbeC/o/pDco1LN5tiDkk=\r\n-----END PUBLIC KEY-----"
        }))
        .unwrap();

        assert!(
            certificate.client_public_key.is_some(),
            "client_public_key should be deserialized"
        );
        assert!(
            certificate.matches_client_public_key("gTaZvmRLXpjg8ajCWICHrp6AbeC/o/pDco1LN5tiDkk="),
            "client_public_key was: {:?}",
            certificate.client_public_key
        );
    }

    #[test]
    fn accepts_common_certificate_response_shapes() {
        let response: CertificateResponse = serde_json::from_value(json!({
            "Certificate": "cert-pem",
            "ExpirationTime": 2,
            "RefreshTime": 1,
            "AssignedIP": "10.2.0.2/32"
        }))
        .unwrap();

        assert_eq!(response.certificate, "cert-pem");
        assert_eq!(response.expiration_time_ms().unwrap(), 2000);
        assert_eq!(response.refresh_time_ms().unwrap(), 1000);
        assert_eq!(response.assigned_ip.as_deref(), Some("10.2.0.2/32"));
    }

    #[test]
    fn serializes_login_and_session_fork_like_proton_client() {
        let login_info = serde_json::to_value(LoginInfoBody {
            username: Some("alice@example.com".into()),
            intent: "Auto".into(),
        })
        .unwrap();
        assert_eq!(login_info["Username"], "alice@example.com");
        assert_eq!(login_info["Intent"], "Auto");

        let login = serde_json::to_value(LoginBody {
            username: "alice@example.com".into(),
            persistent_cookies: 1,
            client_ephemeral: "client-ephemeral".into(),
            client_proof: "client-proof".into(),
            srp_session: "srp-session".into(),
            two_factor_code: Some("123456".into()),
        })
        .unwrap();
        assert_eq!(login["PersistentCookies"], 1);
        assert_eq!(login["SRPSession"], "srp-session");
        assert_eq!(login["TwoFactorCode"], "123456");

        let refresh = serde_json::to_value(RefreshSessionBody {
            refresh_token: "refresh-token".into(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            redirect_uri: "https://protonmail.com".into(),
        })
        .unwrap();
        assert_eq!(refresh["RefreshToken"], "refresh-token");
        assert!(refresh.get("UID").is_none());

        let fork = serde_json::to_value(SessionForkBody {
            payload: "payload".into(),
            child_client_id: "web-vpn-settings".into(),
            independent: 1,
            user_code: Some("code".into()),
        })
        .unwrap();
        assert_eq!(fork["ChildClientID"], "web-vpn-settings");
        assert_eq!(fork["Payload"], "payload");
        assert_eq!(fork["Independent"], 1);
        assert_eq!(fork["UserCode"], "code");
    }

    #[test]
    fn normalizes_legacy_core_base_url_to_api_root() {
        let client = ProtonApiClient::new("https://account.protonvpn.com/api/core/v4").unwrap();
        assert_eq!(client.base_url, "https://account.protonvpn.com/api");
        assert_eq!(
            client.api_url("core/v4/auth/info"),
            "https://account.protonvpn.com/api/core/v4/auth/info"
        );
    }

    #[test]
    fn deserializes_modern_auth_info_shape() {
        let response: LoginInfoResponse = serde_json::from_value(json!({
            "Code": 1000,
            "Version": 4,
            "Modulus": "signed-modulus",
            "ServerEphemeral": "server-ephemeral",
            "Salt": "salt",
            "SRPSession": "srp-session"
        }))
        .unwrap();

        assert_eq!(response.version, 4);
        assert_eq!(response.srp_session, "srp-session");
    }

    #[test]
    fn detects_two_factor_requirements_from_auth_response() {
        let response: AuthResponse = serde_json::from_value(json!({
            "UID": "uid-123",
            "AccessToken": "access-token",
            "RefreshToken": "refresh-token",
            "TwoFactor": 1,
            "2FA": {
                "Enabled": 1,
                "TOTP": 1
            }
        }))
        .unwrap();

        assert!(response.requires_two_factor());
        assert!(response.supports_totp());
    }
}
