use anyhow::{Context, Result};
use reqwest::{Client, header::HeaderValue};
use std::path::PathBuf;

use crate::auth::SrpProof;
use crate::config::{ProtonClientProfile, RuntimeContext};
use crate::model::{LogicalServer, ProtonLogicalResponse};
use crate::state::StateStore;

mod auth;
mod certificate;
mod http;
mod human_verification;
mod session;

use http::{
    BROWSER_DOWNLOADS_REFERER, BROWSER_LOGIN_REFERER, PROTON_LOGICALS_PROTOCOLS,
    browser_default_headers, human_verification_request_headers, normalize_api_base_url,
    send_json_with_retry_with_observer, with_browser_origin_headers, with_browser_referer_headers,
};

pub use auth::{
    ApiCodeResponse, AuthResponse, AuthTokens, LoginBody, LoginInfoBody, LoginInfoResponse,
    LoginIntent, LoginTwoFactorBody, PreAuthSession, TwoFactorState,
};
pub use certificate::{
    CertificateFeatures, CertificateListResponse, CertificateRequest, CertificateResponse,
    PersistentCertificateFeatures, SessionLocalKeyBody, SessionPayloadBody,
};
pub use human_verification::HumanVerificationChallenge;
pub use session::{AuthCookiesBody, RefreshSessionBody, SessionForkBody};

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
    state_dir: Option<PathBuf>,
}

impl ProtonApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_profile(base_url, &ProtonClientProfile::default())
    }

    pub fn from_context(context: &RuntimeContext) -> Result<Self> {
        Self::with_profile_and_state_dir(
            &context.api_base_url,
            &context.proton_client,
            Some((false, Some(context.state_dir.clone()))),
        )
    }

    pub fn from_context_with_debug(context: &RuntimeContext, debug_http: bool) -> Result<Self> {
        Self::with_profile_and_state_dir(
            &context.api_base_url,
            &context.proton_client,
            Some((debug_http, Some(context.state_dir.clone()))),
        )
    }

    pub fn with_profile(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
    ) -> Result<Self> {
        Self::with_profile_and_state_dir(base_url, profile, None)
    }

    pub fn with_profile_and_debug(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
        debug_http: bool,
    ) -> Result<Self> {
        Self::with_profile_and_state_dir(base_url, profile, Some((debug_http, None)))
    }

    fn with_profile_and_state_dir(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
        settings: Option<(bool, Option<PathBuf>)>,
    ) -> Result<Self> {
        let (debug_http, state_dir) = settings.unwrap_or((false, None));
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
            .connect_timeout(std::time::Duration::from_secs(5))
            .read_timeout(std::time::Duration::from_secs(20))
            .timeout(std::time::Duration::from_secs(30))
            .default_headers(default_headers)
            .user_agent(profile.user_agent.clone())
            .build()?;

        Ok(Self {
            base_url: normalize_api_base_url(base_url.into()),
            client,
            client_id: profile.client_id.clone(),
            debug_http,
            state_dir,
        })
    }

    fn open_state_store(&self) -> Result<Option<StateStore>> {
        let Some(state_dir) = self.state_dir.as_ref() else {
            return Ok(None);
        };

        Ok(Some(StateStore::open_in(state_dir)?))
    }

    fn username_for_uid(&self, uid: Option<&str>) -> Option<String> {
        let uid = uid?;
        let store = match self.open_state_store() {
            Ok(Some(store)) => store,
            Ok(None) => return None,
            Err(error) => {
                if self.debug_http {
                    eprintln!(
                        "[pso-debug] could not resolve Proton username for uid {uid}: {error:#}"
                    );
                }
                return None;
            }
        };
        match store.load_username_by_uid(uid) {
            Ok(username) => username,
            Err(error) => {
                if self.debug_http {
                    eprintln!(
                        "[pso-debug] could not resolve Proton username for uid {uid}: {error:#}"
                    );
                }
                None
            }
        }
    }

    fn with_username_cookie_header(
        &self,
        builder: reqwest::RequestBuilder,
        username: Option<&str>,
        request_url: &reqwest::Url,
    ) -> reqwest::RequestBuilder {
        let Some(username) = username else {
            return builder;
        };

        let Some(store) = self.open_state_store().ok().flatten() else {
            return builder;
        };

        match store.load_proton_cookie_header(
            username,
            request_url.host_str().unwrap_or_default(),
            request_url.path(),
            request_url.scheme() == "https",
        ) {
            Ok(Some(cookie_header)) => builder.header(reqwest::header::COOKIE, cookie_header),
            Ok(None) => builder,
            Err(error) => {
                if self.debug_http {
                    eprintln!(
                        "[pso-debug] could not load Proton cookies for {username}: {error:#}"
                    );
                }
                builder
            }
        }
    }

    fn response_set_cookie_values(response: &reqwest::Response) -> Vec<String> {
        response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok().map(ToOwned::to_owned))
            .collect()
    }

    fn store_response_cookies_for_username(
        &self,
        username: &str,
        response: &reqwest::Response,
    ) -> Result<()> {
        let Some(store) = self.open_state_store()? else {
            return Ok(());
        };

        let Some(request_host) = response.url().host_str() else {
            return Ok(());
        };
        let set_cookie_values = Self::response_set_cookie_values(response);
        if set_cookie_values.is_empty() {
            return Ok(());
        }

        store.record_proton_set_cookies(
            username,
            request_host,
            response.url().path(),
            &set_cookie_values,
        )
    }

    fn store_response_cookies_for_uid(
        &self,
        uid: Option<&str>,
        response: &reqwest::Response,
    ) -> Result<()> {
        let Some(username) = self.username_for_uid(uid) else {
            return Ok(());
        };

        self.store_response_cookies_for_username(&username, response)
    }

    pub async fn get_certificate(
        &self,
        access: &ProtonAccessToken,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse> {
        let url = self.api_url("vpn/v1/certificate");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        send_json_with_retry_with_observer(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.post(&url), access, &request_url),
                    BROWSER_DOWNLOADS_REFERER,
                )
                .json(request)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(access_uid, response),
        )
        .await
        .context("Proton certificate request failed")
    }

    pub async fn list_sessions(&self, access: &ProtonAccessToken) -> Result<serde_json::Value> {
        let url = self.api_url("auth/v4/sessions");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        send_json_with_retry_with_observer(
            || {
                with_browser_referer_headers(
                    self.with_access_token_auth(self.client.get(&url), access, &request_url),
                    BROWSER_LOGIN_REFERER,
                )
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(access_uid, response),
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
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        let request = SessionLocalKeyBody { key: key.into() };
        send_json_with_retry_with_observer(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.put(&url), access, &request_url),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(access_uid, response),
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
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        let request = SessionPayloadBody {
            payload,
            persistent_cookies: 1,
        };
        send_json_with_retry_with_observer(
            || {
                with_browser_origin_headers(
                    self.with_access_token_auth(self.client.post(&url), access, &request_url),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(access_uid, response),
        )
        .await
        .context("Proton session payload request failed")
    }

    pub async fn list_persistent_certificates(
        &self,
        access: &ProtonAccessToken,
    ) -> Result<Vec<CertificateResponse>> {
        let url = self.api_url("vpn/v1/certificate/all");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        Ok(
            send_json_with_retry_with_observer::<CertificateListResponse, _, _>(
                || {
                    with_browser_referer_headers(
                        self.with_access_token_auth(self.client.get(&url), access, &request_url),
                        BROWSER_DOWNLOADS_REFERER,
                    )
                    .query(&[
                        ("Mode", "persistent"),
                        ("Offset", "0"),
                        ("Limit", "51"),
                    ])
                },
                self.debug_http,
                |response| self.store_response_cookies_for_uid(access_uid, response),
            )
            .await
            .context("Proton certificate list request failed")?
            .into_certificates(),
        )
    }

    pub async fn get_logicals(
        &self,
        access: &ProtonAccessToken,
        country: Option<&str>,
        netzone: Option<&str>,
    ) -> Result<Vec<LogicalServer>> {
        let url = self.api_url("vpn/v2/logicals");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = access.uid.as_deref();
        Ok(
            send_json_with_retry_with_observer::<ProtonLogicalResponse, _, _>(
                || {
                    let mut builder = self
                        .with_access_token_auth(self.client.get(&url), access, &request_url)
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
                |response| self.store_response_cookies_for_uid(access_uid, response),
            )
            .await
            .context("Proton logicals request failed")?
            .into_servers(),
        )
    }

    pub async fn create_unauth_session(&self, username: &str) -> Result<PreAuthSession> {
        let url = self.api_url("auth/v4/sessions");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        send_json_with_retry_with_observer(
            || {
                let builder =
                    with_browser_origin_headers(self.client.post(&url), BROWSER_LOGIN_REFERER)
                        .header("x-enforce-unauthsession", "true");
                self.with_username_cookie_header(builder, Some(username), &request_url)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_username(username, response),
        )
        .await
        .context("Proton unauthenticated session request failed")
    }

    pub async fn auth_info(
        &self,
        session: &PreAuthSession,
        username: &str,
        intent: LoginIntent,
        human_verification_token: Option<&str>,
    ) -> Result<LoginInfoResponse> {
        let url = self.api_url("core/v4/auth/info");
        let request = LoginInfoBody {
            username: Some(username.to_string()),
            intent,
        };
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        send_json_with_retry_with_observer(
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
                    builder = builder.headers(human_verification_request_headers(token));
                }
                builder = self.with_username_cookie_header(builder, Some(username), &request_url);
                builder
            },
            self.debug_http,
            |response| self.store_response_cookies_for_username(username, response),
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
            payload: None,
            two_factor_code: two_factor_code.map(ToOwned::to_owned),
        };
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        send_json_with_retry_with_observer(
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
                    builder = builder.headers(human_verification_request_headers(token));
                }
                builder = self.with_username_cookie_header(builder, Some(username), &request_url);
                builder
            },
            self.debug_http,
            |response| self.store_response_cookies_for_username(username, response),
        )
        .await
        .context("Proton auth request failed")
    }

    pub async fn authenticate_two_factor(
        &self,
        username: &str,
        tokens: &AuthTokens,
        two_factor_code: &str,
    ) -> Result<()> {
        let uid = tokens
            .uid
            .as_deref()
            .context("Proton auth response did not include UID for two-factor follow-up")?;
        let url = self.api_url("core/v4/auth/2fa");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let request = LoginTwoFactorBody {
            two_factor_code: two_factor_code.to_string(),
        };
        let _response: ApiCodeResponse = send_json_with_retry_with_observer(
            || {
                let builder = with_browser_origin_headers(
                    self.with_auth_headers(self.client.post(&url), uid, &tokens.access_token),
                    BROWSER_LOGIN_REFERER,
                )
                .json(&request);
                self.with_username_cookie_header(builder, Some(username), &request_url)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_username(username, response),
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
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let access_uid = primary_access.uid.as_deref();

        send_json_with_retry_with_observer(
            || {
                self.with_access_token_auth(self.client.post(&url), primary_access, &request_url)
                    .json(&request)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(access_uid, response),
        )
        .await
        .context("Proton session fork request failed")
    }

    pub async fn refresh_session(
        &self,
        username: &str,
        uid: &str,
        refresh_token: &str,
    ) -> Result<AuthTokens> {
        let url = self.api_url("auth/v4/refresh");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let request = RefreshSessionBody {
            uid: uid.to_string(),
            refresh_token: refresh_token.to_string(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            redirect_uri: "https://protonmail.com".into(),
            state: session::generate_refresh_state_token(),
            access_token: None,
        };

        send_json_with_retry_with_observer(
            || {
                let builder = self
                    .client
                    .post(&url)
                    .header("x-pm-uid", uid)
                    .json(&request);
                self.with_username_cookie_header(builder, Some(username), &request_url)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_username(username, response),
        )
        .await
        .context("Proton auth refresh request failed")
    }

    pub async fn auth_cookies(
        &self,
        uid: &str,
        access_token: &str,
        request: &AuthCookiesBody,
    ) -> Result<ApiCodeResponse> {
        let url = self.api_url("core/v4/auth/cookies");
        let request_url = reqwest::Url::parse(&url).context("invalid Proton API url")?;
        let cookie_username = self.username_for_uid(Some(uid));
        send_json_with_retry_with_observer(
            || {
                let builder = with_browser_origin_headers(
                    self.with_auth_headers(self.client.post(&url), uid, access_token),
                    BROWSER_LOGIN_REFERER,
                )
                .json(request);
                self.with_username_cookie_header(builder, cookie_username.as_deref(), &request_url)
            },
            self.debug_http,
            |response| self.store_response_cookies_for_uid(Some(uid), response),
        )
        .await
        .context("Proton auth cookies request failed")
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn with_auth_headers(
        &self,
        builder: reqwest::RequestBuilder,
        uid: &str,
        access_token: &str,
    ) -> reqwest::RequestBuilder {
        builder.header("x-pm-uid", uid).bearer_auth(access_token)
    }

    fn with_access_token_auth(
        &self,
        builder: reqwest::RequestBuilder,
        access: &ProtonAccessToken,
        request_url: &reqwest::Url,
    ) -> reqwest::RequestBuilder {
        let builder = match access.uid.as_deref() {
            Some(uid) => builder.header("x-pm-uid", uid),
            None => builder,
        };
        let cookie_username = self.username_for_uid(access.uid.as_deref());
        let builder =
            self.with_username_cookie_header(builder, cookie_username.as_deref(), request_url);
        builder.bearer_auth(&access.access_token)
    }
}
