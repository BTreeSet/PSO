use std::time::Duration;

use anyhow::{Context, Result, bail};
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

#[derive(Clone, Debug)]
pub struct ProtonApiClient {
    base_url: String,
    client: Client,
    client_id: String,
}

impl ProtonApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Self::with_profile(base_url, &ProtonClientProfile::default())
    }

    pub fn from_context(context: &RuntimeContext) -> Result<Self> {
        Self::with_profile(&context.api_base_url, &context.proton_client)
    }

    pub fn with_profile(
        base_url: impl Into<String>,
        profile: &ProtonClientProfile,
    ) -> Result<Self> {
        let mut default_headers = HeaderMap::new();
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
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            client_id: profile.client_id.clone(),
        })
    }

    pub async fn get_certificate(
        &self,
        access_token: &str,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse> {
        let url = format!("{}/vpn/v1/certificate", self.base_url);
        send_json_with_retry(|| {
            self.client
                .post(&url)
                .bearer_auth(access_token)
                .json(request)
        })
        .await
        .context("Proton certificate request failed")
    }

    pub async fn get_logicals(
        &self,
        access_token: &str,
        country: Option<&str>,
        netzone: Option<&str>,
    ) -> Result<Vec<LogicalServer>> {
        let url = format!("{}/vpn/v2/logicals", self.base_url);
        Ok(send_json_with_retry::<ProtonLogicalResponse, _>(|| {
            let mut builder = self.client.get(&url).bearer_auth(access_token).query(&[
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
        })
        .await
        .context("Proton logicals request failed")?
        .into_servers())
    }

    pub async fn auth_info(
        &self,
        username: &str,
        human_verification_token: Option<&str>,
    ) -> Result<LoginInfoResponse> {
        let url = format!("{}/auth/v4/info", self.base_url);
        let request = LoginInfoBody {
            username: username.to_string(),
        };
        send_json_with_retry(|| {
            let mut builder = self.client.post(&url).json(&request);
            if let Some(token) = human_verification_token {
                builder = builder.header("X-PM-Human-Verification", token);
            }
            builder
        })
        .await
        .context("Proton auth info request failed")
    }

    pub async fn authenticate(
        &self,
        username: &str,
        srp: &SrpProof,
        modulus_hex: &str,
        two_factor_code: Option<&str>,
        human_verification_token: Option<&str>,
    ) -> Result<AuthTokens> {
        let url = format!("{}/auth/v4", self.base_url);
        let request = LoginBody {
            username: username.to_string(),
            client_ephemeral: srp.client_ephemeral.clone(),
            client_proof: srp.client_proof.clone(),
            two_factor_code: two_factor_code.map(ToOwned::to_owned),
            srp_modulus_hex: modulus_hex.to_string(),
        };
        send_json_with_retry(|| {
            let mut builder = self.client.post(&url).json(&request);
            if let Some(token) = human_verification_token {
                builder = builder.header("X-PM-Human-Verification", token);
            }
            builder
        })
        .await
        .context("Proton auth request failed")
    }

    pub async fn fork_vpn_session(
        &self,
        primary_access_token: &str,
        payload: Option<String>,
    ) -> Result<AuthTokens> {
        let url = format!("{}/auth/v4/sessions/forks", self.base_url);
        let request = SessionForkBody {
            payload: payload.unwrap_or_default(),
            child_client_id: self.client_id.clone(),
            independent: 1,
            user_code: None,
        };

        send_json_with_retry(|| {
            self.client
                .post(&url)
                .bearer_auth(primary_access_token)
                .json(&request)
        })
        .await
        .context("Proton session fork request failed")
    }

    pub async fn refresh_session(&self, uid: &str, refresh_token: &str) -> Result<AuthTokens> {
        let url = format!("{}/auth/v4/refresh", self.base_url);
        let request = RefreshSessionBody {
            uid: uid.to_string(),
            refresh_token: refresh_token.to_string(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            redirect_uri: "http://protonvpn.ch".into(),
        };

        send_json_with_retry(|| self.client.post(&url).json(&request))
            .await
            .context("Proton auth refresh request failed")
    }
}

async fn send_json_with_retry<T, F>(mut build: F) -> Result<T>
where
    T: DeserializeOwned,
    F: FnMut() -> RequestBuilder,
{
    let mut last_error = None;
    for attempt in 0..3 {
        match build().send().await {
            Ok(response) if has_human_verification(&response) => {
                return decode_response(response).await;
            }
            Ok(response) if is_retryable(response.status()) && attempt < 2 => {
                sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
            }
            Ok(response) => return decode_response(response).await,
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

async fn decode_response<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    if has_human_verification(&response) {
        let challenge = response
            .headers()
            .get("X-PM-Human-Verification")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("challenge")
            .to_string();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "human verification required: solve the Proton challenge and retry with --human-verification-token ({challenge}). Response body: {body}"
        );
    }

    response
        .error_for_status()
        .context("Proton API request failed")?
        .json::<T>()
        .await
        .context("failed to decode Proton API response")
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginInfoBody {
    pub username: String,
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
    #[serde(alias = "TwoFactor", default)]
    pub two_factor: Option<u8>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginBody {
    pub username: String,
    pub client_ephemeral: String,
    pub client_proof: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_code: Option<String>,
    #[serde(rename = "SRPModulusHex")]
    pub srp_modulus_hex: String,
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
    pub uid: String,
    pub refresh_token: String,
    pub response_type: String,
    pub grant_type: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CertificateRequest {
    #[serde(rename = "ClientPublicKey")]
    pub client_public_key: String,
    #[serde(rename = "ClientPublicKeyMode")]
    pub client_public_key_mode: String,
    #[serde(rename = "DeviceName")]
    pub device_name: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "Features")]
    pub features: Vec<String>,
    #[serde(rename = "Duration", skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

impl CertificateRequest {
    pub fn wireguard_session(
        client_public_key: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            client_public_key: client_public_key.into(),
            client_public_key_mode: "EC".into(),
            device_name: device_name.into(),
            mode: "session".into(),
            features: Vec::new(),
            duration: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CertificateResponse {
    #[serde(alias = "Certificate", alias = "certificate")]
    pub certificate: String,
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
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_certificate_request_like_proton_client() {
        let request = CertificateRequest::wireguard_session("public-key", "PSO-Rust-Control-Plane");
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["ClientPublicKey"], "public-key");
        assert_eq!(value["ClientPublicKeyMode"], "EC");
        assert_eq!(value["DeviceName"], "PSO-Rust-Control-Plane");
        assert_eq!(value["Mode"], "session");
        assert_eq!(value["Features"], json!([]));
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
            username: "alice@example.com".into(),
        })
        .unwrap();
        assert_eq!(login_info["Username"], "alice@example.com");

        let fork = serde_json::to_value(SessionForkBody {
            payload: "payload".into(),
            child_client_id: "android-vpn".into(),
            independent: 1,
            user_code: Some("code".into()),
        })
        .unwrap();
        assert_eq!(fork["ChildClientID"], "android-vpn");
        assert_eq!(fork["Payload"], "payload");
        assert_eq!(fork["Independent"], 1);
        assert_eq!(fork["UserCode"], "code");
    }
}
