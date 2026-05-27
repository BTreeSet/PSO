use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum LoginIntent {
    Auto,
    Proton,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginInfoBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub intent: LoginIntent,
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
    #[serde(rename = "Payload", skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LoginTwoFactorBody {
    pub two_factor_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "AuthTokensWire")]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub uid: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
struct AuthTokensWire {
    #[serde(alias = "access_token")]
    access_token: String,
    #[serde(alias = "refresh_token")]
    refresh_token: String,
    #[serde(default, rename = "UID")]
    uid_upper: Option<String>,
    #[serde(default, rename = "Uid")]
    uid_title: Option<String>,
    #[serde(default, rename = "uid")]
    uid_lower: Option<String>,
    #[serde(default, alias = "TokenType", alias = "token_type")]
    token_type: Option<String>,
    #[serde(default, alias = "ExpiresIn", alias = "expires_in")]
    expires_in: Option<u64>,
}

impl From<AuthTokensWire> for AuthTokens {
    fn from(value: AuthTokensWire) -> Self {
        Self {
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            uid: value.uid_lower.or(value.uid_title).or(value.uid_upper),
            token_type: value.token_type,
            expires_in: value.expires_in,
        }
    }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::session::{RefreshSessionBody, SessionForkBody};
    use super::*;

    #[test]
    fn serializes_login_and_auth_followup_bodies_like_proton_client() {
        let login_info = serde_json::to_value(LoginInfoBody {
            username: Some("alice@example.com".into()),
            intent: LoginIntent::Auto,
        })
        .unwrap();
        assert_eq!(login_info["Username"], "alice@example.com");
        assert_eq!(login_info["Intent"], "Auto");

        let proton_login_info = serde_json::to_value(LoginInfoBody {
            username: Some("alice@example.com".into()),
            intent: LoginIntent::Proton,
        })
        .unwrap();
        assert_eq!(proton_login_info["Intent"], "Proton");

        let login = serde_json::to_value(LoginBody {
            username: "alice@example.com".into(),
            persistent_cookies: 1,
            client_ephemeral: "client-ephemeral".into(),
            client_proof: "client-proof".into(),
            srp_session: "srp-session".into(),
            payload: Some(json!({
                "opaque": "browser-payload"
            })),
            two_factor_code: Some("123456".into()),
        })
        .unwrap();
        assert_eq!(login["PersistentCookies"], 1);
        assert_eq!(login["SRPSession"], "srp-session");
        assert_eq!(login["Payload"]["opaque"], "browser-payload");
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
    fn deserializes_pre_auth_session_and_code_response_shapes() {
        let session: PreAuthSession = serde_json::from_value(json!({
            "AccessToken": "access-token",
            "RefreshToken": "refresh-token",
            "UID": "uid-123"
        }))
        .unwrap();
        assert_eq!(session.access_token, "access-token");
        assert_eq!(session.refresh_token, "refresh-token");
        assert_eq!(session.uid, "uid-123");

        let code: ApiCodeResponse = serde_json::from_value(json!({
            "Code": 1000
        }))
        .unwrap();
        assert_eq!(code.code, Some(1000));
    }

    #[test]
    fn deserializes_auth_response_and_two_factor_state_shapes() {
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

        let two_factor = serde_json::to_value(LoginTwoFactorBody {
            two_factor_code: "123456".into(),
        })
        .unwrap();
        assert_eq!(two_factor["TwoFactorCode"], "123456");
    }

    #[test]
    fn deserializes_auth_response_with_duplicate_uid_aliases() {
        let response: AuthResponse = serde_json::from_str(
            r#"{
                "UID": "uid-from-uppercase",
                "Uid": "uid-from-mixed-case",
                "AccessToken": "access-token",
                "RefreshToken": "refresh-token",
                "ServerProof": "server-proof"
            }"#,
        )
        .unwrap();

        assert_eq!(response.tokens.uid.as_deref(), Some("uid-from-mixed-case"));
        assert_eq!(response.tokens.access_token, "access-token");
        assert_eq!(response.tokens.refresh_token, "refresh-token");
    }
}
