use base64::{Engine as _, engine::general_purpose};
use rand_core::{OsRng, RngCore};
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
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
    #[serde(rename = "UID")]
    pub uid: String,
    pub refresh_token: String,
    pub response_type: String,
    pub grant_type: String,
    #[serde(rename = "RedirectURI")]
    pub redirect_uri: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AuthCookiesBody {
    #[serde(rename = "UID")]
    pub uid: String,
    pub response_type: String,
    pub grant_type: String,
    pub refresh_token: String,
    #[serde(rename = "RedirectURI")]
    pub redirect_uri: String,
    pub persistent: u8,
    pub state: String,
}

pub(super) fn generate_refresh_state_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_session_fork_and_refresh_bodies_like_proton_client() {
        let refresh = serde_json::to_value(RefreshSessionBody {
            uid: "uid-123".into(),
            refresh_token: "refresh-token".into(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            redirect_uri: "https://protonmail.ch".into(),
            state: "state-token".into(),
            access_token: None,
        })
        .unwrap();
        assert_eq!(refresh["UID"], "uid-123");
        assert_eq!(refresh["RefreshToken"], "refresh-token");
        assert_eq!(refresh["RedirectURI"], "https://protonmail.ch");
        assert_eq!(refresh["State"], "state-token");
        assert!(refresh.get("AccessToken").is_none());

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
    fn serializes_browser_auth_cookies_body_like_proton_client() {
        let cookies = serde_json::to_value(AuthCookiesBody {
            uid: "uid-123".into(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            refresh_token: "refresh-token".into(),
            redirect_uri: "https://protonmail.com".into(),
            persistent: 0,
            state: "state-token".into(),
        })
        .unwrap();

        assert_eq!(cookies["UID"], "uid-123");
        assert_eq!(cookies["ResponseType"], "token");
        assert_eq!(cookies["GrantType"], "refresh_token");
        assert_eq!(cookies["RefreshToken"], "refresh-token");
        assert_eq!(cookies["RedirectURI"], "https://protonmail.com");
        assert_eq!(cookies["Persistent"], 0);
        assert_eq!(cookies["State"], "state-token");
    }

    #[test]
    fn generates_refresh_state_tokens_as_opaque_non_empty_values() {
        let state = generate_refresh_state_token();

        assert!(!state.is_empty());
        assert!(state.len() >= 32);
        assert!(
            state
                .chars()
                .all(|character| character.is_ascii_alphanumeric()
                    || character == '-'
                    || character == '_')
        );
    }
}
