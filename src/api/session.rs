use base64::{Engine as _, engine::general_purpose};
use rand_core::{OsRng, RngCore};
use serde::Serialize;

/// Body sent by Proton's web client to `POST /api/core/v4/auth/cookies` to
/// exchange a refresh token for a fresh access token plus the cookie-backed
/// session that the browser maintains. Field order, casing, and the
/// `Persistent: 0` marker mirror the captured request exactly.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshSessionBody {
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

impl RefreshSessionBody {
    /// Build a refresh request shaped exactly like the proton-web client.
    pub fn browser(uid: &str, refresh_token: &str) -> Self {
        Self {
            uid: uid.to_string(),
            response_type: "token".into(),
            grant_type: "refresh_token".into(),
            refresh_token: refresh_token.to_string(),
            redirect_uri: "https://protonmail.com".into(),
            persistent: 0,
            state: generate_refresh_state_token(),
        }
    }
}

pub(super) fn generate_refresh_state_token() -> String {
    let mut bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_body_matches_browser_capture_shape() {
        let body =
            serde_json::to_value(RefreshSessionBody::browser("uid-123", "refresh-token")).unwrap();

        assert_eq!(body["UID"], "uid-123");
        assert_eq!(body["ResponseType"], "token");
        assert_eq!(body["GrantType"], "refresh_token");
        assert_eq!(body["RefreshToken"], "refresh-token");
        assert_eq!(body["RedirectURI"], "https://protonmail.com");
        assert_eq!(body["Persistent"], 0);
        assert!(body["State"].as_str().unwrap().len() >= 24);
    }

    #[test]
    fn refresh_state_tokens_are_opaque_url_safe() {
        let state = generate_refresh_state_token();
        assert!(state.len() >= 24);
        assert!(
            state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
