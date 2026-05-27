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
    pub refresh_token: String,
    pub response_type: String,
    pub grant_type: String,
    #[serde(rename = "RedirectURI")]
    pub redirect_uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_session_fork_and_refresh_bodies_like_proton_client() {
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
}
