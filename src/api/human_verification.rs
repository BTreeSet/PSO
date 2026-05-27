use serde::Deserialize;

pub(crate) const HUMAN_VERIFICATION_CAPTCHA_TYPE: &str = "captcha";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct HumanVerificationResponseBody {
    #[serde(alias = "Details", default)]
    details: Option<HumanVerificationDetails>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct HumanVerificationDetails {
    #[serde(
        alias = "HumanVerificationToken",
        alias = "Token",
        alias = "token",
        default
    )]
    token: Option<String>,
    #[serde(
        default,
        alias = "HumanVerificationMethods",
        alias = "Methods",
        alias = "methods"
    )]
    methods: Vec<String>,
    #[serde(default, alias = "WebUrl", alias = "webUrl", alias = "web_url")]
    web_url: Option<String>,
    #[serde(default, alias = "Title", alias = "title")]
    title: Option<String>,
    #[serde(default, alias = "Description", alias = "description")]
    description: Option<String>,
    #[serde(
        default,
        alias = "ExpiresAt",
        alias = "expiresAt",
        alias = "expires_at"
    )]
    expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanVerificationChallenge {
    pub challenge_token: String,
    pub methods: Vec<String>,
    pub web_url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub expires_at: Option<u64>,
    pub debug_details: Option<String>,
}

impl HumanVerificationChallenge {
    pub(crate) fn from_response(
        body: &[u8],
        challenge_token: &str,
        debug_details: Option<String>,
    ) -> Self {
        let parsed = serde_json::from_slice::<HumanVerificationResponseBody>(body).ok();
        let details = parsed
            .as_ref()
            .and_then(|response| response.details.as_ref());
        let challenge_token = details
            .and_then(|details| details.token.clone())
            .unwrap_or_else(|| challenge_token.to_string());
        let methods = details
            .map(|details| details.methods.clone())
            .filter(|methods| !methods.is_empty())
            .unwrap_or_else(|| vec![HUMAN_VERIFICATION_CAPTCHA_TYPE.to_string()]);
        let web_url = details
            .and_then(|details| details.web_url.clone())
            .unwrap_or_else(|| {
                format!(
                    "https://verify.proton.me/?methods={}&token={challenge_token}",
                    methods.join(",")
                )
            });

        Self {
            challenge_token,
            methods,
            web_url,
            title: details.and_then(|details| details.title.clone()),
            description: details.and_then(|details| details.description.clone()),
            expires_at: details.and_then(|details| details.expires_at),
            debug_details,
        }
    }

    pub fn web_url(&self) -> &str {
        &self.web_url
    }

    pub fn token_type(&self) -> &str {
        self.methods
            .first()
            .map(|method| method.as_str())
            .unwrap_or(HUMAN_VERIFICATION_CAPTCHA_TYPE)
    }

    pub fn supports_captcha(&self) -> bool {
        self.methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(HUMAN_VERIFICATION_CAPTCHA_TYPE))
    }
}

impl std::fmt::Display for HumanVerificationChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "human verification required (methods={}; url={})",
            self.methods.join(","),
            self.web_url
        )?;
        if let Some(details) = self.debug_details.as_deref() {
            write!(f, "; {details}")?;
        }
        Ok(())
    }
}

impl std::error::Error for HumanVerificationChallenge {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_human_verification_challenge_shape() {
        let challenge = HumanVerificationChallenge::from_response(
            br#"{"Code":9001,"Error":"For security reasons, please complete CAPTCHA.","Details":{"HumanVerificationToken":"E-Psio7Nfo8DkBIuQu9niLA3","HumanVerificationMethods":["captcha"],"Title":"Human Verification","Description":"","WebUrl":"https://verify.proton.me/?methods=captcha&token=E-Psio7Nfo8DkBIuQu9niLA3","ExpiresAt":1779826106}}"#,
            "fallback-token",
            None,
        );

        assert_eq!(challenge.challenge_token, "E-Psio7Nfo8DkBIuQu9niLA3");
        assert_eq!(challenge.methods, vec!["captcha"]);
        assert_eq!(
            challenge.web_url(),
            "https://verify.proton.me/?methods=captcha&token=E-Psio7Nfo8DkBIuQu9niLA3"
        );
        assert_eq!(challenge.token_type(), "captcha");
        assert!(challenge.supports_captcha());
    }
}
