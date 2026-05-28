use std::fmt::Write as _;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{
    Request, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue},
};
use serde::de::DeserializeOwned;
use tokio::time::sleep;

use super::human_verification::{HUMAN_VERIFICATION_CAPTCHA_TYPE, HumanVerificationChallenge};

pub(crate) const PROTON_LOGICALS_PROTOCOLS: &str = "WireGuardUDP,WireGuardTCP,WireGuardTLS";
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
pub(crate) const BROWSER_LOGIN_REFERER: &str = "https://account.protonvpn.com/login";
pub(crate) const BROWSER_DOWNLOADS_REFERER: &str = "https://account.protonvpn.com/downloads";

pub(crate) fn normalize_api_base_url(base_url: impl Into<String>) -> String {
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

pub(crate) fn browser_default_headers() -> HeaderMap {
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

pub(crate) fn human_verification_request_headers(token: &str) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-pm-human-verification-token",
        HeaderValue::from_str(token).context("invalid Proton human verification token")?,
    );
    headers.insert(
        "x-pm-human-verification-token-type",
        HeaderValue::from_static(HUMAN_VERIFICATION_CAPTCHA_TYPE),
    );
    Ok(headers)
}

pub(crate) fn with_browser_referer_headers(
    builder: RequestBuilder,
    referer: &'static str,
) -> RequestBuilder {
    builder.header("referer", referer)
}

pub(crate) fn with_browser_origin_headers(
    builder: RequestBuilder,
    referer: &'static str,
) -> RequestBuilder {
    builder
        .header("origin", BROWSER_ORIGIN)
        .header("referer", referer)
}

pub(crate) async fn send_json_with_retry_with_observer<T, F, O>(
    mut build: F,
    debug_http: bool,
    mut observe: O,
) -> Result<T>
where
    T: DeserializeOwned,
    F: FnMut() -> RequestBuilder,
    O: FnMut(&Response) -> Result<()>,
{
    let mut last_error = None;
    for attempt in 0..3 {
        let request = build();
        if debug_http {
            match request.try_clone().and_then(|builder| builder.build().ok()) {
                Some(preview) => debug_request_attempt(attempt + 1, 3, &preview),
                None => eprintln!(
                    "[pso-debug] --> request {}/3: unable to preview request body",
                    attempt + 1
                ),
            }
        }

        match request.send().await {
            Ok(response) => {
                observe(&response)?;
                if has_human_verification(&response) {
                    return decode_response(response, debug_http).await;
                }
                if is_retryable(response.status()) && attempt < 2 {
                    if debug_http {
                        eprintln!(
                            "[pso-debug] <-- retryable response; retrying request after {} ms",
                            250 * (attempt + 1) as u64
                        );
                    }
                    sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
                    continue;
                }
                return decode_response(response, debug_http).await;
            }
            Err(error) if attempt < 2 => {
                if debug_http {
                    eprintln!(
                        "[pso-debug] <-- transport error; retrying request after {} ms: {error:#}",
                        250 * (attempt + 1) as u64
                    );
                }
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
    has_human_verification_status(response.status(), response.headers())
}

fn has_human_verification_status(status: StatusCode, headers: &HeaderMap) -> bool {
    matches!(status.as_u16(), 422 | 429) && headers.contains_key("X-PM-Human-Verification")
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: Response,
    debug_http: bool,
) -> Result<T> {
    let status = response.status();
    let url = response.url().clone();

    if debug_http {
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .context("failed to read Proton API response body")?;
        let body_text = body_bytes_to_text(body.as_ref());
        debug_response_attempt(status, &url, &headers, &body_text);

        if has_human_verification_status(status, &headers) {
            let challenge = headers
                .get("X-PM-Human-Verification")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("challenge")
                .to_string();
            return Err(HumanVerificationChallenge::from_response(
                body.as_ref(),
                &challenge,
                Some(format!(
                    "status={status}; url={url}; headers={}",
                    format_headers(&headers)
                )),
            )
            .into());
        }

        if !status.is_success() {
            bail!(
                "Proton API request failed: status={} url={} headers={} body={}",
                status,
                url,
                format_headers(&headers),
                body_text,
            );
        }

        return serde_json::from_slice::<T>(body.as_ref())
            .context("failed to decode Proton API response");
    }

    if has_human_verification(&response) {
        let challenge = response
            .headers()
            .get("X-PM-Human-Verification")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("challenge")
            .to_string();
        let body = response.text().await.unwrap_or_default();
        return Err(
            HumanVerificationChallenge::from_response(body.as_bytes(), &challenge, None).into(),
        );
    }

    response
        .error_for_status()
        .context("Proton API request failed")?
        .json::<T>()
        .await
        .context("failed to decode Proton API response")
}

fn debug_request_attempt(attempt: usize, total_attempts: usize, request: &Request) {
    let mut output = String::new();
    let _ = writeln!(output, "[pso-debug] --> request {attempt}/{total_attempts}");
    let _ = writeln!(
        output,
        "[pso-debug] --> {} {}",
        request.method(),
        request.url()
    );
    let _ = writeln!(output, "[pso-debug] --> headers:");
    for (name, value) in request.headers() {
        let _ = writeln!(
            output,
            "[pso-debug]     {}: {}",
            name,
            header_value_to_text(name.as_str(), value)
        );
    }

    match request.body().and_then(|body| body.as_bytes()) {
        Some(body) if !body.is_empty() => {
            let _ = writeln!(output, "[pso-debug] --> body:");
            let _ = writeln!(output, "{}", body_bytes_to_text(body));
        }
        Some(_) => {
            let _ = writeln!(output, "[pso-debug] --> body: <empty>");
        }
        None => {
            let _ = writeln!(output, "[pso-debug] --> body: <streaming or unavailable>");
        }
    }

    eprint!("{output}");
}

fn debug_response_attempt(status: StatusCode, url: &reqwest::Url, headers: &HeaderMap, body: &str) {
    let mut output = String::new();
    let _ = writeln!(output, "[pso-debug] <-- response: {status} {url}");
    let _ = writeln!(output, "[pso-debug] <-- headers:");
    for (name, value) in headers {
        let _ = writeln!(
            output,
            "[pso-debug]     {}: {}",
            name,
            header_value_to_text(name.as_str(), value)
        );
    }
    let _ = writeln!(output, "[pso-debug] <-- body:");
    let _ = writeln!(output, "{body}");
    eprint!("{output}");
}

fn format_headers(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for (name, value) in headers {
        parts.push(format!(
            "{name}: {}",
            header_value_to_text(name.as_str(), value)
        ));
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn header_value_to_text(_name: &str, value: &HeaderValue) -> String {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|_| format!("{:?}", value.as_bytes()))
}

fn body_bytes_to_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => serde_json::from_str::<serde_json::Value>(text)
            .map(|value| serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string()))
            .unwrap_or_else(|_| text.to_string()),
        Err(_) => format!("{:?}", bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn human_verification_request_headers_match_capture() {
        let headers =
            human_verification_request_headers("challenge-token:resolved-token").expect("headers");
        assert_eq!(
            headers.get("x-pm-human-verification-token").unwrap(),
            "challenge-token:resolved-token"
        );
        assert_eq!(
            headers.get("x-pm-human-verification-token-type").unwrap(),
            "captcha"
        );
    }

    #[test]
    fn rejects_invalid_human_verification_tokens() {
        assert!(human_verification_request_headers("bad\nvalue").is_err());
    }

    #[test]
    fn normalizes_legacy_core_base_url_to_api_root() {
        assert_eq!(
            normalize_api_base_url("https://account.protonvpn.com/api/core/v4"),
            "https://account.protonvpn.com/api"
        );
    }
}
