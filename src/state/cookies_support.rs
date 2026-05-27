pub(super) fn canonicalize_host(value: &str) -> String {
    value.trim().trim_start_matches('.').to_ascii_lowercase()
}

pub(super) fn canonicalize_cookie_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || !value.starts_with('/') {
        "/".to_string()
    } else {
        value.to_string()
    }
}

pub(super) fn canonicalize_request_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "/".to_string()
    } else if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{}", value)
    }
}

pub(super) fn canonicalize_same_site(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "lax" => "Lax".to_string(),
        "strict" => "Strict".to_string(),
        "none" => "None".to_string(),
        other => other.to_string(),
    }
}

pub(super) fn normalize_cookie_value(value: &str) -> String {
    let value = value.trim();
    match value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        Some(stripped) => stripped.to_string(),
        None => value.to_string(),
    }
}

pub(super) fn default_cookie_path(request_path: &str) -> String {
    let request_path = canonicalize_request_path(request_path);
    if request_path == "/" {
        return request_path;
    }

    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => request_path[..index].to_string(),
    }
}

pub(super) fn domain_matches(cookie_domain: &str, request_host: &str, host_only: bool) -> bool {
    let cookie_domain = canonicalize_host(cookie_domain);
    let request_host = canonicalize_host(request_host);

    if cookie_domain.is_empty() || request_host.is_empty() {
        return false;
    }

    if host_only {
        return request_host == cookie_domain;
    }

    if request_host == cookie_domain {
        return true;
    }

    if !cookie_domain.contains('.') {
        return false;
    }

    request_host
        .strip_suffix(&cookie_domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

pub(super) fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    let cookie_path = canonicalize_cookie_path(cookie_path);
    let request_path = canonicalize_request_path(request_path);

    if request_path == cookie_path {
        return true;
    }

    if !request_path.starts_with(&cookie_path) {
        return false;
    }

    cookie_path.ends_with('/')
        || request_path
            .as_bytes()
            .get(cookie_path.len())
            .is_some_and(|value| *value == b'/')
}

pub(super) fn cookie_domain_candidates(request_host: &str) -> Vec<String> {
    let request_host = canonicalize_host(request_host);
    if request_host.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut suffix = request_host.as_str();
    loop {
        if suffix == request_host || suffix.contains('.') {
            candidates.push(suffix.to_string());
        } else {
            break;
        }

        match suffix.find('.') {
            Some(index) => suffix = &suffix[index + 1..],
            None => break,
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_cookie_domain_candidates_from_request_host() {
        assert_eq!(
            cookie_domain_candidates("Account.ProtonVPN.com"),
            vec![
                "account.protonvpn.com".to_string(),
                "protonvpn.com".to_string(),
            ]
        );
    }

    #[test]
    fn keeps_single_label_hosts_as_single_candidates() {
        assert_eq!(
            cookie_domain_candidates("localhost"),
            vec!["localhost".to_string()]
        );
    }

    #[test]
    fn matches_parent_domains_but_not_bare_tlds() {
        assert!(domain_matches(
            "protonvpn.com",
            "account.protonvpn.com",
            false
        ));
        assert!(!domain_matches("com", "account.protonvpn.com", false));
        assert!(domain_matches("localhost", "localhost", false));
    }
}
