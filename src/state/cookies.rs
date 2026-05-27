use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::{ToSql, params, params_from_iter};
use tracing::warn;

use super::cookies_support::{
    canonicalize_cookie_path, canonicalize_host, canonicalize_request_path, canonicalize_same_site,
    cookie_domain_candidates, default_cookie_path, domain_matches, normalize_cookie_value,
    path_matches,
};
use super::support::unix_timestamp;
use super::{ProtonCookieRow, StateStore, username_state_key};

#[derive(Clone, Debug)]
struct PersistedCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: bool,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    expires_at_ms: Option<i64>,
    created_at: i64,
}

impl PersistedCookie {
    fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
    }
}

#[derive(Clone, Debug)]
struct PersistedCookieRow {
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: bool,
    secure: bool,
    _http_only: bool,
    _same_site: Option<String>,
    expires_at_ms: Option<i64>,
    created_at: i64,
}

impl PersistedCookieRow {
    fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
    }

    fn matches(&self, request_host: &str, request_path: &str, request_is_secure: bool) -> bool {
        if self.secure && !request_is_secure {
            return false;
        }

        if !domain_matches(&self.domain, request_host, self.host_only) {
            return false;
        }

        path_matches(&self.path, request_path)
    }
}

impl StateStore {
    pub fn clear_proton_cookies_for_username(&self, username: &str) -> Result<usize> {
        let username_key = username_state_key(username);
        self.connection
            .execute(
                "DELETE FROM proton_cookies WHERE username_key = ?1",
                params![username_key],
            )
            .map_err(Into::into)
    }

    pub fn clear_proton_cookies(&self) -> Result<usize> {
        self.connection
            .execute("DELETE FROM proton_cookies", [])
            .map_err(Into::into)
    }

    pub fn list_proton_cookies(&self, limit: usize) -> Result<Vec<ProtonCookieRow>> {
        let mut statement = self.connection.prepare(
            "SELECT c.username_key, a.username, c.cookie_name, c.cookie_domain, c.cookie_path,
                    c.cookie_value, c.host_only, c.secure, c.http_only, c.same_site,
                    c.expires_at_ms, c.created_at, c.updated_at
             FROM proton_cookies c
               LEFT JOIN users a ON a.username_key = c.username_key
             ORDER BY c.updated_at DESC, a.username ASC, c.cookie_domain ASC,
                      c.cookie_path ASC, c.cookie_name ASC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(ProtonCookieRow {
                username_key: row.get(0)?,
                username: row.get(1)?,
                cookie_name: row.get(2)?,
                cookie_domain: row.get(3)?,
                cookie_path: row.get(4)?,
                cookie_value: row.get(5)?,
                host_only: row.get::<_, i64>(6)? != 0,
                secure: row.get::<_, i64>(7)? != 0,
                http_only: row.get::<_, i64>(8)? != 0,
                same_site: row.get(9)?,
                expires_at_ms: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        super::support::collect_rows(rows)
    }

    pub fn record_proton_set_cookies(
        &self,
        username: &str,
        request_host: &str,
        request_path: &str,
        set_cookie_values: &[String],
    ) -> Result<()> {
        if set_cookie_values.is_empty() {
            return Ok(());
        }

        let username_key = username_state_key(username);
        let updated_at = unix_timestamp()?;
        let now_ms = current_time_ms();
        self.upsert_user(&username_key, username, updated_at)?;

        for value in set_cookie_values {
            let Some(cookie) = parse_set_cookie(value, request_host, request_path, now_ms) else {
                warn!("ignoring malformed Proton Set-Cookie header");
                continue;
            };

            if cookie.is_expired(now_ms) {
                self.delete_proton_cookie(
                    &username_key,
                    &cookie.name,
                    &cookie.domain,
                    &cookie.path,
                )?;
                continue;
            }

            self.store_proton_cookie(&username_key, &cookie, updated_at)?;
        }

        Ok(())
    }

    pub fn load_proton_cookie_header(
        &self,
        username: &str,
        request_host: &str,
        request_path: &str,
        request_is_secure: bool,
    ) -> Result<Option<String>> {
        let username_key = username_state_key(username);
        let request_host = canonicalize_host(request_host);
        let domain_candidates = cookie_domain_candidates(&request_host);
        if domain_candidates.is_empty() {
            return Ok(None);
        }

        let placeholders = std::iter::repeat_n("?", domain_candidates.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT cookie_name, cookie_value, cookie_domain, cookie_path,
                    host_only, secure, http_only, same_site, expires_at_ms, created_at
             FROM proton_cookies
             WHERE username_key = ? AND cookie_domain IN ({placeholders})"
        );
        let mut statement = self.connection.prepare(&sql)?;

        let request_path = canonicalize_request_path(request_path);
        let now_ms = current_time_ms();
        let mut active_cookies = Vec::new();
        let mut expired_cookies = Vec::new();

        let rows = statement.query_map(
            params_from_iter(
                std::iter::once(&username_key as &dyn ToSql).chain(
                    domain_candidates
                        .iter()
                        .map(|candidate| candidate as &dyn ToSql),
                ),
            ),
            |row| {
                Ok(PersistedCookieRow {
                    name: row.get(0)?,
                    value: row.get(1)?,
                    domain: row.get(2)?,
                    path: row.get(3)?,
                    host_only: row.get::<_, i64>(4)? != 0,
                    secure: row.get::<_, i64>(5)? != 0,
                    _http_only: row.get::<_, i64>(6)? != 0,
                    _same_site: row.get(7)?,
                    expires_at_ms: row.get(8)?,
                    created_at: row.get(9)?,
                })
            },
        )?;

        for row in rows {
            let row = row?;
            if row.is_expired(now_ms) {
                expired_cookies.push((row.name, row.domain, row.path));
                continue;
            }

            if row.matches(&request_host, &request_path, request_is_secure) {
                active_cookies.push(row);
            }
        }

        drop(statement);

        for (name, domain, path) in expired_cookies {
            self.delete_proton_cookie(&username_key, &name, &domain, &path)?;
        }

        active_cookies.sort_by(|left, right| {
            right
                .path
                .len()
                .cmp(&left.path.len())
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.domain.cmp(&right.domain))
                .then_with(|| left.name.cmp(&right.name))
        });

        if active_cookies.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                active_cookies
                    .into_iter()
                    .map(|cookie| format!("{}={}", cookie.name, cookie.value))
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    fn store_proton_cookie(
        &self,
        username_key: &str,
        cookie: &PersistedCookie,
        updated_at: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO proton_cookies
               (username_key, cookie_name, cookie_domain, cookie_path, cookie_value,
                host_only, secure, http_only, same_site, expires_at_ms, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(username_key, cookie_name, cookie_domain, cookie_path) DO UPDATE SET
               cookie_value = excluded.cookie_value,
               host_only = excluded.host_only,
               secure = excluded.secure,
               http_only = excluded.http_only,
               same_site = excluded.same_site,
               expires_at_ms = excluded.expires_at_ms,
               updated_at = excluded.updated_at",
            params![
                username_key,
                &cookie.name,
                &cookie.domain,
                &cookie.path,
                &cookie.value,
                if cookie.host_only { 1 } else { 0 },
                if cookie.secure { 1 } else { 0 },
                if cookie.http_only { 1 } else { 0 },
                cookie.same_site.as_deref(),
                cookie.expires_at_ms,
                cookie.created_at,
                updated_at,
            ],
        )?;
        Ok(())
    }

    fn delete_proton_cookie(
        &self,
        username_key: &str,
        name: &str,
        domain: &str,
        path: &str,
    ) -> Result<()> {
        self.connection.execute(
            "DELETE FROM proton_cookies
             WHERE username_key = ?1 AND cookie_name = ?2 AND cookie_domain = ?3 AND cookie_path = ?4",
            params![username_key, name, domain, path],
        )?;
        Ok(())
    }
}

fn parse_set_cookie(
    header_value: &str,
    request_host: &str,
    request_path: &str,
    now_ms: i64,
) -> Option<PersistedCookie> {
    let mut parts = header_value.split(';');
    let name_value = parts.next()?.trim();
    let (raw_name, raw_value) = name_value.split_once('=')?;
    let name = raw_name.trim();
    if name.is_empty() {
        return None;
    }

    let mut domain = canonicalize_host(request_host);
    let mut host_only = true;
    let mut path = default_cookie_path(request_path);
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    let mut expires_at_ms = None;
    let mut max_age = None;

    for attribute in parts {
        let attribute = attribute.trim();
        if attribute.is_empty() {
            continue;
        }

        let (attribute_name, attribute_value) = match attribute.split_once('=') {
            Some((attribute_name, attribute_value)) => {
                (attribute_name.trim(), Some(attribute_value.trim()))
            }
            None => (attribute, None),
        };

        match attribute_name.to_ascii_lowercase().as_str() {
            "domain" => {
                let Some(value) = attribute_value else {
                    continue;
                };
                let candidate = canonicalize_host(value);
                if candidate.is_empty() || !domain_matches(&candidate, request_host, false) {
                    return None;
                }
                domain = candidate;
                host_only = false;
            }
            "path" => {
                if let Some(value) = attribute_value {
                    path = canonicalize_cookie_path(value);
                }
            }
            "secure" => secure = true,
            "httponly" => http_only = true,
            "samesite" => {
                if let Some(value) = attribute_value {
                    same_site = Some(canonicalize_same_site(value));
                }
            }
            "max-age" => {
                if let Some(value) = attribute_value {
                    max_age = value.parse::<i64>().ok();
                }
            }
            "expires" => {
                if let Some(value) = attribute_value {
                    expires_at_ms = httpdate::parse_http_date(value)
                        .ok()
                        .and_then(system_time_to_unix_ms);
                }
            }
            _ => {}
        }
    }

    let expires_at_ms = match max_age {
        Some(max_age) if max_age <= 0 => Some(now_ms.saturating_sub(1)),
        Some(max_age) => Some(now_ms.saturating_add(max_age.saturating_mul(1_000))),
        None => expires_at_ms,
    };

    Some(PersistedCookie {
        name: name.to_string(),
        value: normalize_cookie_value(raw_value),
        domain,
        path,
        host_only,
        secure,
        http_only,
        same_site,
        expires_at_ms,
        created_at: unix_timestamp().ok()?,
    })
}

fn current_time_ms() -> i64 {
    system_time_to_unix_ms(SystemTime::now()).unwrap_or(i64::MAX)
}

fn system_time_to_unix_ms(value: SystemTime) -> Option<i64> {
    let duration = value.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_cookie_rules() {
        let now_ms = 1_000_000_i64;
        let cookie = parse_set_cookie(
            "Session-Id=session-123; Domain=protonvpn.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=60",
            "account.protonvpn.com",
            "/api/core/v4/auth",
            now_ms,
        )
        .expect("cookie");

        assert_eq!(cookie.name, "Session-Id");
        assert_eq!(cookie.domain, "protonvpn.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site.as_deref(), Some("Lax"));
        assert_eq!(cookie.expires_at_ms, Some(now_ms + 60_000));
    }

    #[test]
    fn rejects_bare_tld_cookie_domains() {
        let cookie = parse_set_cookie(
            "Session-Id=session-123; Domain=com; Path=/; Secure",
            "account.protonvpn.com",
            "/api/core/v4/auth",
            1_000_000,
        );

        assert!(cookie.is_none());
    }

    #[test]
    fn matches_domains_and_paths_like_browser_cookies() {
        let row = PersistedCookieRow {
            name: "Session-Id".into(),
            value: "session-123".into(),
            domain: "protonvpn.com".into(),
            path: "/api".into(),
            host_only: false,
            secure: true,
            _http_only: true,
            _same_site: None,
            expires_at_ms: None,
            created_at: 1,
        };

        assert!(row.matches("account.protonvpn.com", "/api/core/v4/auth", true));
        assert!(!row.matches("account.protonvpn.com", "/downloads", true));
        assert!(!row.matches("account.protonvpn.com", "/api/core/v4/auth", false));
    }

    #[test]
    fn resolves_default_cookie_path_from_request_path() {
        assert_eq!(default_cookie_path("/"), "/");
        assert_eq!(default_cookie_path("/api/core/v4/auth"), "/api/core/v4");
        assert_eq!(default_cookie_path("api/core/v4/auth"), "/api/core/v4");
    }
}
