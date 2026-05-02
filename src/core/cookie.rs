use crate::core::{AuthConfig, SessionToken};

/// Returns a Set-Cookie header value for issuing/refreshing the session cookie.
/// Forced flags: HttpOnly, Secure, Path=/. Forbidden: Domain. Prefix: __Host-.
pub fn session_cookie_header_value(token: &SessionToken, cfg: &AuthConfig) -> String {
    let max_age = cfg.session_sliding_ttl.as_secs();
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite={}; Max-Age={}",
        cfg.cookie_name(),
        token.as_str(),
        cfg.same_site.as_cookie_attr(),
        max_age,
    )
}

pub fn session_cookie_clear_header_value(cfg: &AuthConfig) -> String {
    format!(
        "{}=; Path=/; HttpOnly; Secure; SameSite={}; Max-Age=0",
        cfg.cookie_name(),
        cfg.same_site.as_cookie_attr(),
    )
}

/// Parse Cookie header to extract the value of our session cookie.
/// `cookie_header` is the raw value of the `Cookie` request header (multiple `name=value; ...` pairs).
pub fn extract_session_cookie_value<'a>(
    cookie_header: Option<&'a str>,
    cfg: &AuthConfig,
) -> Option<&'a str> {
    let raw = cookie_header?;
    // Search for "<name>=" prefix among ;-separated pairs.
    let target = format!("{}=", cfg.cookie_name());
    raw.split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(target.as_str()))
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Pepper;

    fn cfg() -> AuthConfig {
        AuthConfig::builder_from_pepper(Pepper::from_bytes([0u8; 32]))
            .build()
            .unwrap()
    }

    #[test]
    fn set_cookie_has_required_flags() {
        let token = SessionToken::from_string("ABCxyz".into());
        let v = session_cookie_header_value(&token, &cfg());
        assert!(v.starts_with("__Host-session=ABCxyz; "));
        assert!(v.contains("HttpOnly"));
        assert!(v.contains("Secure"));
        assert!(v.contains("SameSite=Strict"));
        assert!(v.contains("Path=/"));
        assert!(v.contains("Max-Age="));
        assert!(!v.contains("Domain"));
    }

    #[test]
    fn clear_cookie_has_max_age_zero() {
        let v = session_cookie_clear_header_value(&cfg());
        assert!(v.contains("Max-Age=0"));
        assert!(v.starts_with("__Host-session=; "));
    }

    #[test]
    fn extracts_solo_cookie() {
        assert_eq!(
            extract_session_cookie_value(Some("__Host-session=abc"), &cfg()),
            Some("abc")
        );
    }

    #[test]
    fn extracts_among_others() {
        assert_eq!(
            extract_session_cookie_value(Some("foo=bar; __Host-session=tok; baz=qux"), &cfg()),
            Some("tok")
        );
    }

    #[test]
    fn returns_none_for_empty_or_missing() {
        assert_eq!(extract_session_cookie_value(None, &cfg()), None);
        assert_eq!(extract_session_cookie_value(Some(""), &cfg()), None);
        assert_eq!(extract_session_cookie_value(Some("foo=bar"), &cfg()), None);
        assert_eq!(
            extract_session_cookie_value(Some("__Host-session="), &cfg()),
            None
        );
    }
}
