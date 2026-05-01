// Wspólne narzędzia dla cookie sesji. `__Host-` prefix wymusza że cookie żyje
// tylko dla DOKŁADNEJ domeny (nie subdomen) i wymaga `Secure` + `Path=/` bez `Domain`.
// Browsers traktują http://localhost jako "secure context" więc Secure działa też w devie.

use axum::http::{HeaderMap, header::COOKIE};

pub const COOKIE_NAME: &str = "__Host-session";

// Wszystkie endpointy które dotykają sesji używają tego samego setu atrybutów —
// niespójność (np. brak HttpOnly w jednym miejscu) byłaby cichym bugiem.
pub fn set_cookie(plaintext_token: &str, max_age_secs: u64) -> String {
    format!("{COOKIE_NAME}={plaintext_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age_secs}")
}

pub const CLEAR_COOKIE: &str = "__Host-session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

// Cookie header może zawierać wiele par `name=value; name=value`. Szukamy naszej
// po nazwie. Zwracamy `None` także dla pustej wartości — pusty token to clearowany cookie.
pub fn extract_session_cookie(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix("__Host-session="))
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
        h
    }

    #[test]
    fn extracts_solo_cookie() {
        let h = headers_with("__Host-session=abc123");
        assert_eq!(extract_session_cookie(&h), Some("abc123"));
    }

    #[test]
    fn extracts_among_others() {
        let h = headers_with("foo=bar; __Host-session=tok; baz=qux");
        assert_eq!(extract_session_cookie(&h), Some("tok"));
    }

    #[test]
    fn returns_none_when_missing() {
        let h = headers_with("foo=bar; baz=qux");
        assert_eq!(extract_session_cookie(&h), None);
    }

    #[test]
    fn returns_none_when_empty_value() {
        let h = headers_with("__Host-session=");
        assert_eq!(extract_session_cookie(&h), None);
    }

    #[test]
    fn returns_none_when_no_cookie_header() {
        assert_eq!(extract_session_cookie(&HeaderMap::new()), None);
    }
}
