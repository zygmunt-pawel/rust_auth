use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretBox};

use crate::core::traits::{AllowAll, EmailPolicy, NoOpSink, SessionEventSink};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
}

impl SameSite {
    pub fn as_cookie_attr(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
        }
    }
}

/// 32-byte server-side pepper for HMAC-SHA256(pepper, plaintext) over all stored hashes.
/// Wrap a SecretBox so accidental Debug logging never prints the bytes.
#[derive(Clone)]
pub struct Pepper(Arc<SecretBox<[u8; 32]>>);

impl Pepper {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(bytes))))
    }

    /// 32 raw bytes from base64-decoded env var. Panics if input doesn't decode to exactly 32 bytes —
    /// this is a startup-time configuration check, not a runtime path.
    pub fn from_base64(s: &str) -> Self {
        use base64::Engine as _;
        let v = base64::engine::general_purpose::STANDARD.decode(s)
            .expect("AUTH_TOKEN_PEPPER must be valid base64");
        let bytes: [u8; 32] = v.try_into().expect("AUTH_TOKEN_PEPPER must decode to exactly 32 bytes");
        Self::from_bytes(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; 32] { self.0.expose_secret() }
}

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pepper").field("bytes", &"***").finish()
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    pub cookie_name_suffix: String,
    pub same_site: SameSite,
    pub session_sliding_ttl: Duration,
    pub session_absolute_ttl: Duration,
    pub session_refresh_threshold: Duration,

    pub magic_link_ttl: Duration,
    pub code_ttl: Duration,

    pub issue_per_email_min_gap: Duration,
    pub issue_per_email_24h_cap: u32,
    pub issue_per_ip_1h_cap: u32,
    pub issue_per_ip_24h_cap: u32,
    pub verify_per_ip_per_min_cap: u32,
    pub code_failures_per_email_24h_cap: u32,
    pub email_lockout_duration: Duration,

    pub token_pepper: Pepper,

    pub policy: Arc<dyn EmailPolicy>,
    pub event_sink: Arc<dyn SessionEventSink>,
}

impl AuthConfig {
    pub fn new(token_pepper: Pepper) -> Self {
        Self {
            cookie_name_suffix: "session".into(),
            same_site: SameSite::Strict,
            session_sliding_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            session_absolute_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            session_refresh_threshold: Duration::from_secs(24 * 60 * 60),

            magic_link_ttl: Duration::from_secs(15 * 60),
            code_ttl: Duration::from_secs(5 * 60),

            issue_per_email_min_gap: Duration::from_secs(60),
            issue_per_email_24h_cap: 5,
            issue_per_ip_1h_cap: 5,
            issue_per_ip_24h_cap: 30,
            verify_per_ip_per_min_cap: 30,
            code_failures_per_email_24h_cap: 50,
            email_lockout_duration: Duration::from_secs(60 * 60),

            token_pepper,

            policy: Arc::new(AllowAll),
            event_sink: Arc::new(NoOpSink),
        }
    }

    /// Final cookie name including __Host- prefix (always enforced).
    pub fn cookie_name(&self) -> String {
        format!("__Host-{}", self.cookie_name_suffix)
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("cookie_name_suffix", &self.cookie_name_suffix)
            .field("same_site", &self.same_site)
            .field("session_sliding_ttl", &self.session_sliding_ttl)
            .field("session_absolute_ttl", &self.session_absolute_ttl)
            .field("session_refresh_threshold", &self.session_refresh_threshold)
            .field("magic_link_ttl", &self.magic_link_ttl)
            .field("code_ttl", &self.code_ttl)
            .field("token_pepper", &self.token_pepper)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_name_has_host_prefix() {
        let cfg = AuthConfig::new(Pepper::from_bytes([0u8; 32]));
        assert_eq!(cfg.cookie_name(), "__Host-session");
    }

    #[test]
    fn pepper_debug_redacts() {
        let p = Pepper::from_bytes([7u8; 32]);
        let s = format!("{p:?}");
        assert!(s.contains("***"));
        assert!(!s.contains("777")); // numbers from raw bytes shouldn't leak
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = AuthConfig::new(Pepper::from_bytes([0u8; 32]));
        assert_eq!(cfg.same_site, SameSite::Strict);
        assert_eq!(cfg.session_sliding_ttl, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(cfg.issue_per_email_min_gap, Duration::from_secs(60));
        assert_eq!(cfg.code_failures_per_email_24h_cap, 50);
    }
}
