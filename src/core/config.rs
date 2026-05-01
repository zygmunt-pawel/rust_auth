use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

use crate::core::traits::{AllowAll, EmailPolicy, NoOpSink, SessionEventSink};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("pepper must be valid base64 of exactly 32 bytes")]
    InvalidPepper,
}

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
/// Wrapped in `SecretBox` so accidental Debug logging never prints the bytes.
///
/// Most users don't construct this directly — they pass a base64 string to
/// [`AuthConfig::new`]. `Pepper` is exposed for tests (`from_bytes`) and for advanced
/// cases like fetching pepper bytes from a KMS.
#[derive(Clone)]
pub struct Pepper(Arc<SecretBox<[u8; 32]>>);

impl Pepper {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(SecretBox::new(Box::new(bytes))))
    }

    /// Decode 32 bytes from a base64 string. Returns `ConfigError::InvalidPepper` if the
    /// input doesn't decode to exactly 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self, ConfigError> {
        use base64::Engine as _;
        let v = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| ConfigError::InvalidPepper)?;
        let bytes: [u8; 32] = v.try_into().map_err(|_| ConfigError::InvalidPepper)?;
        Ok(Self::from_bytes(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
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

    pub token_pepper: Pepper,

    pub policy: Arc<dyn EmailPolicy>,
    pub event_sink: Arc<dyn SessionEventSink>,
}

impl AuthConfig {
    /// Construct with a base64-encoded 32-byte pepper.
    ///
    /// The library doesn't read environment variables — read it from your config crate
    /// (figment / config-rs / env / Vault / KMS) and pass the resulting string here.
    ///
    /// ```ignore
    /// let pepper_b64 = std::env::var("AUTH_TOKEN_PEPPER")?;
    /// let cfg = AuthConfig::new(&pepper_b64)?;
    /// ```
    pub fn new(pepper_base64: &str) -> Result<Self, ConfigError> {
        Ok(Self::from_pepper(Pepper::from_base64(pepper_base64)?))
    }

    /// Construct from a [`Pepper`] directly. Intended for tests and advanced cases
    /// (e.g. pepper bytes fetched from KMS / HSM).
    pub fn from_pepper(token_pepper: Pepper) -> Self {
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
        let cfg = AuthConfig::from_pepper(Pepper::from_bytes([0u8; 32]));
        assert_eq!(cfg.cookie_name(), "__Host-session");
    }

    #[test]
    fn pepper_debug_redacts() {
        let p = Pepper::from_bytes([7u8; 32]);
        let s = format!("{p:?}");
        assert!(s.contains("***"));
        assert!(!s.contains("777"));
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = AuthConfig::from_pepper(Pepper::from_bytes([0u8; 32]));
        assert_eq!(cfg.same_site, SameSite::Strict);
        assert_eq!(cfg.session_sliding_ttl, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(cfg.issue_per_email_min_gap, Duration::from_secs(60));
        assert_eq!(cfg.code_failures_per_email_24h_cap, 50);
    }

    #[test]
    fn pepper_from_base64_decodes_valid() {
        // 32 zero bytes → base64 standard
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        assert!(Pepper::from_base64(&b64).is_ok());
    }

    #[test]
    fn pepper_from_base64_rejects_wrong_length() {
        let too_short = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 16]);
        assert!(Pepper::from_base64(&too_short).is_err());
        let too_long = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        assert!(Pepper::from_base64(&too_long).is_err());
    }

    #[test]
    fn pepper_from_base64_rejects_invalid_base64() {
        assert!(Pepper::from_base64("not!valid!base64!").is_err());
    }

    #[test]
    fn auth_config_new_with_valid_b64_string() {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [42u8; 32]);
        let cfg = AuthConfig::new(&b64).unwrap();
        assert_eq!(cfg.cookie_name(), "__Host-session");
    }

    #[test]
    fn auth_config_new_rejects_bad_pepper() {
        assert!(AuthConfig::new("garbage").is_err());
    }
}
