use std::sync::Arc;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

use crate::core::policy::DisposableBlocklist;
use crate::core::traits::{EmailPolicy, NoOpSink, SessionEventSink};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("pepper must be valid base64 of exactly 32 bytes")]
    InvalidPepper,
    #[error("invalid config: {0}")]
    Invalid(String),
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

// ─────────────────────── AuthConfig (read-only after build) ───────────────────────

/// Validated, immutable auth-library config.
///
/// Construct exclusively via [`AuthConfig::builder`] (or `builder_from_pepper`) — the
/// builder validates all single-field ranges AND cross-field invariants before
/// returning a value. Fields are read-only; library functions read via getters.
///
/// ```ignore
/// let cfg = AuthConfig::builder(&pepper_b64)?
///     .magic_link_ttl(Duration::from_secs(15 * 60))
///     .code_ttl(Duration::from_secs(15 * 60))
///     .build()?;
/// ```
#[derive(Clone)]
pub struct AuthConfig {
    pub(crate) cookie_name_suffix: String,
    pub(crate) same_site: SameSite,
    pub(crate) session_sliding_ttl: Duration,
    pub(crate) session_absolute_ttl: Duration,
    pub(crate) session_refresh_threshold: Duration,

    pub(crate) magic_link_ttl: Duration,
    pub(crate) code_ttl: Duration,

    pub(crate) issue_per_email_cap: u32,
    pub(crate) issue_per_ip_cap: u32,
    pub(crate) issue_window: Duration,
    pub(crate) issue_block_duration: Duration,
    pub(crate) ip_permanent_block_threshold: u32,

    pub(crate) verify_per_ip_per_min_cap: u32,
    pub(crate) code_failures_per_email_24h_cap: u32,
    pub(crate) code_attempts_per_row: u8,
    pub(crate) link_attempts_per_token: u8,

    pub(crate) token_pepper: Pepper,

    pub(crate) policy: Arc<dyn EmailPolicy>,
    #[allow(dead_code)] // exposed via event_sink() getter for consumers; not consumed by lib
    pub(crate) event_sink: Arc<dyn SessionEventSink>,

    pub(crate) log_full_email: bool,
}

impl AuthConfig {
    /// Start a builder with a base64-encoded 32-byte pepper.
    pub fn builder(pepper_base64: &str) -> Result<AuthConfigBuilder, ConfigError> {
        Ok(AuthConfigBuilder::new(Pepper::from_base64(pepper_base64)?))
    }

    /// Start a builder with an already-decoded [`Pepper`].
    pub fn builder_from_pepper(pepper: Pepper) -> AuthConfigBuilder {
        AuthConfigBuilder::new(pepper)
    }

    // ── read-only getters ────────────────────────────────────────────────────

    pub fn cookie_name_suffix(&self) -> &str {
        &self.cookie_name_suffix
    }
    pub fn same_site(&self) -> SameSite {
        self.same_site
    }
    pub fn session_sliding_ttl(&self) -> Duration {
        self.session_sliding_ttl
    }
    pub fn session_absolute_ttl(&self) -> Duration {
        self.session_absolute_ttl
    }
    pub fn session_refresh_threshold(&self) -> Duration {
        self.session_refresh_threshold
    }
    pub fn magic_link_ttl(&self) -> Duration {
        self.magic_link_ttl
    }
    pub fn code_ttl(&self) -> Duration {
        self.code_ttl
    }
    pub fn issue_per_email_cap(&self) -> u32 {
        self.issue_per_email_cap
    }
    pub fn issue_per_ip_cap(&self) -> u32 {
        self.issue_per_ip_cap
    }
    pub fn issue_window(&self) -> Duration {
        self.issue_window
    }
    pub fn issue_block_duration(&self) -> Duration {
        self.issue_block_duration
    }
    pub fn ip_permanent_block_threshold(&self) -> u32 {
        self.ip_permanent_block_threshold
    }
    pub fn verify_per_ip_per_min_cap(&self) -> u32 {
        self.verify_per_ip_per_min_cap
    }
    pub fn code_failures_per_email_24h_cap(&self) -> u32 {
        self.code_failures_per_email_24h_cap
    }
    pub fn code_attempts_per_row(&self) -> u8 {
        self.code_attempts_per_row
    }
    pub fn link_attempts_per_token(&self) -> u8 {
        self.link_attempts_per_token
    }
    pub fn log_full_email(&self) -> bool {
        self.log_full_email
    }
    pub fn policy(&self) -> &Arc<dyn EmailPolicy> {
        &self.policy
    }
    pub fn event_sink(&self) -> &Arc<dyn SessionEventSink> {
        &self.event_sink
    }

    /// Final cookie name including __Host- prefix (always enforced).
    pub fn cookie_name(&self) -> String {
        format!("__Host-{}", self.cookie_name_suffix)
    }

    /// Emit a `tracing::info!` event with all settings (excluding pepper / dyn traits).
    /// Call once at startup so the active config is visible in your log aggregator.
    pub fn log_settings(&self) {
        tracing::info!(
            cookie_name = %self.cookie_name(),
            same_site = ?self.same_site,
            magic_link_ttl_secs = self.magic_link_ttl.as_secs(),
            code_ttl_secs = self.code_ttl.as_secs(),
            session_sliding_ttl_secs = self.session_sliding_ttl.as_secs(),
            session_absolute_ttl_secs = self.session_absolute_ttl.as_secs(),
            session_refresh_threshold_secs = self.session_refresh_threshold.as_secs(),
            issue_per_email_cap = self.issue_per_email_cap,
            issue_per_ip_cap = self.issue_per_ip_cap,
            issue_window_secs = self.issue_window.as_secs(),
            issue_block_duration_secs = self.issue_block_duration.as_secs(),
            ip_permanent_block_threshold = self.ip_permanent_block_threshold,
            verify_per_ip_per_min_cap = self.verify_per_ip_per_min_cap,
            code_failures_per_email_24h_cap = self.code_failures_per_email_24h_cap,
            code_attempts_per_row = self.code_attempts_per_row,
            link_attempts_per_token = self.link_attempts_per_token,
            log_full_email = self.log_full_email,
            policy = self.policy.name(),
            "auth config initialized",
        );
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

// ─────────────────────── AuthConfigBuilder ───────────────────────

/// Builder for [`AuthConfig`]. Setters are infallible; `build()` returns
/// `Result<AuthConfig, ConfigError>` after validating every single-field range
/// and every cross-field invariant. Defaults applied for unset fields.
#[derive(Clone)]
pub struct AuthConfigBuilder {
    pepper: Pepper,
    cookie_name_suffix: Option<String>,
    same_site: Option<SameSite>,
    session_sliding_ttl: Option<Duration>,
    session_absolute_ttl: Option<Duration>,
    session_refresh_threshold: Option<Duration>,
    magic_link_ttl: Option<Duration>,
    code_ttl: Option<Duration>,
    issue_per_email_cap: Option<u32>,
    issue_per_ip_cap: Option<u32>,
    issue_window: Option<Duration>,
    issue_block_duration: Option<Duration>,
    ip_permanent_block_threshold: Option<u32>,
    verify_per_ip_per_min_cap: Option<u32>,
    code_failures_per_email_24h_cap: Option<u32>,
    code_attempts_per_row: Option<u8>,
    link_attempts_per_token: Option<u8>,
    policy: Option<Arc<dyn EmailPolicy>>,
    event_sink: Option<Arc<dyn SessionEventSink>>,
    log_full_email: Option<bool>,
}

impl AuthConfigBuilder {
    fn new(pepper: Pepper) -> Self {
        Self {
            pepper,
            cookie_name_suffix: None,
            same_site: None,
            session_sliding_ttl: None,
            session_absolute_ttl: None,
            session_refresh_threshold: None,
            magic_link_ttl: None,
            code_ttl: None,
            issue_per_email_cap: None,
            issue_per_ip_cap: None,
            issue_window: None,
            issue_block_duration: None,
            ip_permanent_block_threshold: None,
            verify_per_ip_per_min_cap: None,
            code_failures_per_email_24h_cap: None,
            code_attempts_per_row: None,
            link_attempts_per_token: None,
            policy: None,
            event_sink: None,
            log_full_email: None,
        }
    }

    pub fn cookie_name_suffix(mut self, v: impl Into<String>) -> Self {
        self.cookie_name_suffix = Some(v.into());
        self
    }
    pub fn same_site(mut self, v: SameSite) -> Self {
        self.same_site = Some(v);
        self
    }
    pub fn session_sliding_ttl(mut self, v: Duration) -> Self {
        self.session_sliding_ttl = Some(v);
        self
    }
    pub fn session_absolute_ttl(mut self, v: Duration) -> Self {
        self.session_absolute_ttl = Some(v);
        self
    }
    pub fn session_refresh_threshold(mut self, v: Duration) -> Self {
        self.session_refresh_threshold = Some(v);
        self
    }
    pub fn magic_link_ttl(mut self, v: Duration) -> Self {
        self.magic_link_ttl = Some(v);
        self
    }
    pub fn code_ttl(mut self, v: Duration) -> Self {
        self.code_ttl = Some(v);
        self
    }
    pub fn issue_per_email_cap(mut self, v: u32) -> Self {
        self.issue_per_email_cap = Some(v);
        self
    }
    pub fn issue_per_ip_cap(mut self, v: u32) -> Self {
        self.issue_per_ip_cap = Some(v);
        self
    }
    pub fn issue_window(mut self, v: Duration) -> Self {
        self.issue_window = Some(v);
        self
    }
    pub fn issue_block_duration(mut self, v: Duration) -> Self {
        self.issue_block_duration = Some(v);
        self
    }
    pub fn ip_permanent_block_threshold(mut self, v: u32) -> Self {
        self.ip_permanent_block_threshold = Some(v);
        self
    }
    pub fn verify_per_ip_per_min_cap(mut self, v: u32) -> Self {
        self.verify_per_ip_per_min_cap = Some(v);
        self
    }
    pub fn code_failures_per_email_24h_cap(mut self, v: u32) -> Self {
        self.code_failures_per_email_24h_cap = Some(v);
        self
    }
    pub fn code_attempts_per_row(mut self, v: u8) -> Self {
        self.code_attempts_per_row = Some(v);
        self
    }
    pub fn link_attempts_per_token(mut self, v: u8) -> Self {
        self.link_attempts_per_token = Some(v);
        self
    }
    pub fn policy(mut self, v: Arc<dyn EmailPolicy>) -> Self {
        self.policy = Some(v);
        self
    }
    pub fn event_sink(mut self, v: Arc<dyn SessionEventSink>) -> Self {
        self.event_sink = Some(v);
        self
    }
    pub fn log_full_email(mut self, v: bool) -> Self {
        self.log_full_email = Some(v);
        self
    }

    /// Apply defaults, validate every invariant, and produce an immutable [`AuthConfig`].
    /// Returns `ConfigError::Invalid` for any constraint violation.
    pub fn build(self) -> Result<AuthConfig, ConfigError> {
        let cookie_name_suffix = self.cookie_name_suffix.unwrap_or_else(|| "session".into());
        let same_site = self.same_site.unwrap_or(SameSite::Strict);
        let session_sliding_ttl = self
            .session_sliding_ttl
            .unwrap_or(Duration::from_secs(7 * 24 * 60 * 60));
        let session_absolute_ttl = self
            .session_absolute_ttl
            .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60));
        let session_refresh_threshold = self
            .session_refresh_threshold
            .unwrap_or(Duration::from_secs(24 * 60 * 60));
        let magic_link_ttl = self.magic_link_ttl.unwrap_or(Duration::from_secs(15 * 60));
        let code_ttl = self.code_ttl.unwrap_or(Duration::from_secs(15 * 60));
        let issue_per_email_cap = self.issue_per_email_cap.unwrap_or(15);
        let issue_per_ip_cap = self.issue_per_ip_cap.unwrap_or(15);
        let issue_window = self.issue_window.unwrap_or(Duration::from_secs(30 * 60));
        let issue_block_duration = self
            .issue_block_duration
            .unwrap_or(Duration::from_secs(30 * 60));
        let ip_permanent_block_threshold = self.ip_permanent_block_threshold.unwrap_or(3);
        let verify_per_ip_per_min_cap = self.verify_per_ip_per_min_cap.unwrap_or(30);
        let code_failures_per_email_24h_cap = self.code_failures_per_email_24h_cap.unwrap_or(0);
        let code_attempts_per_row = self.code_attempts_per_row.unwrap_or(5);
        let link_attempts_per_token = self.link_attempts_per_token.unwrap_or(3);
        // Fail-secure default: disposable-domain blocklist (~5400 entries) is ON.
        // Opt out explicitly with `.policy(Arc::new(AllowAll))` for invite-only / B2B
        // setups where every signup must already be in the consumer's allowlist anyway.
        let policy = self
            .policy
            .unwrap_or_else(|| Arc::new(DisposableBlocklist::with_default_list()));
        let event_sink = self.event_sink.unwrap_or_else(|| Arc::new(NoOpSink));
        let log_full_email = self.log_full_email.unwrap_or(false);

        // ── single-field range checks ───────────────────────────────────────
        if magic_link_ttl.is_zero() {
            return Err(ConfigError::Invalid("magic_link_ttl must be > 0".into()));
        }
        if code_ttl.is_zero() {
            return Err(ConfigError::Invalid("code_ttl must be > 0".into()));
        }
        if session_sliding_ttl.is_zero() {
            return Err(ConfigError::Invalid(
                "session_sliding_ttl must be > 0".into(),
            ));
        }
        if session_refresh_threshold.is_zero() {
            return Err(ConfigError::Invalid(
                "session_refresh_threshold must be > 0".into(),
            ));
        }
        if issue_block_duration.is_zero() {
            return Err(ConfigError::Invalid(
                "issue_block_duration must be > 0".into(),
            ));
        }
        // Sanity range — DB no longer enforces an upper bound (config is source of truth),
        // but anything > 10 is OTP-policy nonsense and likely a typo.
        if !(1..=10).contains(&code_attempts_per_row) {
            return Err(ConfigError::Invalid(format!(
                "code_attempts_per_row must be in 1..=10, got {code_attempts_per_row}"
            )));
        }
        if !(1..=10).contains(&link_attempts_per_token) {
            return Err(ConfigError::Invalid(format!(
                "link_attempts_per_token must be in 1..=10, got {link_attempts_per_token}"
            )));
        }
        if issue_window < Duration::from_secs(60) {
            return Err(ConfigError::Invalid(format!(
                "issue_window must be >= 60s, got {}s",
                issue_window.as_secs()
            )));
        }
        if cookie_name_suffix.is_empty() {
            return Err(ConfigError::Invalid(
                "cookie_name_suffix must be non-empty".into(),
            ));
        }

        // ── cross-field invariants ──────────────────────────────────────────
        if code_ttl > magic_link_ttl {
            return Err(ConfigError::Invalid(format!(
                "code_ttl ({}s) must be <= magic_link_ttl ({}s) — DB CHECK constraint enforces this",
                code_ttl.as_secs(),
                magic_link_ttl.as_secs(),
            )));
        }
        if session_sliding_ttl > session_absolute_ttl {
            return Err(ConfigError::Invalid(format!(
                "session_sliding_ttl ({}s) must be <= session_absolute_ttl ({}s)",
                session_sliding_ttl.as_secs(),
                session_absolute_ttl.as_secs(),
            )));
        }
        if session_refresh_threshold >= session_sliding_ttl {
            return Err(ConfigError::Invalid(format!(
                "session_refresh_threshold ({}s) must be < session_sliding_ttl ({}s)",
                session_refresh_threshold.as_secs(),
                session_sliding_ttl.as_secs(),
            )));
        }

        Ok(AuthConfig {
            cookie_name_suffix,
            same_site,
            session_sliding_ttl,
            session_absolute_ttl,
            session_refresh_threshold,
            magic_link_ttl,
            code_ttl,
            issue_per_email_cap,
            issue_per_ip_cap,
            issue_window,
            issue_block_duration,
            ip_permanent_block_threshold,
            verify_per_ip_per_min_cap,
            code_failures_per_email_24h_cap,
            code_attempts_per_row,
            link_attempts_per_token,
            token_pepper: self.pepper,
            policy,
            event_sink,
            log_full_email,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pepper() -> Pepper {
        Pepper::from_bytes([0u8; 32])
    }

    #[test]
    fn cookie_name_has_host_prefix() {
        let cfg = AuthConfig::builder_from_pepper(test_pepper())
            .build()
            .unwrap();
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
        let cfg = AuthConfig::builder_from_pepper(test_pepper())
            .build()
            .unwrap();
        assert_eq!(cfg.same_site(), SameSite::Strict);
        assert_eq!(
            cfg.session_sliding_ttl(),
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(cfg.issue_per_email_cap(), 15);
        assert_eq!(cfg.issue_per_ip_cap(), 15);
        assert_eq!(cfg.issue_window(), Duration::from_secs(30 * 60));
        assert_eq!(cfg.issue_block_duration(), Duration::from_secs(30 * 60));
        assert_eq!(cfg.ip_permanent_block_threshold(), 3);
        assert_eq!(
            cfg.code_failures_per_email_24h_cap(),
            0,
            "lockout disabled by default"
        );
        assert_eq!(cfg.code_attempts_per_row(), 5);
        assert_eq!(cfg.link_attempts_per_token(), 3);
        assert_eq!(cfg.magic_link_ttl(), Duration::from_secs(15 * 60));
        assert_eq!(cfg.code_ttl(), Duration::from_secs(15 * 60));
    }

    #[tokio::test]
    async fn default_policy_blocks_disposable() {
        // Regression guard: default policy must be DisposableBlocklist (fail-secure),
        // not AllowAll. If somebody flips this back to AllowAll, this test trips.
        let cfg = AuthConfig::builder_from_pepper(test_pepper())
            .build()
            .unwrap();
        assert_eq!(cfg.policy().name(), "DisposableBlocklist");
        let bad = crate::core::Email::try_from("user@mailinator.com".to_string()).unwrap();
        assert!(
            !cfg.policy().allow(&bad).await,
            "default policy must reject known disposable domain"
        );
    }

    #[test]
    fn pepper_from_base64_decodes_valid() {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        assert!(Pepper::from_base64(&b64).is_ok());
    }

    #[test]
    fn pepper_from_base64_rejects_wrong_length() {
        let too_short =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 16]);
        assert!(Pepper::from_base64(&too_short).is_err());
        let too_long =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        assert!(Pepper::from_base64(&too_long).is_err());
    }

    #[test]
    fn pepper_from_base64_rejects_invalid_base64() {
        assert!(Pepper::from_base64("not!valid!base64!").is_err());
    }

    #[test]
    fn builder_with_valid_b64_pepper() {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [42u8; 32]);
        let cfg = AuthConfig::builder(&b64).unwrap().build().unwrap();
        assert_eq!(cfg.cookie_name(), "__Host-session");
    }

    #[test]
    fn builder_rejects_bad_pepper() {
        assert!(AuthConfig::builder("garbage").is_err());
    }

    // ── cross-field validation tests ────────────────────────────────────────

    #[test]
    fn rejects_code_ttl_exceeding_link_ttl() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .magic_link_ttl(Duration::from_secs(60))
            .code_ttl(Duration::from_secs(120))
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("code_ttl")));
    }

    #[test]
    fn rejects_session_sliding_above_absolute() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .session_sliding_ttl(Duration::from_secs(100))
            .session_absolute_ttl(Duration::from_secs(50))
            .session_refresh_threshold(Duration::from_secs(10))
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("sliding")));
    }

    #[test]
    fn rejects_refresh_threshold_above_sliding() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .session_sliding_ttl(Duration::from_secs(100))
            .session_refresh_threshold(Duration::from_secs(100))
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("refresh_threshold")));
    }

    #[test]
    fn rejects_zero_magic_link_ttl() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .magic_link_ttl(Duration::ZERO)
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("magic_link_ttl")));
    }

    #[test]
    fn rejects_code_attempts_per_row_out_of_range() {
        for bad in [0u8, 11, 50, 255] {
            let r = AuthConfig::builder_from_pepper(test_pepper())
                .code_attempts_per_row(bad)
                .build();
            assert!(
                matches!(r, Err(ConfigError::Invalid(_))),
                "expected error for {bad}"
            );
        }
        for ok in [1u8, 5, 10] {
            let r = AuthConfig::builder_from_pepper(test_pepper())
                .code_attempts_per_row(ok)
                .build();
            assert!(r.is_ok(), "expected ok for {ok}");
        }
    }

    #[test]
    fn rejects_link_attempts_per_token_out_of_range() {
        for bad in [0u8, 11, 50, 255] {
            let r = AuthConfig::builder_from_pepper(test_pepper())
                .link_attempts_per_token(bad)
                .build();
            assert!(
                matches!(r, Err(ConfigError::Invalid(_))),
                "expected error for {bad}"
            );
        }
        for ok in [1u8, 3, 10] {
            let r = AuthConfig::builder_from_pepper(test_pepper())
                .link_attempts_per_token(ok)
                .build();
            assert!(r.is_ok(), "expected ok for {ok}");
        }
    }

    #[test]
    fn rejects_short_issue_window() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .issue_window(Duration::from_secs(30))
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("issue_window")));
    }

    #[test]
    fn rejects_empty_cookie_name_suffix() {
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .cookie_name_suffix("")
            .build();
        assert!(matches!(r, Err(ConfigError::Invalid(s)) if s.contains("cookie_name_suffix")));
    }

    #[test]
    fn equal_session_sliding_and_absolute_is_ok() {
        let dur = Duration::from_secs(7 * 24 * 60 * 60);
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .session_sliding_ttl(dur)
            .session_absolute_ttl(dur)
            .session_refresh_threshold(Duration::from_secs(60))
            .build();
        assert!(r.is_ok());
    }

    #[test]
    fn equal_code_and_link_ttl_is_ok() {
        let dur = Duration::from_secs(15 * 60);
        let r = AuthConfig::builder_from_pepper(test_pepper())
            .magic_link_ttl(dur)
            .code_ttl(dur)
            .build();
        assert!(r.is_ok());
    }
}
