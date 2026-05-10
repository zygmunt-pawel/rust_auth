//! Google Sign-In identity provider — id_token (JWT) verification.
//!
//! Frontend (GIS / mobile SDK / One Tap) hands the backend a Google-issued
//! `id_token`. This verifier validates it locally against Google's published
//! JWKS, with a TTL cache + concurrent-refresh dedup. No `client_secret`,
//! no token endpoint round-trip — pure in-process validation.
//!
//! Security invariants enforced:
//! - Algorithm whitelisted to RS256 (no `alg=none`, no RS↔HS confusion).
//! - `iss` ∈ `{accounts.google.com, https://accounts.google.com}`.
//! - `aud == audience` (your OAuth client_id).
//! - `exp` checked with 30 s leeway.
//! - `email_verified == true` (otherwise `IdentityError::EmailNotVerified`).
//!
//! JWKS validation logic and the `IdentityProvider` impl land in subsequent
//! commits; this module currently only scaffolds the struct.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::{IdentityError, VerifiedIdentity};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS_ALLOWED: &[&str] = &["accounts.google.com", "https://accounts.google.com"];

/// Verifier for Google-issued OIDC `id_token` JWTs.
///
/// Construct once at startup and share via `Arc` — the struct is internally
/// synchronized and the JWKS cache is shared across all verify calls.
pub struct GoogleIdTokenVerifier {
    /// OAuth 2.0 client_id we expect in the `aud` claim. Without this match,
    /// any other Google-integrated app's id_token would authenticate against us.
    audience: String,
    http: reqwest::Client,
    /// Pinned upstream JWKS URL. Public field only via the test-only
    /// `with_jwks_url` constructor — production callers always hit Google.
    jwks_url: String,
    /// `iss` claim values we accept. Hardcoded to Google's two canonical forms.
    iss_allowed: &'static [&'static str],
    jwks: tokio::sync::RwLock<JwksState>,
    /// Serializes concurrent JWKS refreshes — only one `GET /certs` in flight
    /// at a time even under a flood of unknown-kid tokens.
    refresh_lock: tokio::sync::Mutex<()>,
    /// Timestamp of the last failed refresh. Subsequent refreshes within the
    /// cooldown window short-circuit to `Transient`, preventing a flood of
    /// invalid tokens from DoS-ing Google's JWKS endpoint via us.
    last_failed_refresh: tokio::sync::Mutex<Option<Instant>>,
}

/// Snapshot of the JWKS state — keys plus the moment they were fetched and the
/// TTL we derived from `Cache-Control: max-age` on the response.
pub(crate) struct JwksState {
    pub(crate) keys: HashMap<String, jsonwebtoken::DecodingKey>,
    pub(crate) fetched_at: Instant,
    pub(crate) ttl: Duration,
}

impl JwksState {
    /// Empty initial state — `fetched_at` is set to a moment so far in the past
    /// that any TTL check treats it as expired, forcing the first verify to
    /// trigger a fetch.
    fn empty() -> Self {
        Self {
            keys: HashMap::new(),
            // Instant::now() - very large duration would underflow; pick a TTL
            // of zero so any check `fetched_at + ttl > now` is false.
            fetched_at: Instant::now(),
            ttl: Duration::ZERO,
        }
    }
}

impl GoogleIdTokenVerifier {
    /// Build a verifier pointed at Google's production JWKS endpoint.
    /// `audience` is your OAuth 2.0 client_id from Google Cloud Console.
    pub fn new(audience: impl Into<String>) -> Self {
        Self::build(audience.into(), GOOGLE_JWKS_URL.to_string())
    }

    /// Test-only constructor — points the verifier at a custom JWKS URL
    /// (typically a `wiremock::MockServer`). Not part of the stable public
    /// surface; do not rely on it in production code.
    #[doc(hidden)]
    pub fn with_jwks_url(audience: impl Into<String>, jwks_url: impl Into<String>) -> Self {
        Self::build(audience.into(), jwks_url.into())
    }

    fn build(audience: String, jwks_url: String) -> Self {
        Self {
            audience,
            http: reqwest::Client::new(),
            jwks_url,
            iss_allowed: GOOGLE_ISS_ALLOWED,
            jwks: tokio::sync::RwLock::new(JwksState::empty()),
            refresh_lock: tokio::sync::Mutex::new(()),
            last_failed_refresh: tokio::sync::Mutex::new(None),
        }
    }

    pub(crate) async fn verify_inner(&self, _raw_token: &str) -> Result<VerifiedIdentity, IdentityError> {
        // Real implementation lands in the next task (JWT validation).
        Err(IdentityError::Invalid("verifier not yet implemented".into()))
    }
}
