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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::header::HeaderMap;
use serde::Deserialize;

use crate::core::{Email, IdentityError, IdentityProvider, VerifiedIdentity};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS_ALLOWED: &[&str] = &["accounts.google.com", "https://accounts.google.com"];

/// The single algorithm Google ever uses for id_tokens. Hardcoded — never
/// derive from the token header. Skipping this whitelist enables `alg=none`
/// and RS256↔HS256 confusion attacks.
const ALLOWED_ALGS: &[Algorithm] = &[Algorithm::RS256];

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
    /// at a time even under a flood of unknown-kid tokens. After acquiring the
    /// lock, refreshers re-check cache freshness; the loser of the race exits
    /// without a second fetch.
    refresh_lock: tokio::sync::Mutex<()>,
    /// Timestamp of the last failed refresh. Subsequent refreshes within
    /// `FAILED_REFRESH_COOLDOWN` short-circuit to `Transient`, preventing a
    /// flood of unknown-kid tokens from DoS-ing the JWKS endpoint via us.
    last_failed_refresh: tokio::sync::Mutex<Option<Instant>>,
}

/// How long a failed refresh suppresses retries. Short enough that a real
/// outage clears quickly; long enough that a bot replaying invalid tokens
/// can't trigger N hits per second.
const FAILED_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
/// Fallback when the response has no parseable `Cache-Control: max-age`.
/// Google sets ~6h in practice; 1h is the conservative default.
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);

/// Snapshot of the JWKS state — keys plus the moment they were fetched and the
/// TTL we derived from `Cache-Control: max-age` on the response.
struct JwksState {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
    ttl: Duration,
}

impl JwksState {
    fn is_fresh(&self) -> bool {
        // ttl == 0 sentinels the initial empty state — always stale.
        self.ttl > Duration::ZERO && self.fetched_at.elapsed() <= self.ttl
    }
}

impl JwksState {
    /// Empty initial state — the first verify call triggers a fetch.
    fn empty() -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
            ttl: Duration::ZERO,
        }
    }
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

#[derive(Deserialize)]
struct JwkEntry {
    kid: String,
    /// Optional in the JWK spec; Google sets `"RS256"`. Used as a belt-and-braces
    /// filter to drop any non-RS256 keys before they reach the cache.
    #[serde(default)]
    alg: Option<String>,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    email: String,
    email_verified: bool,
    /// Pulled for completeness; iss/aud/exp are validated by `Validation`.
    name: Option<String>,
    picture: Option<String>,
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

    /// Look up a kid only if the cache is still within its TTL window.
    /// A stale cache returns None, forcing the caller to refresh — this is how
    /// `Cache-Control: max-age` expiry triggers the next fetch.
    async fn lookup_key_fresh(&self, kid: &str) -> Option<DecodingKey> {
        let state = self.jwks.read().await;
        if !state.is_fresh() {
            return None;
        }
        state.keys.get(kid).cloned()
    }

    /// Fetch JWKS, gated by:
    /// - cooldown: a recent failure short-circuits to `Transient`,
    /// - lock: only one refresh runs at a time across concurrent verifies,
    /// - re-check: after acquiring the lock, the loser of the race sees the
    ///   winner's fresh cache and returns without a second HTTP call.
    async fn refresh_jwks(&self) -> Result<(), IdentityError> {
        // 1. DoS-cooldown — checked WITHOUT holding the refresh_lock so that
        //    cooldown decisions don't serialize on the lock.
        if let Some(t) = *self.last_failed_refresh.lock().await
            && t.elapsed() < FAILED_REFRESH_COOLDOWN
        {
            return Err(IdentityError::Transient("jwks refresh in cooldown".into()));
        }

        // 2. Capture call-start timestamp BEFORE waiting for the lock — used
        //    by the post-lock re-check to detect whether another refresher
        //    completed while we were queued.
        let started = Instant::now();
        let _guard = self.refresh_lock.lock().await;

        // 3. Lock-acquired re-check: if cache was updated AFTER we started
        //    queueing, another refresher beat us to it — exit without a
        //    second HTTP call. We compare timestamps (not is_fresh()) because
        //    `is_fresh()` is true for hours after a successful fetch, which
        //    would suppress legitimate refreshes triggered by an unknown kid.
        if self.jwks.read().await.fetched_at > started {
            return Ok(());
        }

        // 4. Actual fetch + state update; on any failure, record the timestamp
        //    so the cooldown trips on the next caller.
        match self.do_fetch_jwks().await {
            Ok(()) => {
                *self.last_failed_refresh.lock().await = None;
                Ok(())
            }
            Err(e) => {
                *self.last_failed_refresh.lock().await = Some(Instant::now());
                Err(e)
            }
        }
    }

    async fn do_fetch_jwks(&self) -> Result<(), IdentityError> {
        let resp = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| IdentityError::Transient(format!("jwks fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(IdentityError::Transient(format!(
                "jwks fetch: HTTP {}",
                resp.status()
            )));
        }
        let ttl = parse_max_age(resp.headers()).unwrap_or(DEFAULT_JWKS_TTL);
        let body: JwksResponse = resp
            .json()
            .await
            .map_err(|e| IdentityError::Transient(format!("jwks parse: {e}")))?;

        let mut keys = HashMap::with_capacity(body.keys.len());
        for jwk in body.keys {
            // Drop any non-RS256 keys defensively — Google only serves RS256,
            // but a future spec change should not silently widen what we accept.
            if jwk.alg.as_deref().is_some_and(|a| a != "RS256") {
                continue;
            }
            let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|e| IdentityError::Transient(format!("decode key {}: {e}", jwk.kid)))?;
            keys.insert(jwk.kid, key);
        }

        let mut state = self.jwks.write().await;
        state.keys = keys;
        state.fetched_at = Instant::now();
        state.ttl = ttl;
        Ok(())
    }

    pub(crate) async fn verify_inner(
        &self,
        raw_token: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        // 1. Header inspection — algorithm whitelist BEFORE any crypto.
        //    `decode_header` already rejects `alg=none` because jsonwebtoken
        //    10.x removed the variant from the Algorithm enum entirely; this
        //    explicit check is defense-in-depth against future API changes.
        let header = decode_header(raw_token)
            .map_err(|e| IdentityError::Invalid(format!("malformed jwt header: {e}")))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(IdentityError::Invalid(format!(
                "alg not allowed: {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| IdentityError::Invalid("missing kid".into()))?;

        // 2. Key lookup — refresh the JWKS once on miss (or stale cache).
        let key = match self.lookup_key_fresh(&kid).await {
            Some(k) => k,
            None => {
                self.refresh_jwks().await?;
                // Post-refresh lookup ignores TTL freshness — we just fetched.
                self.jwks
                    .read()
                    .await
                    .keys
                    .get(&kid)
                    .cloned()
                    .ok_or_else(|| IdentityError::Invalid(format!("unknown kid: {kid}")))?
            }
        };

        // 3. Validate signature + standard claims.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(self.iss_allowed);
        validation.validate_exp = true;
        validation.leeway = 30;

        let token_data = decode::<Claims>(raw_token, &key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind::*;
            let reason = match e.kind() {
                ExpiredSignature => "expired",
                InvalidAudience => "invalid audience",
                InvalidIssuer => "invalid issuer",
                InvalidSignature => "bad signature",
                InvalidAlgorithm | InvalidAlgorithmName => "alg mismatch",
                _ => "jwt validation failed",
            };
            IdentityError::Invalid(reason.into())
        })?;

        // 4. email_verified gate — Google sets `false` for accounts where it
        //    does not control the mailbox; we never trust those for sign-in.
        if !token_data.claims.email_verified {
            return Err(IdentityError::EmailNotVerified);
        }

        // 5. Build VerifiedIdentity. Email format is enforced by `Email::try_from`.
        let email = Email::try_from(token_data.claims.email)
            .map_err(|e| IdentityError::Invalid(format!("malformed email claim: {e:?}")))?;

        Ok(VerifiedIdentity {
            provider: "google",
            subject: token_data.claims.sub,
            email,
            email_verified: true,
            display_name: token_data.claims.name,
            picture_url: token_data.claims.picture,
        })
    }
}

/// Extract `max-age=N` (in seconds) from a `Cache-Control` header. Returns
/// `None` if absent or malformed; callers fall back to `DEFAULT_JWKS_TTL`.
fn parse_max_age(headers: &HeaderMap) -> Option<Duration> {
    let cc = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=")
            && let Ok(n) = rest.parse::<u64>()
        {
            return Some(Duration::from_secs(n));
        }
    }
    None
}

#[async_trait]
impl IdentityProvider for GoogleIdTokenVerifier {
    fn provider_id(&self) -> &'static str {
        "google"
    }

    async fn verify(&self, raw_token: &str) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_inner(raw_token).await
    }
}
