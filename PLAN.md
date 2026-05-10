# Sign in with Google — implementation plan (v0.2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Google Sign-In to `auth_rust` as a first-class auth path next to magic-link, with a provider-agnostic core ready for Apple/GitHub later.

**Architecture:** New `IdentityProvider` trait + `auth_identities` table. Orchestration in `complete_identity_login()` reuses the existing `UserResolver` and `create_session()`. Google verifier is feature-gated (`--features google`); default build adds zero new deps.

**Tech stack:** sqlx + Postgres (existing), `reqwest` (rustls, optional), `jsonwebtoken` 10.x (optional), `wiremock` (dev-deps for HTTP mocking).

**Working directory:** `/Users/pawel/workspace/rust_packages/rust_auth/` — current branch (no worktree, no merge complications since we touch a fresh feature surface only).

---

## File map

**Created:**
- `src/core/identity.rs` — `IdentityProvider` trait, `VerifiedIdentity`, `IdentityError`
- `src/providers/mod.rs` — submodule root, gated `pub mod google;` behind `feature = "google"`
- `src/providers/google.rs` — `GoogleIdTokenVerifier` + JWKS cache
- `src/store/identity.rs` — `complete_identity_login` orchestration
- `tests/google_verifier.rs` — unit-ish integration tests for the Google JWT validator (mocked JWKS via `wiremock`)
- `tests/identity_login.rs` — orchestration tests with stub `IdentityProvider`
- `tests/google_real_token.rs` — `#[ignore]`-d manual smoke test against real Google id_token

**Modified:**
- `Cargo.toml` — add `[features] google = [...]`, optional deps, dev-dep `wiremock`
- `migrations/20260501000000_auth_init.up.sql` — append `auth_identities` block
- `migrations/20260501000000_auth_init.down.sql` — prepend `DROP TABLE auth_identities`
- `src/lib.rs` — `pub mod providers;` (always present, contents gated)
- `src/core/mod.rs` — `pub mod identity;` + re-exports
- `src/core/traits.rs` — extend `SessionEvent` with `IdentityLinked`
- `src/store/mod.rs` — `mod identity;` + `pub use identity::complete_identity_login;`
- `tests/migrate.rs` — assert `auth_identities` table + index exist after migration
- `README.md` — new "Sign in with Google" section before FAQ

---

## Task 1: Migration — `auth_identities` table

**Files:**
- Modify: `migrations/20260501000000_auth_init.up.sql` (append at end)
- Modify: `migrations/20260501000000_auth_init.down.sql` (prepend — must drop before `users`)
- Modify: `tests/migrate.rs` (extend existing test)

**What:**
- UP: append the `auth_identities` block from the spec — `BIGINT GENERATED ALWAYS AS IDENTITY` PK, `user_id` FK with `ON DELETE CASCADE`, `provider TEXT`, `subject TEXT`, `email_at_link TEXT` (with email format CHECK matching the existing `users` constraint), `created_at`, `last_login_at`, `UNIQUE (provider, subject)`, `INDEX (user_id)`.
- DOWN: prepend `DROP TABLE IF EXISTS auth_identities;`.

**Tests (`tests/migrate.rs`):**
- Existing test runs the migrator. Add assertions:
  - `SELECT to_regclass('auth_identities')` is non-null
  - `SELECT indexname FROM pg_indexes WHERE tablename = 'auth_identities'` contains `idx_auth_identities_user`
  - `SELECT conname FROM pg_constraint WHERE conrelid = 'auth_identities'::regclass` includes `auth_identities_provider_subject_uniq`

**Done when:** `cargo test --test migrate` passes against a fresh test DB.

**Commit:** `feat(migration): add auth_identities table for external identity linking`

---

## Task 2: Core types — `IdentityProvider`, `VerifiedIdentity`, `IdentityError`

**Files:**
- Create: `src/core/identity.rs`
- Modify: `src/core/mod.rs` (`pub mod identity;` + re-exports)

**Contracts (`src/core/identity.rs`):**

```rust
#[async_trait]
pub trait IdentityProvider: Send + Sync + 'static {
    fn provider_id(&self) -> &'static str;          // "google", "apple", ...
    async fn verify(&self, raw_token: &str) -> Result<VerifiedIdentity, IdentityError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub provider: &'static str,
    pub subject: String,
    pub email: Email,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("token invalid: {0}")] Invalid(String),
    #[error("email not verified by provider")] EmailNotVerified,
    #[error("provider transient error: {0}")] Transient(String),
}
```

Re-export from `core::mod.rs` so `auth_rust::core::IdentityProvider` is the public path.

**Tests:** none at this level — pure types with no runtime. Compile-only.

**Done when:** `cargo build` and `cargo doc --no-deps` pass.

**Commit:** `feat(core): add IdentityProvider trait + VerifiedIdentity + IdentityError`

---

## Task 3: Audit event — `SessionEvent::IdentityLinked`

**Files:**
- Modify: `src/core/traits.rs` (extend enum)

**Contract:**

```rust
pub enum SessionEvent {
    // existing variants unchanged
    IdentityLinked { user_id: i64, provider: &'static str, subject: String },
}
```

`NoOpSink` impl already uses `_event` — no change needed there.

**Tests:** rely on the integration tests in Task 8 to cover emission. Just verify `cargo build` to confirm the existing `match`-on-`SessionEvent` in cleanup.rs / session.rs / verify.rs has no exhaustive-match obligation broken (audit at write time — if any `match` doesn't have wildcard arm, add one or extend it explicitly).

**Done when:** `cargo build --all-targets` clean, `cargo clippy --all-targets -- -D warnings` clean.

**Commit:** `feat(events): add SessionEvent::IdentityLinked variant`

---

## Task 4: Cargo features — `google` flag + optional deps

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs` (add `pub mod providers;`)
- Create: `src/providers/mod.rs` (skeleton)

**`Cargo.toml`:**

```toml
[features]
default = []
google = ["dep:reqwest", "dep:jsonwebtoken"]

[dependencies]
# existing deps unchanged
reqwest = { version = "=0.13.3", default-features = false, features = ["rustls-tls", "json"], optional = true }
jsonwebtoken = { version = "=10.3.0", default-features = false, optional = true }

[dev-dependencies]
# existing dev-deps unchanged
wiremock = "=0.6.5"
rsa = { version = "=0.9.6", features = ["sha2"] }    # generate RSA keypair in google_verifier tests (mint signed JWTs against mocked JWKS)
```

(Versions follow the repo's `=N.N.N` exact-pin convention. If `cargo update` reveals a newer patch, bump together.)

**`src/providers/mod.rs`:**

```rust
#[cfg(feature = "google")]
pub mod google;
```

**`src/lib.rs`:**

```rust
pub mod core;
pub mod providers;   // gated contents inside
pub mod store;
```

**Tests:**
- `cargo build` (default features) — must NOT pull `reqwest` / `jsonwebtoken` into the dep graph. Verify with `cargo tree | grep -E 'reqwest|jsonwebtoken'` returning empty.
- `cargo build --features google` — must succeed.
- `cargo test --no-default-features` — sanity: no test references gated paths unconditionally.

**Done when:** all three commands pass.

**Commit:** `feat(features): add google feature flag + optional reqwest/jsonwebtoken deps`

---

## Task 5: Google verifier — struct + JWKS cache scaffolding

**Files:**
- Modify: `src/providers/google.rs` (was empty after Task 4)

**Contract:**

```rust
pub struct GoogleIdTokenVerifier {
    audience: String,
    http: reqwest::Client,
    jwks_url: String,            // injectable for tests; default https://www.googleapis.com/oauth2/v3/certs
    iss_allowed: &'static [&'static str], // ["accounts.google.com", "https://accounts.google.com"]
    jwks: tokio::sync::RwLock<JwksState>,
    refresh_lock: tokio::sync::Mutex<()>,
    last_failed_refresh: tokio::sync::Mutex<Option<std::time::Instant>>, // DoS dedupe
}

struct JwksState {
    keys: std::collections::HashMap<String /*kid*/, jsonwebtoken::DecodingKey>,
    fetched_at: std::time::Instant,
    ttl: std::time::Duration,
}

impl GoogleIdTokenVerifier {
    pub fn new(audience: impl Into<String>) -> Self { /* default URL */ }

    /// Test-only constructor — lets tests point at a wiremock server.
    #[doc(hidden)]
    pub fn with_jwks_url(audience: impl Into<String>, jwks_url: impl Into<String>) -> Self { ... }
}
```

Empty `verify()` returning `Err(IdentityError::Invalid("not implemented".into()))` — body lands in Task 6.

**Tests:** none yet (real validation in Task 6).

**Done when:** `cargo build --features google` passes.

**Commit:** `feat(google): scaffold GoogleIdTokenVerifier struct + JWKS state`

---

## Task 6: Google verifier — JWT validation logic (mocked JWKS)

**Files:**
- Modify: `src/providers/google.rs` (implement `verify()` and `IdentityProvider` impl)
- Create: `tests/google_verifier.rs`

**Implementation contract for `verify(raw_token)`:**

1. Parse header via `jsonwebtoken::decode_header(raw_token)`.
2. If `header.alg != Algorithm::RS256` → `Err(Invalid("alg not allowed"))`. Hardcoded whitelist, no per-call config.
3. Pull `kid` from header; on missing → `Err(Invalid("missing kid"))`.
4. Lookup key in `self.jwks.read().keys`. If miss → call `refresh_jwks()` (Task 7); after refresh re-read; still miss → `Err(Invalid("unknown kid"))`.
5. Build `Validation`:
   ```rust
   let mut v = Validation::new(Algorithm::RS256);
   v.set_audience(&[&self.audience]);
   v.set_issuer(self.iss_allowed);
   v.validate_exp = true;
   v.leeway = 30;
   v.required_spec_claims = ["exp", "iss", "aud", "sub"].iter().map(|s| s.to_string()).collect();
   ```
6. `decode::<Claims>` with `Validation` → maps `ErrorKind::ExpiredSignature` → `Invalid("expired")`, `InvalidAudience`/`InvalidIssuer` → `Invalid(...)`, `InvalidSignature` → `Invalid("bad signature")`.
7. `if !claims.email_verified { return Err(EmailNotVerified) }`.
8. Build `Email::try_from(claims.email)` (existing type) — failure → `Invalid("malformed email claim")`.
9. Return `VerifiedIdentity { provider: "google", subject: claims.sub, email, email_verified: true, display_name: claims.name, picture_url: claims.picture }`.

`Claims` struct (private):

```rust
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    email: String,
    email_verified: bool,
    iss: String,            // validated by `Validation`
    aud: String,            // validated by `Validation`
    exp: i64,               // validated by `Validation`
    name: Option<String>,
    picture: Option<String>,
    azp: Option<String>,
    hd: Option<String>,
}
```

`IdentityProvider` impl: `provider_id() -> "google"`, `verify` delegates to inherent method.

**Tests (`tests/google_verifier.rs`, gated `#[cfg(feature = "google")]`):**

Setup helper: spin up `wiremock::MockServer`. Generate an RSA-2048 keypair once per test process via `rsa::RsaPrivateKey::new(&mut rng, 2048)` (the `rsa` dev-dep added in Task 4). Convert public components to base64url for the JWKS JSON (`{"kid": "test-kid-1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "...", "e": "AQAB"}`). Convert private key to PEM and load into `jsonwebtoken::EncodingKey::from_rsa_pem` for minting. Helper signature: `fn mint_token(claims: serde_json::Value, kid: &str, alg: Algorithm) -> String` so individual tests can inject bad `alg` / wrong `kid` / etc.

Tests:
- `happy_path_returns_verified_identity` — well-formed token → `VerifiedIdentity { provider: "google", subject: "sub-123", email: "alice@example.com", email_verified: true, ... }`
- `wrong_audience_rejected` — token with `aud = "other-client"` → `Invalid`
- `wrong_issuer_rejected` — `iss = "https://accounts.example.com"` → `Invalid`
- `expired_token_rejected` — `exp` 5 min ago → `Invalid`
- `email_not_verified_rejected` — `email_verified = false` → `EmailNotVerified` (not generic `Invalid`)
- `alg_none_rejected` — header `alg = none`, no signature → `Invalid` BEFORE any signature check
- `alg_hs256_rejected` — header `alg = HS256` (RS-HS confusion) → `Invalid`
- `unknown_kid_with_no_refresh_rejected` — kid not in initial JWKS, mock returns same JWKS on refresh → `Invalid`
- `malformed_token_rejected` — random string → `Invalid`

**Done when:** `cargo test --features google --test google_verifier` is green.

**Commit:** `feat(google): implement id_token validation (RS256, iss, aud, exp, email_verified)`

---

## Task 7: Google verifier — JWKS HTTP fetch + cache + dedup

**Files:**
- Modify: `src/providers/google.rs` (implement `refresh_jwks` and integrate)

**Contract:**

```rust
async fn refresh_jwks(&self) -> Result<(), IdentityError> {
    // DoS dedupe: if a refresh failed within the last 30s, short-circuit.
    if let Some(t) = *self.last_failed_refresh.lock().await {
        if t.elapsed() < Duration::from_secs(30) {
            return Err(IdentityError::Transient("jwks refresh in cooldown".into()));
        }
    }

    let _guard = self.refresh_lock.lock().await; // serialize concurrent refreshes

    // Re-check after acquiring the lock — another task may have just refreshed.
    if /* current state has a valid TTL window */ { return Ok(()); }

    let resp = self.http.get(&self.jwks_url).send().await
        .map_err(|e| IdentityError::Transient(format!("jwks fetch: {e}")))?;
    let ttl = parse_max_age(resp.headers()).unwrap_or(Duration::from_secs(3600));
    let body: JwksResponse = resp.json().await
        .map_err(|e| IdentityError::Transient(format!("jwks parse: {e}")))?;

    let mut keys = HashMap::new();
    for jwk in body.keys {
        if jwk.alg.as_deref() != Some("RS256") { continue; } // belt-and-braces filter
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| IdentityError::Transient(format!("decode key: {e}")))?;
        keys.insert(jwk.kid, key);
    }

    *self.jwks.write().await = JwksState { keys, fetched_at: Instant::now(), ttl };
    *self.last_failed_refresh.lock().await = None;
    Ok(())
}

fn parse_max_age(headers: &HeaderMap) -> Option<Duration> { /* Cache-Control: max-age=N */ }
```

Wire `verify()`'s "unknown kid" branch to `refresh_jwks()` then re-lookup. On JWKS fetch failure, set `last_failed_refresh = Some(now)` so 100 bad tokens don't hammer Google.

**Tests (extend `tests/google_verifier.rs`):**

- `unknown_kid_triggers_refresh_then_success` — initial JWKS has only `test-kid-1`; mint token with `kid = test-kid-2`; configure wiremock to return JWKS with both kids on second `GET /certs` → verify succeeds, mock recorded **2** GETs.
- `cache_hit_no_http_on_second_verify` — verify same token twice → mock recorded exactly **1** GET (the initial unknown-kid refresh).
- `concurrent_unknown_kid_dedupe_one_fetch` — spawn 50 `tokio::join!` of `verify()` with kid not yet in cache; mock returns updated JWKS → assert mock recorded **1** GET (refresh_lock serialized).
- `failed_refresh_cooldown_30s` — mock returns 500 on `GET /certs`; first verify with unknown kid → `Transient`; second verify with same unknown kid within 30s → returns `Transient` WITHOUT a second HTTP call (mock recorded 1 GET).
- `cache_control_max_age_respected` — mock returns JWKS with `Cache-Control: max-age=2`; first verify hits HTTP, sleep 3s (or use `tokio::time::pause`), second verify with same kid → second HTTP fetch recorded.

**Done when:** `cargo test --features google --test google_verifier` is green; `cargo clippy --features google -- -D warnings` clean.

**Commit:** `feat(google): JWKS fetch with TTL cache + concurrent-refresh dedup + DoS cooldown`

---

## Task 8: Public function — `complete_identity_login` orchestration

**Files:**
- Create: `src/store/identity.rs`
- Modify: `src/store/mod.rs` (`mod identity; pub use identity::complete_identity_login;`)
- Create: `tests/identity_login.rs`

**Contract:**

```rust
#[tracing::instrument(
    name = "auth.identity.login",
    skip_all,
    fields(
        provider = field::Empty,
        email = field::Empty,
        user_id = field::Empty,
        session_id = field::Empty,
        outcome = field::Empty,
        linked = field::Empty,
    ),
)]
pub async fn complete_identity_login(
    pool: &PgPool,
    provider: &dyn IdentityProvider,
    raw_token: &str,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &dyn UserResolver,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError>;
```

**Flow:**

1. `tracing::Span::current().record("provider", provider.provider_id());`
2. `let identity = provider.verify(raw_token).await.map_err(|e| { /* log + map */ })?;`
   - `IdentityError::EmailNotVerified` → record `outcome = "email_not_verified"`, `warn!`, `Err(AuthError::Unauthorized)`
   - `IdentityError::Invalid(msg)` → record `outcome = "invalid_token"`, debug log with `token_hash_prefix = sha256(raw_token)[..12]` (NOT the token), `Err(AuthError::Unauthorized)`
   - `IdentityError::Transient(msg)` → record `outcome = "provider_transient"`, `warn!`, `Err(AuthError::Internal(format!("identity provider transient: {msg}")))`
3. Record `email = identity.email.for_log(cfg.log_full_email)`.
4. Lookup existing identity:
   ```sql
   SELECT user_id FROM auth_identities WHERE provider = $1 AND subject = $2
   ```
5. **Hit:** `UPDATE auth_identities SET last_login_at = NOW() WHERE provider = $1 AND subject = $2`. Set `linked = false`.
6. **Miss:**
   - `let user_id = resolver.resolve_or_create(pool, &identity.email).await.map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;`
   - `INSERT INTO auth_identities (user_id, provider, subject, email_at_link) VALUES ($1, $2, $3, $4)` — note: no `ON CONFLICT` (we already checked); if INSERT races and hits the unique constraint, it's a real concurrency bug — surface as `AuthError::Internal`.
   - Set `linked = true`.
   - Emit `sink.on_event(SessionEvent::IdentityLinked { user_id: user_id.0, provider: identity.provider, subject: identity.subject.clone() }).await;`
7. Record `user_id`.
8. `let session = create_session(pool, user_id, ip, user_agent, cfg).await?;` — `create_session` is `pub(crate)`, accessible from `src/store/identity.rs` since same crate.
9. Record `session_id`.
10. `sink.on_event(SessionEvent::Created { session_id, user_id, ip, user_agent: ... }).await;`
11. Record `outcome = "success"`, `linked`. `tracing::info!(outcome = "success", linked, ...)`.
12. Return `(session.token, user_id)`.

**Tests (`tests/identity_login.rs`):**

Stub provider:

```rust
struct StubProvider { identity: VerifiedIdentity, fail: Option<IdentityError> }
#[async_trait]
impl IdentityProvider for StubProvider {
    fn provider_id(&self) -> &'static str { self.identity.provider }
    async fn verify(&self, _: &str) -> Result<VerifiedIdentity, IdentityError> {
        if let Some(e) = &self.fail { return Err(clone_err(e)); }
        Ok(self.identity.clone())
    }
}
```

Recording sink:

```rust
#[derive(Default)] struct RecSink { events: Mutex<Vec<SessionEvent>> }
#[async_trait] impl SessionEventSink for RecSink {
    async fn on_event(&self, e: SessionEvent) { self.events.lock().await.push(e); }
}
```

Cases:
- `(a) brand_new_user_creates_user_identity_and_session` — empty DB. After call: 1 `users` row with `email = identity.email`, 1 `auth_identities` row with matching `(provider, subject)`, 1 `sessions` row, sink saw `IdentityLinked` then `Created`, returned `UserId` matches.
- `(b) magic_link_user_then_google_same_email_links` — first `verify_magic_link_or_code` to create user `U`. Then `complete_identity_login` with `identity.email == U.email`. After: still 1 `users` row, identity row points to `U.id`, sink saw `IdentityLinked` + `Created`, returned `user_id == U.id`.
- `(c) second_google_login_reuses_identity` — repeat call (b) twice. Second call: no new identity row, `last_login_at` advanced, sink for second call saw ONLY `Created` (no `IdentityLinked`).
- `(d) different_email_creates_second_user` — first call creates user A (`alice@x.com`). Second call with `identity.email = bob@x.com` → second `users` row, second `auth_identities` row, distinct `user_id`.
- `(e) email_not_verified_returns_unauthorized` — stub provider returns `EmailNotVerified`. Result: `Err(AuthError::Unauthorized)`, no `users`/`auth_identities`/`sessions` rows inserted.
- `(f) invalid_token_returns_unauthorized` — stub returns `Invalid`. Same DB invariants as (e).
- `(g) two_providers_same_email_share_user` — call with `provider="google"` then with `provider="apple"` (stub) using the same email. Both identities link to the same `user_id` (resolver matches by email both times).

Use existing `tests/common/` helpers for DB setup if present (check `tests/common/mod.rs`).

**Done when:** `cargo test --test identity_login` green.

**Commit:** `feat(store): complete_identity_login orchestrates verify → link → session`

---

## Task 9: README — "Sign in with Google" section

**Files:**
- Modify: `README.md`

**Insert** between current "Customization" section and "Production deployment" section. Content:

- Heading `## Sign in with Google`
- Subsection "Requirements": OAuth 2.0 Client ID in Google Cloud Console (type: Web application), scopes `openid email profile`, frontend SDK that delivers the `id_token` (Google Identity Services with FedCM, or mobile Credential Manager).
- Subsection "Wire it up" with axum handler example matching `examples/axum.rs` style:
  ```rust
  use auth_rust::store::complete_identity_login;
  use auth_rust::providers::google::GoogleIdTokenVerifier;

  let google = Arc::new(GoogleIdTokenVerifier::new(env::var("GOOGLE_CLIENT_ID")?));

  async fn google_login(State(s): State<AppState>, ClientIp(ip): ClientIp,
                        ua: Option<TypedHeader<UserAgent>>, Json(body): Json<GoogleBody>)
      -> Result<impl IntoResponse, AuthError> {
      let (token, _user_id) = complete_identity_login(
          &s.pool, &*s.google, &body.id_token,
          ip, ua.as_deref(), &AutoSignupResolver, &s.cfg, &*s.sink).await?;
      let cookie = session_cookie_header_value(&token, &s.cfg);
      Ok(([(SET_COOKIE, cookie)], StatusCode::NO_CONTENT))
  }
  #[derive(Deserialize)] struct GoogleBody { id_token: String }
  ```
- Subsection "How it links to magic-link accounts":
  - Same email on Google and previous magic-link → one account (auto-link via `UserResolver`).
  - Different email → two distinct accounts. Intentional — no UI for merging.
- Subsection "Cargo features": `auth_rust = { …, features = ["google"] }`. Default build is unchanged.
- Subsection "Out of scope (v0.2)": Authorization Code flow / `client_secret` / `refresh_token` (use frontend GIS — backend never speaks to Google's token endpoint), manual account linking, account merge, providers other than Google.

Update **Features** bullet list near the top: append `- ✅ Sign in with Google (id_token verification, JWKS-cached, auto-link to magic-link accounts on matching email)`.

**Tests:** none. Skim-read in IDE; ensure code blocks compile-quote-style matches the rest of README.

**Done when:** `cargo doc --no-deps` still passes (markdown in README isn't compiled but checks consistency).

**Commit:** `docs(readme): document Sign in with Google integration`

---

## Task 10: Manual smoke test — real Google id_token

**Files:**
- Create: `tests/google_real_token.rs`

**Contract:**

```rust
#![cfg(feature = "google")]

use auth_rust::core::IdentityProvider;
use auth_rust::providers::google::GoogleIdTokenVerifier;

#[tokio::test]
#[ignore = "manual: needs GOOGLE_CLIENT_ID + GOOGLE_TEST_ID_TOKEN env"]
async fn verifies_real_google_id_token() {
    let aud = std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID");
    let token = std::env::var("GOOGLE_TEST_ID_TOKEN").expect("GOOGLE_TEST_ID_TOKEN");

    let v = GoogleIdTokenVerifier::new(aud);
    let identity = v.verify(&token).await.expect("verify ok");

    assert_eq!(identity.provider, "google");
    assert!(identity.email_verified);
    println!("verified: sub={} email={}", identity.subject, identity.email.as_str());
}
```

How to run when needed: `GOOGLE_CLIENT_ID=... GOOGLE_TEST_ID_TOKEN=... cargo test --features google --test google_real_token -- --ignored`.

**Tests:** itself is the test. CI skips it (`#[ignore]`). README/PLAN doesn't reference how to grab a real token — that's developer-side (Google OAuth Playground).

**Done when:** `cargo test --features google --test google_real_token` shows `0 passed; 0 failed; 1 ignored`.

**Commit:** `test(google): add ignored real-token smoke test for manual runs`

---

## Final verification (post Task 10)

Run before declaring done:

- `cargo test` (default features) — all existing tests pass, no Google touched.
- `cargo test --features google` — all tests pass including new ones.
- `cargo build --release --features google` — clean.
- `cargo clippy --all-targets --features google -- -D warnings` — clean.
- `cargo doc --no-deps --features google` — no broken intra-doc links.
- `cargo audit --ignore RUSTSEC-2023-0071` — no new advisories beyond the existing ignore.
- `cargo tree -f "{p} {f}"` (default) — confirm `reqwest` and `jsonwebtoken` are NOT pulled.

**Final commit (only if README pulled in version bumps or other tidy-ups land):** `chore(release): prep v0.2.0 — Google Sign-In`. Otherwise no extra commit; the per-task commits stand.

---

## Out of scope for this plan (do not implement)

- Authorization Code Flow / PKCE / token endpoint exchange
- `client_secret` storage
- `refresh_token` (Google's or our own)
- Manual account linking endpoint (`POST /auth/link-google`)
- Account unlink / merge
- Apple, GitHub, Microsoft, other providers
- Per-provider rate limits beyond what `verify_per_ip_per_min_cap` already gives us via the surrounding handler
- Identity-aware audit logging beyond the new `IdentityLinked` event
