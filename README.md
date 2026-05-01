# `auth_rust`

Reusable, security-hardened **passwordless** auth for Rust services. Magic-link + 6-digit code, Postgres-backed sessions, transport-agnostic.

```rust
auth_rust::store::issue_magic_link(&pool, "user@example.com", ip, &cfg, &mailer).await?;
//      ↓ user clicks link or types code
let (session_token, _user_id) = auth_rust::store::verify_magic_link_or_code(
    &pool, input, ip, ua, &AutoSignupResolver, &cfg, &sink,
).await?;
//      ↓ subsequent requests
let (user, refresh_cookie) = auth_rust::store::authenticate_session(
    &pool, cookie_header, &cfg, &sink,
).await?;
```

That's the whole flow. ~50 lines of glue code wires it into axum/actix/anything (see `examples/axum.rs`).

---

## Table of contents

- [What it does](#what-it-does)
- [What it doesn't do](#what-it-doesnt-do)
- [Security guarantees (enforced)](#security-guarantees-enforced)
- [Threat model](#threat-model)
- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Full integration (axum)](#full-integration-axum)
- [Public API reference](#public-api-reference)
- [Configuration](#configuration)
- [Implementing the traits](#implementing-the-traits)
- [Operating it](#operating-it)
- [FAQ](#faq)
- [Migration namespace](#migration-namespace)
- [License](#license)

---

## What it does

| Feature | Status |
|---|---|
| Magic-link issuance (URL token, 32B, base64url) | ✅ |
| 6-digit OTP code (alternative to link, same row, same TTL pool) | ✅ |
| Single email contains both link and code (user picks) | ✅ |
| Auto-signup at first successful verify | ✅ |
| Custom `UserResolver` (whitelist/invite-only/SSO merge) | ✅ |
| Postgres-backed sessions (sliding + absolute TTL) | ✅ |
| `__Host-` prefixed cookie, HttpOnly/Secure/SameSite=Strict | ✅ |
| Atomic in-place refresh (no thundering herd) | ✅ |
| Privilege-change rotation via `rotate_session()` | ✅ |
| Logout (`delete_session`) | ✅ |
| Per-email + per-IP rate limits inside `issue_magic_link` | ✅ |
| Per-IP rate limit on `/verify` (built-in, configurable) | ✅ |
| 24h global per-email failed-attempt lockout | ✅ |
| Disposable-email blocking via `EmailPolicy` trait | ✅ |
| Audit-log hook via `SessionEventSink` trait | ✅ |
| Constant-time pad on issue + verify (anti-enumeration) | ✅ |
| Uniform 200 from issue regardless of input (anti-enumeration) | ✅ |

## What it doesn't do

These are deliberately **out of scope** — different libraries, or your responsibility:

- ❌ Passwords, password reset, password strength checks
- ❌ 2FA / TOTP / WebAuthn / passkeys
- ❌ OAuth, SAML, OIDC, social login
- ❌ Email template rendering (you implement `Mailer`, you choose templating)
- ❌ HTTP rate limiting (`tower_governor` etc.) — defense-in-depth your job
- ❌ HTTP routing — you wire the functions into your framework
- ❌ JWT / stateless tokens — by design (see [FAQ](#faq))
- ❌ CAPTCHA, behavioral signals, anomaly detection
- ❌ Mailer queue / retry — `Mailer::send_magic_link` is one synchronous attempt; you decide retry policy

---

## Security guarantees (enforced)

These cannot be turned off — no config knobs, no feature flags. Pick this library only if you agree with all of them.

- **HMAC-SHA256 with server-side pepper** for *every* hash stored in the database (URL token, OTP code, session token). A leaked DB without the pepper is not enough to authenticate or reverse-lookup tokens.
- **`__Host-` cookie prefix** is forced. The cookie is rejected by browsers if `Domain` is set, `Secure` is missing, or `Path != /`. No subdomain cookie-tossing.
- **HttpOnly + Secure + SameSite=Strict** (default; `Lax` available as opt-in). Path is always `/`.
- **Constant-time pad ~100 ms** wraps both `issue_magic_link` and `verify_magic_link_or_code`. Invalid email format, rate-limited, blocked-by-policy, and success all return in (approximately) the same wall-clock time.
- **Dummy HMAC** runs on the email-locked branch and dummy `subtle::ct_eq` on the no-row-found branch — keeps CPU work parity between code paths.
- **Atomic single-statement** code-attempt increment: no TOCTOU race when concurrent verify attempts hit the same email.
- **5 attempts per code row** then hard-invalidated. Plus a global cap: `SUM(code_attempts)` per email > 50 in last 24h → all subsequent verifies for that email return `EmailLocked`.
- **3 attempts per URL token** (defense-in-depth despite 256-bit entropy).
- **Atomic in-place refresh** of `expires_at` when within the refresh threshold — concurrent reqs can't all race to refresh.
- **Rejection sampling** for the 6-digit code — no modulo bias.
- **`subtle::ConstantTimeEq`** for hash comparison in Rust (not `==`).
- **32 random bytes from `OsRng::try_fill_bytes`** for tokens (256 bits entropy, base64url no-pad).

---

## Threat model

**Protected against:**

- Email-account enumeration via timing or response-code differences on `issue_magic_link`.
- Brute-forcing the 6-digit code (5/row + 50/24h email lockout + per-IP throttle).
- Brute-forcing URL tokens (256-bit entropy, but also a 3-attempt cap).
- DB-only compromise (read-only SQL injection, replica access, backup theft) — token hashes are useless without the pepper.
- Subdomain XSS / cookie-tossing — `__Host-` prefix is browser-enforced.
- Token replay after consumption — `used_at` flag is set atomically with `RETURNING`.
- CSRF on state-changing requests after login — `SameSite=Strict` blocks cross-site cookie sends.
- Session fixation — token rotated on every successful verify (login).

**Not protected against (your responsibility):**

- A compromised mailbox (attacker reads the link or code from the victim's inbox).
- A compromised app process (attacker has the pepper from env).
- Phishing / social engineering.
- Rate-limit floods at the HTTP layer (use `tower_governor` for additional defense).
- TLS downgrade / mitm (use HTTPS — `Secure` cookie is browser-enforced *with* a real cert).
- DDOS at the SMTP relay (consumer's mailer should have its own send caps).

**Not implemented for v1 (consider for v1.1+):**

- IP/UA binding of sessions (Clerk binds, Stytch optional, GitHub doesn't — UX trade-off).
- Same-device binding of magic link (cookie-bound EML — defends against forwarded-link / mailbox-prefetch attacks).
- Audit log persistence (you wire `SessionEventSink` to your SIEM).

---

## Quick start

```toml
# Cargo.toml
[dependencies]
auth_rust = { git = "https://github.com/zygmunt-pawel/rust_auth" }
sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "postgres", "macros", "migrate"] }
```

Generate a 32-byte pepper once and store it in your secrets manager (Vault / AWS SM / 1Password / `.env` for local dev):

```bash
openssl rand -base64 32
```

Bootstrap on app startup:

```rust
use auth_rust::core::{AuthConfig, Pepper};
use auth_rust::store;

let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
store::migrator().run(&pool).await?;   // single migration: users, magic_links, sessions, auth_verify_attempts

let pepper = Pepper::from_base64(&std::env::var("AUTH_TOKEN_PEPPER")?);
let cfg = AuthConfig::new(pepper);     // sane defaults; adjust via cfg.foo = ... if needed
```

Wire three handlers into your framework (full axum example below):

| Endpoint | Function | Body |
|---|---|---|
| `POST /auth/magic-link` | `store::issue_magic_link(pool, email, ip, cfg, mailer)` | `{ "email": "..." }` |
| `POST /auth/verify`     | `store::verify_magic_link_or_code(pool, input, ip, ua, resolver, cfg, sink)` | `{ "token": "..." }` or `{ "email": "...", "code": "123456" }` |
| `POST /auth/logout`     | `store::delete_session(pool, cookie_header, cfg, sink)` | empty |

For protected routes wrap them with middleware that calls `store::authenticate_session(...)` and injects the `AuthenticatedUser` into request extensions.

---

## Prerequisites

- **Rust 1.85+** (uses edition 2024)
- **Postgres 18+** — the migration calls the built-in `uuidv7()`. On Postgres 16/17 you'd need the `pg_uuidv7` extension installed by your DBA before running the library migrator.
- A working `Mailer` implementation. The library has no built-in mailer — you bring your own (`lettre`, `resend`, `sendgrid`, mock-for-tests, whatever).
- TLS for production (`Secure` cookie attribute requires HTTPS, which the library forces).

---

## Architecture

```
                ┌──────────────────────────────────────────────────┐
                │                  your service                    │
                │                                                  │
                │   ┌──────────────┐   ┌──────────────────────┐    │
   POST /magic ─┼──►│ your handler │──►│ issue_magic_link()   │    │
                │   └──────────────┘   └──────────┬───────────┘    │
                │                                 │ INSERT          │
                │   ┌──────────────┐   ┌─────────▼────────────┐    │
   POST /verify ┼──►│ your handler │──►│ verify_*_or_code()   │    │
                │   └──────────────┘   └──────────┬───────────┘    │
                │                                 │ UPDATE used_at  │
                │                                 │ INSERT session  │
                │   ┌──────────────────┐ ┌────────▼────────────┐   │
   any req ─────┼──►│ your middleware  │►│ authenticate_*()    │   │
                │   └──────────────────┘ └─────────────────────┘   │
                │                                                  │
                └──────────────────────┬───────────────────────────┘
                                       │  (single Postgres)
                                       ▼
                            ┌──────────────────────┐
                            │ users · magic_links  │
                            │ sessions · auth_     │
                            │   verify_attempts    │
                            └──────────────────────┘
```

Two public modules:

- **`auth_rust::core`** — types, traits, framework-agnostic helpers. No DB, no HTTP.
- **`auth_rust::store`** — high-level operations on `&PgPool`. Security-critical logic lives here.

The library never touches a `Router`, never spawns a task, never knows about axum. You wire it into your framework.

The whole library ships **one** SQL migration (`20260501000000_auth_init.sql`) that creates four tables: `users`, `magic_links`, `sessions`, `auth_verify_attempts`.

---

## Full integration (axum)

`examples/axum.rs` is the canonical reference. Below is a condensed walkthrough.

### `AppState`

```rust
use std::sync::Arc;
use sqlx::PgPool;
use auth_rust::core::{AuthConfig, Mailer, SessionEventSink};

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    mailer: Arc<dyn Mailer>,
    cfg: Arc<AuthConfig>,
    sink: Arc<dyn SessionEventSink>,
}
```

### `Mailer` implementation (lettre / resend / yourchoice)

```rust
use auth_rust::core::{Email, MagicLinkToken, MailerError, VerifyCode, Mailer};

struct ResendMailer { client: resend_rs::Resend, from: String }

#[async_trait::async_trait]
impl Mailer for ResendMailer {
    async fn send_magic_link(
        &self, email: &Email, link: &MagicLinkToken, code: &VerifyCode,
    ) -> Result<(), MailerError> {
        let html = format!(
            r#"<p>Click <a href="https://app.example.com/auth/landing?token={}">to sign in</a>,</p>
               <p>or paste this code: <strong>{}</strong></p>"#,
            link.as_str(), code.as_str(),
        );
        self.client.emails.send(resend_rs::types::CreateEmailBaseOptions::new(
            &self.from, vec![email.as_str()], "Sign in to Example",
        ).with_html(&html)).await.map_err(|e| MailerError::Retryable(Box::new(e)))?;
        Ok(())
    }
}
```

`MailerError::Retryable` vs `Permanent` — currently informational; the library makes one synchronous send attempt and propagates failures. Your handler decides whether to retry, queue, or log+200.

### `EmailPolicy` (disposable blocklist, optional)

```rust
use std::collections::HashSet;
use auth_rust::core::{Email, EmailPolicy};

struct DisposableBlocklist { blocked: HashSet<String> }

impl DisposableBlocklist {
    fn from_embedded() -> Self {
        // Get the list from https://github.com/disposable-email-domains/disposable-email-domains
        let raw = include_str!("../disposable_domains.txt");
        Self { blocked: raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect() }
    }
}

#[async_trait::async_trait]
impl EmailPolicy for DisposableBlocklist {
    async fn allow(&self, email: &Email) -> bool {
        let domain = email.as_str().rsplit('@').next().unwrap_or("");
        !self.blocked.contains(domain)
    }
}
```

Blocked emails are silently dropped (timing-equivalent to a successful send — no enumeration leak). The user sees a generic "check your inbox" message; their inbox stays empty.

`EmailPolicy::allow` MUST be fast (<5ms). Pre-load any list at startup, no HTTP/DNS calls in the hot path.

### `SessionEventSink` (audit trail, optional)

```rust
use auth_rust::core::{SessionEvent, SessionEventSink};

struct DatadogSink { client: datadog::Client }

#[async_trait::async_trait]
impl SessionEventSink for DatadogSink {
    async fn on_event(&self, event: SessionEvent) {
        match event {
            SessionEvent::Created { user_id, ip, .. } => {
                self.client.event("auth.session.created").tag("user_id", user_id).tag("ip", ip).send().await;
            }
            SessionEvent::Refreshed { .. }
                | SessionEvent::Rotated { .. }
                | SessionEvent::Revoked { .. } => { /* etc. */ }
        }
    }
}
```

Default is `NoOpSink` — no events emitted. Plug this in to push to Datadog/Sentry/Splunk/SIEM.

### Wiring AuthConfig

```rust
use auth_rust::core::{AuthConfig, Pepper, SameSite};

let pepper = Pepper::from_base64(&std::env::var("AUTH_TOKEN_PEPPER")?);
let mut cfg = AuthConfig::new(pepper);

// Override defaults if needed:
cfg.same_site = SameSite::Strict;                                    // already default
cfg.session_sliding_ttl = std::time::Duration::from_secs(7 * 24 * 60 * 60);
cfg.policy = Arc::new(DisposableBlocklist::from_embedded());
cfg.event_sink = Arc::new(DatadogSink { client: dd });

let state = AppState {
    pool, mailer: Arc::new(ResendMailer { ... }), cfg: Arc::new(cfg), sink: Arc::new(DatadogSink { ... }),
};
```

### Handlers

```rust
async fn magic_link_handler(
    State(s): State<AppState>, headers: HeaderMap, Json(req): Json<MagicLinkRequest>,
) -> StatusCode {
    let ip = client_ip(&headers); // your IP extraction (axum-client-ip etc.)
    if let Err(e) = auth_rust::store::issue_magic_link(&s.pool, &req.email, ip, &s.cfg, &*s.mailer).await {
        tracing::warn!(error = %e, "mailer failed");  // log, but still return 200
    }
    StatusCode::OK   // ALWAYS 200 — uniform response is the contract
}

async fn verify_handler(
    State(s): State<AppState>, headers: HeaderMap, Json(body): Json<VerifyBody>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());
    let input = match body {
        VerifyBody::Token { token } => VerifyInput::Token(MagicLinkToken::from_string(token)),
        VerifyBody::Code { email, code } => VerifyInput::Code {
            email: Email::try_from(email).map_err(|_| AuthError::InvalidToken)?,
            code: VerifyCode::from_string(code),
        },
    };
    let (token, _user_id) = auth_rust::store::verify_magic_link_or_code(
        &s.pool, input, ip, ua, &AutoSignupResolver, &s.cfg, &*s.sink,
    ).await?;
    let cookie = session_cookie_header_value(&token, &s.cfg);
    Ok((StatusCode::OK, [(SET_COOKIE, cookie)]).into_response())
}

async fn logout_handler(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let cookie_header = headers.get(COOKIE).and_then(|v| v.to_str().ok());
    let _ = auth_rust::store::delete_session(&s.pool, cookie_header, &s.cfg, &*s.sink).await;
    let clear = session_cookie_clear_header_value(&s.cfg);
    (StatusCode::OK, [(SET_COOKIE, clear)]).into_response()
}
```

### Middleware for protected routes

```rust
async fn require_session(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let cookie_header = req.headers().get(COOKIE).and_then(|v| v.to_str().ok());
    match auth_rust::store::authenticate_session(&s.pool, cookie_header, &s.cfg, &*s.sink).await {
        Ok((user, refresh_cookie)) => {
            req.extensions_mut().insert(user);  // handlers extract via Extension<AuthenticatedUser>
            let mut resp = next.run(req).await;
            if let Some(c) = refresh_cookie {
                // sliding TTL was bumped — re-emit Set-Cookie so browser stays in sync
                resp.headers_mut().insert(SET_COOKIE, c.parse().unwrap());
            }
            resp
        }
        Err(_) => {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(SET_COOKIE, session_cookie_clear_header_value(&s.cfg).parse().unwrap());
            resp
        }
    }
}
```

### Privilege-change rotation

When a user changes their email, enables MFA, or steps up to admin, rotate their session token even mid-session:

```rust
let new_token = auth_rust::store::rotate_session(&s.pool, &cookie_header, &s.cfg, &*s.sink).await?;
let cookie = session_cookie_header_value(&new_token, &s.cfg);
// emit Set-Cookie back to the client; old token is now invalid
```

---

## Public API reference

```rust
// auth_rust::core
pub struct AuthConfig { /* see Configuration */ }
impl AuthConfig { pub fn new(pepper: Pepper) -> Self; pub fn cookie_name(&self) -> String; }

pub enum SameSite { Strict, Lax }

pub struct Pepper(/* opaque, redacted in Debug */);
impl Pepper { pub fn from_bytes(b: [u8; 32]) -> Self; pub fn from_base64(s: &str) -> Self; }

pub struct Email(/* lowercase, validated */);
impl TryFrom<String> for Email { ... }
impl Email { pub fn as_str(&self) -> &str; }

pub struct MagicLinkToken(/* 43-char base64url */);
pub struct SessionToken(/* 43-char base64url */);
pub struct VerifyCode(/* 6 ASCII digits */);
// each has: ::generate(), ::from_string(s), .as_str()

pub enum VerifyInput {
    Token(MagicLinkToken),
    Code { email: Email, code: VerifyCode },
}

pub enum AuthError {
    InvalidToken, TokenExpired, TokenReused, Unauthorized, EmailLocked,
    RateLimited, MailerFailed, Internal(String),
}
impl AuthError { pub fn http_status(&self) -> u16; }

#[async_trait] pub trait Mailer        { async fn send_magic_link(...) -> Result<(), MailerError>; }
#[async_trait] pub trait UserResolver  { async fn resolve_or_create(&self, pool, email) -> Result<UserId, ResolverError>; }
#[async_trait] pub trait EmailPolicy   { async fn allow(&self, email: &Email) -> bool; }
#[async_trait] pub trait SessionEventSink { async fn on_event(&self, event: SessionEvent); }

pub struct AllowAll;     // default EmailPolicy
pub struct NoOpSink;     // default SessionEventSink

pub fn session_cookie_header_value(token: &SessionToken, cfg: &AuthConfig) -> String;
pub fn session_cookie_clear_header_value(cfg: &AuthConfig) -> String;
pub fn extract_session_cookie_value<'a>(header: Option<&'a str>, cfg: &AuthConfig) -> Option<&'a str>;

// auth_rust::store
pub async fn issue_magic_link(
    pool: &PgPool, email_input: &str, ip: IpAddr, cfg: &AuthConfig, mailer: &dyn Mailer,
) -> Result<(), AuthError>;

pub async fn verify_magic_link_or_code(
    pool: &PgPool, input: VerifyInput, ip: IpAddr, user_agent: Option<&str>,
    resolver: &dyn UserResolver, cfg: &AuthConfig, sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError>;

pub async fn authenticate_session(
    pool: &PgPool, cookie_header: Option<&str>, cfg: &AuthConfig, sink: &dyn SessionEventSink,
) -> Result<(AuthenticatedUser, Option<String /* re-emit Set-Cookie */>), AuthError>;

pub async fn delete_session(
    pool: &PgPool, cookie_header: Option<&str>, cfg: &AuthConfig, sink: &dyn SessionEventSink,
) -> Result<Option<UserId>, AuthError>;

pub async fn rotate_session(
    pool: &PgPool, cookie_header: &str, cfg: &AuthConfig, sink: &dyn SessionEventSink,
) -> Result<SessionToken, AuthError>;

pub async fn lookup_user_by_id(pool: &PgPool, user_id: UserId) -> Result<Option<User>, AuthError>;

pub fn migrator() -> &'static sqlx::migrate::Migrator;

pub struct AutoSignupResolver;  // default UserResolver — INSERT IF NOT EXISTS
```

---

## Configuration

All `AuthConfig` fields and their defaults:

| Field | Default | Purpose |
|---|---|---|
| `cookie_name_suffix` | `"session"` | Final cookie name = `__Host-{suffix}` (always prefixed) |
| `same_site` | `SameSite::Strict` | Override to `Lax` only if you have legitimate cross-site nav flows |
| `session_sliding_ttl` | `7d` | Max-Age on the cookie; sliding TTL inside DB |
| `session_absolute_ttl` | `30d` | Hard cap — sessions die at this age regardless of activity |
| `session_refresh_threshold` | `1d` | When `expires_at < NOW() + this`, refresh fires |
| `magic_link_ttl` | `15min` | URL token validity |
| `code_ttl` | `5min` | OTP code validity (shorter — lower entropy) |
| `issue_per_email_min_gap` | `60s` | Minimum delay between two issuances for the same email |
| `issue_per_email_24h_cap` | `5` | Max issuances per email per 24h |
| `issue_per_ip_1h_cap` | `5` | Max distinct recipients per IP per hour |
| `issue_per_ip_24h_cap` | `30` | Max distinct recipients per IP per day |
| `verify_per_ip_per_min_cap` | `30` | Max verify calls per IP per minute (set to `0` to disable) |
| `code_failures_per_email_24h_cap` | `50` | SUM(code_attempts) per email in 24h → email locked |
| `token_pepper` | (required) | 32-byte HMAC key — set once, never rotate without invalidating all sessions |
| `policy` | `Arc::new(AllowAll)` | `EmailPolicy` impl |
| `event_sink` | `Arc::new(NoOpSink)` | `SessionEventSink` impl |

### Tuning notes

- **Lower TTLs** if you're handling sensitive data: `session_sliding_ttl = 1h`, `session_absolute_ttl = 8h`. Forces re-login periodically.
- **`SameSite::Lax`** is needed if you accept inbound deep-links from external domains that should land already-logged-in. For a SaaS dashboard, `Strict` is the right default.
- **`verify_per_ip_per_min_cap = 0`** disables the built-in verify rate limiter entirely (e.g. you have `tower_governor` doing it cheaper at the HTTP layer).
- **Pepper rotation** is not implemented — you'd need a key-versioning column. For now: set the pepper once and treat its loss as a "everyone re-logs in" event.

---

## Implementing the traits

### `Mailer` (required)

You implement this. The library doesn't ship one because email backends are too varied (transactional providers, SMTP, internal queues, mocks for tests).

```rust
#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send_magic_link(
        &self, email: &Email, link_token: &MagicLinkToken, code: &VerifyCode,
    ) -> Result<(), MailerError>;
}

pub enum MailerError {
    Retryable(Box<dyn std::error::Error + Send + Sync>),  // network, SMTP 4xx
    Permanent(Box<dyn std::error::Error + Send + Sync>),  // bounced, malformed, 5xx permanent
}
```

The library makes ONE synchronous attempt. Any error → `AuthError::MailerFailed`. Your handler decides:

- Retry inline (tiny chance of recovering from transient SMTP hiccup)
- Push to a queue (`apalis`, your own — for production reliability)
- Log + return 200 (acceptable for magic-link UX — user just clicks "resend")

### `UserResolver` (default = `AutoSignupResolver`)

```rust
pub trait UserResolver { async fn resolve_or_create(...) -> Result<UserId, ResolverError>; }
```

Default `AutoSignupResolver` does `INSERT INTO users (email) ... ON CONFLICT DO NOTHING; SELECT id FROM users WHERE email = $1`. First successful verify creates the account.

Replace it for **invite-only** apps:

```rust
struct InviteOnly { invited_emails: Arc<RwLock<HashSet<String>>> }

#[async_trait]
impl UserResolver for InviteOnly {
    async fn resolve_or_create(&self, pool: &PgPool, email: &Email) -> Result<UserId, ResolverError> {
        if !self.invited_emails.read().await.contains(email.as_str()) {
            return Err(ResolverError::Rejected("not invited".into()));
        }
        AutoSignupResolver.resolve_or_create(pool, email).await
    }
}
```

### `EmailPolicy` (default = `AllowAll`)

```rust
pub trait EmailPolicy { async fn allow(&self, email: &Email) -> bool; }
```

`false` → silent drop (no INSERT, no mailer call, timing-equivalent to a successful send). Use for:
- Disposable email blocklists (mailinator, guerrillamail, etc.)
- Tenant whitelists (`@yourcompany.com` only)
- Geographic restrictions (decide from email's TLD)

**MUST be fast** (<5ms). Pre-load lists at startup, no DNS/HTTP in the hot path.

### `SessionEventSink` (default = `NoOpSink`)

```rust
pub trait SessionEventSink { async fn on_event(&self, event: SessionEvent); }
pub enum SessionEvent {
    Created  { session_id, user_id, ip, user_agent },
    Refreshed{ session_id, user_id },
    Rotated  { old_session_id, new_session_id, user_id },  // rotate_session() only
    Revoked  { session_id, user_id },                       // delete_session
}
```

Wire to your audit log / SIEM / observability stack.

---

## Operating it

### Pepper management

The pepper is a 32-byte HMAC key. Treat it like a database password:

- Generate once: `openssl rand -base64 32`
- Store in your secrets manager (1Password / Vault / AWS Secrets Manager / `.env` for dev)
- Inject as env var `AUTH_TOKEN_PEPPER`
- Never commit to git
- **Rotation = full invalidation**: changing the pepper invalidates every existing session, magic-link, and OTP code. There's no key versioning.

### Multi-instance deployments

Library is fully stateless across instances — all state lives in Postgres. Two instances with the same `DATABASE_URL` and same pepper share the same auth state. No Redis needed.

If you want per-region pepper (so an EU compromise doesn't auth in US), you'd need separate Postgres instances and separate peppers — out of scope for v1.

### Cleanup of stale rows

`magic_links` rows accumulate. Add a cron job (or `pg_cron` extension):

```sql
-- Run nightly
DELETE FROM magic_links WHERE created_at < NOW() - INTERVAL '7 days';
DELETE FROM auth_verify_attempts WHERE attempted_at < NOW() - INTERVAL '1 hour';
DELETE FROM sessions WHERE absolute_expires_at < NOW();
```

The library does opportunistic cleanup of `auth_verify_attempts` on every verify call (deletes rows older than 5 min). The other tables grow unbounded if you don't sweep.

### Observability

Wire `SessionEventSink` to your stack. Useful metrics derived from events:
- `auth_sessions_created_total` (Created)
- `auth_sessions_refreshed_total` (Refreshed)
- `auth_sessions_rotated_total` (Rotated — only privilege-change)
- `auth_sessions_revoked_total` (Revoked — explicit logout)

`tracing` events the library emits internally (`tracing::debug!`):
- `auth_rust::issue` with `email`, `ip` — silent drops with reason

---

## FAQ

**Q: Why no JWT?**

A: Stateful sessions give you instant revocation, no key rotation pain, no `alg: none` / RS-HS confusion CVEs, no JWT-claims-bloat. Postgres lookups are sub-millisecond with a unique index. The "stateless = scalable" pitch is mostly mythical for monolith deployments — your DB is already the scaling bottleneck.

**Q: Can I run this without Postgres?**

A: No. Sessions live in Postgres. The library is opinionated. If you want stateless, fork.

**Q: Can I customize the email template?**

A: Yes — you implement `Mailer`. The library doesn't render emails. It just hands you `email`, `link_token`, `code` and asks you to send something containing them.

**Q: Can a user have multiple active sessions (mobile + desktop)?**

A: Yes. Each successful verify creates a new session row. Logout deletes one. Listing/revoking all sessions per user isn't in the public API for v1, but is trivially doable: `DELETE FROM sessions WHERE user_id = $1`.

**Q: How do I list all sessions for a user?**

A: `SELECT id, public_id, created_at, last_seen_at, user_agent, ip FROM sessions WHERE user_id = $1`. Not exposed via the library, but you have the pool.

**Q: How do I implement "remember me" vs "session-only"?**

A: Two `AuthConfig`s with different `session_sliding_ttl` / `cookie_name_suffix`. Pick which one to use at verify time. (Slightly awkward — open issue if you need first-class support.)

**Q: How do I implement "step-up auth" (require re-verify for sensitive actions)?**

A: After the user re-verifies, call `rotate_session()` and check the new session's `created_at` in your handler — if it's older than (say) 5 min, refuse the sensitive action and ask them to re-verify.

**Q: Can I rate-limit verify per email instead of just per IP?**

A: The 50/24h global per-email failed-attempt cap covers the worst case (slow brute force from many IPs). Per-email per-minute throttle isn't built in but is trivial to add at your HTTP layer with `tower_governor` keyed on the request's `email` field.

**Q: Does the constant-time pad add 100ms to every login?**

A: Yes, deliberately. If your users complain about login feeling slow, the pad is the first thing to look at. Lower it (it's a constant — fork to change) at your security-vs-UX taste, but be aware: zero pad = enumeration oracle.

**Q: What happens if my Postgres goes down?**

A: All auth fails (Unauthorized for protected routes, MailerFailed for issuance, etc.). The library has no fallback, no cache. Get a Postgres HA setup or a managed DB.

---

## Migration namespace

The library ships **one** SQL migration: `20260501000000_auth_init.sql`. Timestamp prefix is intentional — it lets you drop the library's migrations into the same `migrations/` directory as your own without version collisions (sqlx tracks all migrators in a single `_sqlx_migrations` table by integer version).

Two ways to wire it in:

```rust
// (a) Run them as separate migrators, in any order:
auth_rust::store::migrator().run(&pool).await?;
my_app_migrator.run(&pool).await?;
```

```rust
// (b) Or symlink/copy the auth migration into your migrations/ folder
// and use a single sqlx::migrate!("./migrations") in your app.
// (Less convenient for upgrades, but works if you only have one migrator.)
```

The recommended pattern is (a) — run the library migrator separately on startup, before your own.

---

## License

MIT OR Apache-2.0 — pick whichever fits your project.
