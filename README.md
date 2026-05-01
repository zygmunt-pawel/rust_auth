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

That's the whole flow. ~50 lines of glue wires it into axum/actix/anything — see `examples/axum.rs` for the full reference integration.

---

## Features

- ✅ Magic-link (32B URL token) + 6-digit OTP code in one email — user picks
- ✅ Postgres sessions, sliding + absolute TTL, atomic in-place refresh
- ✅ `__Host-` cookie prefix, `HttpOnly` / `Secure` / `SameSite=Strict`
- ✅ HMAC-SHA256 with server-side pepper for **all** stored hashes
- ✅ Per-email + per-IP rate limits on issue, per-IP throttle on verify
- ✅ 5/row + 50/24h global per-email failed-attempt lockout
- ✅ Constant-time pad (~100ms) on issue + verify — anti-enumeration
- ✅ Bundled disposable-email blocklist (~5400 domains, opt-in)
- ✅ Auto-signup at first verify (or plug your own `UserResolver`)
- ✅ Audit-log hook (`SessionEventSink`)
- ✅ Cleanup helper for old rows (`store::cleanup_expired`)

**Not included** (out of scope by design): passwords, OAuth/2FA, JWT, HTTP routing, mailer queue, CAPTCHA. The library deliberately doesn't read environment variables — you pass strings in.

---

## Quick start

```toml
[dependencies]
auth_rust = { git = "https://github.com/zygmunt-pawel/rust_auth" }
sqlx = { version = "0.8", features = ["runtime-tokio", "tls-rustls", "postgres", "macros", "migrate"] }
```

Generate a 32-byte pepper once and store it in your secrets manager:

```bash
openssl rand -base64 32
```

Bootstrap on app startup:

```rust
use std::sync::Arc;
use auth_rust::core::{AuthConfig, DisposableBlocklist};
use auth_rust::store;

let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
store::migrator().run(&pool).await?;          // single migration: users, magic_links, sessions, auth_verify_attempts

let pepper_b64 = std::env::var("AUTH_TOKEN_PEPPER")?;  // YOU read env, not the lib
let mut cfg = AuthConfig::new(&pepper_b64)?;            // sane defaults; mutate fields below if needed

// Optional: enable bundled disposable-email blocklist
cfg.policy = Arc::new(DisposableBlocklist::with_default_list());
```

Wire three handlers (axum example):

| Endpoint | Function |
|---|---|
| `POST /auth/magic-link` | `store::issue_magic_link(pool, email, ip, cfg, mailer)` |
| `POST /auth/verify` | `store::verify_magic_link_or_code(pool, input, ip, ua, resolver, cfg, sink)` |
| `POST /auth/logout` | `store::delete_session(pool, cookie_header, cfg, sink)` |

For protected routes wrap them with middleware that calls `store::authenticate_session(...)` and injects `AuthenticatedUser` into request extensions. Run `store::cleanup_expired(&pool).await?` from a daily cron.

---

## Prerequisites

- **Rust 1.85+** (edition 2024)
- **Postgres 18+** — migration uses built-in `uuidv7()`. On 16/17, install the `pg_uuidv7` extension first.
- A `Mailer` impl you provide (`lettre`, `resend`, `sendgrid`, mock-for-tests).
- TLS in production (`Secure` cookie attribute requires HTTPS).

---

## Security guarantees (enforced — no knobs)

- **HMAC-SHA256 with server-side pepper** for every stored hash. DB-only leak doesn't authenticate.
- **`__Host-` cookie prefix** is always emitted. Browser refuses cookie if `Domain` is set or `Path != /`. No subdomain cookie-tossing.
- **`HttpOnly` + `Secure` + `SameSite=Strict`** (default; `Lax` available as opt-in).
- **Constant-time pad** wraps `issue_magic_link` and `verify_magic_link_or_code`. Format-error / rate-limited / blocked / success all return in similar wall-clock time.
- **Atomic single-statement** code-attempt increment — no TOCTOU on concurrent verify.
- **5 attempts per code row** + **50/24h global per-email** → `EmailLocked`.
- **3 attempts per URL token** (defense-in-depth despite 256-bit entropy).
- **Atomic in-place refresh** — concurrent reqs can't all race on session refresh.
- **Rejection sampling** for the 6-digit code (no modulo bias).
- **`subtle::ConstantTimeEq`** for hash equality in Rust.
- **32 random bytes from `OsRng::try_fill_bytes`** for tokens (256 bits, base64url no-pad).

**Not protected against:** compromised mailbox, compromised app process (pepper exposed), phishing, TLS mitm. **Not in v1 (consider v1.1):** IP/UA session binding, magic-link cookie binding, session listing/revoke-all-for-user API.

---

## Configuration

```rust
let mut cfg = AuthConfig::new(&pepper_b64)?;

cfg.magic_link_ttl       = Duration::from_secs(15 * 60);       // URL token validity
cfg.code_ttl             = Duration::from_secs(5 * 60);        // OTP code validity (shorter)
cfg.session_sliding_ttl  = Duration::from_secs(7 * 24 * 3600); // sliding window
cfg.session_absolute_ttl = Duration::from_secs(30 * 24 * 3600);// hard cap
cfg.session_refresh_threshold = Duration::from_secs(24 * 3600);// bump TTL when <1d remains
cfg.issue_per_email_min_gap   = Duration::from_secs(60);
cfg.issue_per_email_24h_cap   = 5;
cfg.issue_per_ip_1h_cap       = 5;
cfg.issue_per_ip_24h_cap      = 30;
cfg.verify_per_ip_per_min_cap = 30;     // set 0 to disable built-in verify rate limit
cfg.code_failures_per_email_24h_cap = 50;
cfg.same_site = SameSite::Strict;       // Lax also available
cfg.cookie_name_suffix = "session".into();  // final cookie name = __Host-{suffix}
cfg.log_full_email = false;             // true = log full email; default false = domain only (PII-safe)

// Pluggable hooks:
cfg.policy     = Arc::new(DisposableBlocklist::with_default_list());
cfg.event_sink = Arc::new(MyDatadogSink);
```

Every field has a sensible default — tune what you need. `AuthConfig::new(&str)` is the primary constructor. For tests / KMS-fetched bytes use `AuthConfig::from_pepper(Pepper::from_bytes([..]))`.

---

## Customization (the four traits)

### `Mailer` — required, you provide

```rust
#[async_trait::async_trait]
impl Mailer for MyMailer {
    async fn send_magic_link(
        &self, email: &Email, link: &MagicLinkToken, code: &VerifyCode,
    ) -> Result<(), MailerError> {
        // send via lettre/resend/sendgrid; include both link and code in body
        Ok(())
    }
}
```

Library makes ONE synchronous attempt; errors propagate as `AuthError::MailerFailed`. You decide retry/queue/log.

### `EmailPolicy` — disposable blocklist + custom rules

```rust
// Bundled list (~5400 domains) with extensions and exceptions:
let policy = DisposableBlocklist::with_default_list()
    .add("internal-spam.example")     // also block this
    .add_iter(["a.example", "b.example"])
    .unblock("mailinator.com");       // QA exception

cfg.policy = Arc::new(policy);

// Or write your own (tenant whitelist, geo restrictions, etc.):
struct TenantOnly;
#[async_trait::async_trait]
impl EmailPolicy for TenantOnly {
    async fn allow(&self, email: &Email) -> bool {
        email.as_str().ends_with("@yourcompany.com")
    }
}
```

`policy.allow(email)` returning `false` → silent drop (no INSERT, no mailer, timing-equivalent to success). MUST be fast (<5ms) — pre-load lists at startup, no DNS/HTTP in hot path.

### `UserResolver` — control who can sign up

Default `AutoSignupResolver` does INSERT-IF-NOT-EXISTS on first verify. Replace for invite-only:

```rust
#[async_trait::async_trait]
impl UserResolver for InviteOnly {
    async fn resolve_or_create(&self, pool: &PgPool, email: &Email) -> Result<UserId, ResolverError> {
        if !self.invited.contains(email.as_str()) {
            return Err(ResolverError::Rejected("not invited".into()));
        }
        AutoSignupResolver.resolve_or_create(pool, email).await
    }
}
```

### `SessionEventSink` — audit log hook

```rust
#[async_trait::async_trait]
impl SessionEventSink for DatadogSink {
    async fn on_event(&self, event: SessionEvent) {
        // SessionEvent::{Created, Refreshed, Rotated, Revoked}
        // route to your SIEM / Sentry / Splunk
    }
}
```

Default `NoOpSink` — no events emitted.

---

## Operating it

### Pepper management

32-byte HMAC key, treated like a DB password:

- Generate once: `openssl rand -base64 32`
- Store in your secrets manager (Vault / 1Password / AWS SM / `.env` for dev)
- Pass the string to `AuthConfig::new(&pepper)?`
- **Rotation = full invalidation** — changing the pepper invalidates every session, magic-link, and OTP code. There's no key versioning.

### Multi-instance

All state in Postgres. Two app instances with same `DATABASE_URL` + same pepper share auth state. No Redis needed.

### Cleanup

`magic_links` rows accumulate. Run nightly:

```rust
let report = auth_rust::store::cleanup_expired(&pool).await?;
tracing::info!(
    magic_links = report.magic_links_deleted,
    sessions    = report.sessions_deleted,
    verify_attempts = report.verify_attempts_deleted,
    "auth cleanup",
);
```

Hardcoded sensible windows: `magic_links` older than 7 days (preserves the 24h lockout window + forensics buffer), `sessions` past `absolute_expires_at`, `auth_verify_attempts` older than 5 min.

### Observability

The library emits `tracing` spans + events on every public operation. Plug in any `tracing-subscriber` (or our [`rust_telemetry`](https://github.com/zygmunt-pawel/rust_telemetry) crate for OTel/Loki/Tempo out of the box). Trace↔log correlation just works.

**Spans** (one per public call):
`auth.issue_magic_link` · `auth.verify` · `auth.session.authenticate` · `auth.session.delete` · `auth.session.rotate` · `auth.lookup_user_by_id` · `auth.cleanup_expired`

**Span fields** (recorded as work progresses): `email`, `ip`, `user_id`, `session_id`, `outcome`, `path` (token/code), `token_prefix`.

**Events emitted:**

| Level | Event | When |
|---|---|---|
| `info!` | `outcome="issued"` | magic link sent successfully |
| `info!` | `outcome="success"` | verify (token or code) succeeded |
| `info!` | `outcome="refreshed"` | session sliding TTL bumped |
| `info!` | `outcome="rotated"` | privilege-change rotation |
| `info!` | `outcome="revoked"` | logout |
| `info!` | (cleanup pass) | how many rows GC'd from each table |
| `warn!` | `outcome="rate_limited"` | verify per-IP cap hit |
| `warn!` | `outcome="email_locked"` | 50/24h failed-attempt cap tripped |
| `warn!` | `outcome="mailer_failed"` | mailer rejected send |
| `debug!` | `outcome="format_invalid"\|"rate_limited_email"\|"rate_limited_ip"\|"policy_denied"` | silent drops in `issue_magic_link` |
| `debug!` | `outcome="invalid_token"\|"wrong_code"\|"no_live_row"` | normal verify rejections |
| `debug!` | `outcome="no_cookie"\|"lookup_miss"` | normal session lookup misses |

**PII policy:** by default the `email` field contains only the domain (e.g. `gmail.com`) — full addresses don't reach Loki/Tempo. Flip `cfg.log_full_email = true` to log the complete address (useful for support debugging; remember the retention implications). Operator searching for a specific user can also use `user_id` (post-verify) or query the `users` table directly. Audit-grade events with full identifiers go through `SessionEventSink` (your audit log / SIEM), separate from observability stack. IP addresses are logged as standard for security investigations (GDPR "legitimate interest").

**Filter example:** `RUST_LOG="info,auth_rust=debug"` (or via `tracing_subscriber::EnvFilter`) — sees all auth decisions including silent drops while keeping the rest of your app at INFO.

---

## FAQ

**Why no JWT?**
Stateful sessions = instant revocation, no key rotation pain, no `alg: none` / RS-HS confusion CVEs. DB lookup is sub-ms with the unique index. The "stateless = scalable" pitch is mostly mythical for monoliths.

**Can a user have multiple sessions (mobile + desktop)?**
Yes — each verify creates a new session row. Logout deletes one. To revoke all sessions for a user: `DELETE FROM sessions WHERE user_id = $1` (not exposed via library; you have the pool).

**How do I "remember me" vs "session-only"?**
Two `AuthConfig`s with different `session_sliding_ttl` / `cookie_name_suffix`; pick one at verify time.

**How do I implement step-up auth?**
After re-verify, call `rotate_session(...)` and check the new session's `created_at` in your sensitive handler — refuse if older than (say) 5 min.

**Does the constant-time pad add 100ms to every login?**
Yes, deliberately. Zero pad = enumeration oracle. If users complain about login latency, the pad is the first thing to look at.

**What if Postgres goes down?**
All auth fails. No fallback, no cache. Use a managed DB / HA setup.

---

## Migration namespace

The library ships **one** SQL migration: `20260501000000_auth_init.sql`. Timestamp prefix avoids version-id collisions with consumer migrations sharing `_sqlx_migrations`. Recommended pattern:

```rust
auth_rust::store::migrator().run(&pool).await?;   // run library migrations first
my_app_migrator.run(&pool).await?;                 // then yours
```

---

## License

MIT OR Apache-2.0
