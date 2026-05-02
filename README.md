# `auth_rust`

Reusable, security-hardened **passwordless** auth for Rust services. Magic-link + 6-digit code, Postgres-backed sessions, transport-agnostic.

```rust
auth_rust::store::issue_magic_link(&pool, "user@example.com", ip, &cfg, &mailer).await?;
//      ↓ user clicks link or types code
let (session_token, _user_id) = auth_rust::store::verify_magic_link_or_code(
    &pool, input, ip, ua, &AutoSignupResolver, &cfg, &sink,
).await?;
// Build the Set-Cookie header value and emit it on the verify response — the browser
// stores it and brings it back on every subsequent request as the Cookie header.
let set_cookie = auth_rust::core::cookie::session_cookie_header_value(&session_token, &cfg);
//      ↓ subsequent requests pass the raw Cookie header in
let (user, refresh_cookie) = auth_rust::store::authenticate_session(
    &pool, cookie_header, &cfg, &sink,
).await?;
//   refresh_cookie is Some(...) when sliding TTL was bumped — re-emit as Set-Cookie.
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
- ✅ Bundled disposable-email blocklist (~5400 domains, **on by default** — fail-secure)
- ✅ Auto-signup at first verify (or plug your own `UserResolver`)
- ✅ Audit-log hook (`SessionEventSink`)
- ✅ Cleanup helper for old rows (`store::cleanup_expired`)
- ✅ Built-in `tracing` spans + structured events (logs/traces correlate out-of-box with [`rust_telemetry`](https://github.com/zygmunt-pawel/rust_telemetry))

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
use auth_rust::core::AuthConfig;
use auth_rust::store;

let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
store::migrator().run(&pool).await?;          // single migration: users, magic_links, sessions, auth_verify_attempts

let pepper_b64 = std::env::var("AUTH_TOKEN_PEPPER")?;  // YOU read env, not the lib
let cfg = AuthConfig::builder(&pepper_b64)?            // builder applies sane defaults
    // .policy(...)  // override default DisposableBlocklist if you want custom logic
    // .same_site(SameSite::Lax)
    // ...other overrides
    .build()?;

// Disposable-email blocklist is ON by default. Opt out for invite-only / B2B:
//   .policy(Arc::new(auth_rust::core::AllowAll))
```

Wire three handlers (axum example):

| Endpoint | Function |
|---|---|
| `POST /auth/magic-link` | `store::issue_magic_link(pool, email, ip, cfg, mailer)` |
| `POST /auth/verify` | `store::verify_magic_link_or_code(pool, input, ip, ua, resolver, cfg, sink)` |
| `POST /auth/logout` | `store::delete_session(pool, cookie_header, cfg, sink)` |

For protected routes wrap them with middleware that calls `store::authenticate_session(...)` and injects `AuthenticatedUser` into request extensions. Run `store::cleanup_expired(&pool).await?` from a daily cron. All public ops are `#[tracing::instrument]`-wrapped — pipe `tracing-subscriber` somewhere (or use [`rust_telemetry`](https://github.com/zygmunt-pawel/rust_telemetry)) and you'll see structured spans/events out of the box.

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
- **Per-row brute-force cap on the 6-digit code** (default 5, configurable via `code_attempts_per_row`) + **50/24h global per-email** → `EmailLocked`.
- **Per-token cap on URL link attempts** (default 3, configurable via `link_attempts_per_token`) — defense-in-depth despite 256-bit entropy.
- **Atomic in-place refresh** — concurrent reqs can't all race on session refresh.
- **Rejection sampling** for the 6-digit code (no modulo bias).
- **`subtle::ConstantTimeEq`** for hash equality in Rust.
- **32 random bytes from `OsRng::try_fill_bytes`** for tokens (256 bits, base64url no-pad).

**Not protected against:** compromised mailbox, compromised app process (pepper exposed), phishing, TLS mitm. **Not in v1 (consider v1.1):** IP/UA session binding, magic-link cookie binding, session listing/revoke-all-for-user API.

---

## Configuration

`AuthConfig` is built via `AuthConfigBuilder`. The builder validates every single-field
range and every cross-field invariant (e.g. `code_ttl <= magic_link_ttl`,
`session_refresh_threshold < session_sliding_ttl`) at `build()` time — invalid configs
return `ConfigError::Invalid` with a precise message. After build, fields are read-only.

```rust
let cfg = AuthConfig::builder(&pepper_b64)?
    .magic_link_ttl(Duration::from_secs(15 * 60))           // URL token validity
    .code_ttl(Duration::from_secs(15 * 60))                 // must be <= magic_link_ttl
    .session_sliding_ttl(Duration::from_secs(7 * 24 * 3600))
    .session_absolute_ttl(Duration::from_secs(30 * 24 * 3600))
    .session_refresh_threshold(Duration::from_secs(24 * 3600))
    // Issue rate limits — rolling window (default 30 min). On (cap+1)th request the
    // email/IP is blocked for `issue_block_duration`. Block does NOT extend on retry.
    .issue_per_email_cap(15)
    .issue_per_ip_cap(15)
    .issue_window(Duration::from_secs(30 * 60))             // must be >= 60s
    .issue_block_duration(Duration::from_secs(30 * 60))
    // Repeat-offender: IP blocked >= N times in 24h gets a permanent block (0 = off).
    .ip_permanent_block_threshold(3)
    .verify_per_ip_per_min_cap(30)                          // 0 = disable
    // Per-row brute-force cap on the 6-digit code. Range 1..=10 enforced at build.
    .code_attempts_per_row(5)
    // Per-token brute-force cap on the URL magic-link. Range 1..=10 enforced at build.
    .link_attempts_per_token(3)
    // Account-level lockout — DEFAULT 0 (disabled). Anyone who knows the email can
    // otherwise burn wrong codes to push SUM over the cap and lock out the legit user
    // (OWASP DoS-via-lockout pattern). Only enable with a separate recovery path.
    .code_failures_per_email_24h_cap(0)
    .same_site(SameSite::Strict)
    .cookie_name_suffix("session")                          // final cookie = __Host-session
    .log_full_email(false)                                  // false = domain only (PII-safe)
    // Pluggable hooks:
    .policy(Arc::new(DisposableBlocklist::with_default_list()))
    .event_sink(Arc::new(MyDatadogSink))
    .build()?;

// Optional: log effective settings on startup so they show up in your aggregator.
cfg.log_settings();
```

Every setter is optional — `AuthConfig::builder(&pepper_b64)?.build()?` produces a
config with sensible defaults (15 min TTLs, 15-issue caps, lockout disabled, etc.).
For tests / KMS-fetched bytes use `AuthConfig::builder_from_pepper(Pepper::from_bytes([..]))`.

### Migration safety (changing config on a live DB)

Every field is "future-proof" — old data keeps working when you change config:

- TTLs (`magic_link_ttl`, `code_ttl`, `session_*_ttl`) are bound at INSERT time. Old rows keep their original `expires_at`; new rows use the new value.
- Caps and windows (`issue_per_*_cap`, `issue_window`) are evaluated on each request from current config — no migration needed.
- `code_attempts_per_row` and `link_attempts_per_token` are enforced 1..=10 by builder validation. The DB does not duplicate the upper bound — config is the single source of truth, no schema migration needed to tweak.
- `issue_block_duration` change applies to new blocks only; existing blocks keep their `expires_at`.
- `ip_permanent_block_threshold` change applies on next escalation decision; past blocks count toward lookback regardless.
- Disabling/enabling `code_failures_per_email_24h_cap` is instant; existing high-SUM emails will lock out (or unlock) on next verify.
- Permanent IP blocks (`expires_at = 'infinity'`) survive cleanup forever — manual `DELETE` required to lift.

---

## Customization (the four traits)

### `Mailer` — required, you provide

```rust
#[async_trait::async_trait]
impl Mailer for MyMailer {
    async fn send_magic_link(
        &self, email: &Email, link: &MagicLinkToken, code: &VerifyCode,
    ) -> Result<(), MailerError> {
        match self.client.send(/* ... */).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_transient() => Err(MailerError::retryable(e.to_string())),  // 5xx, timeouts
            Err(e)                     => Err(MailerError::permanent(e.to_string())),  // 4xx, suspended
        }
    }
}
```

Library makes ONE synchronous attempt; both variants surface to callers as `AuthError::MailerFailed`. The Retryable/Permanent split is for *your* observability and retry layer — wrap the mailer with your queue, look at the variant, decide what to do. The auth call itself does not retry.

### `EmailPolicy` — disposable blocklist + custom rules

```rust
// Bundled list (~5400 domains) with extensions and exceptions:
let policy = DisposableBlocklist::with_default_list()
    .add("internal-spam.example")     // also block this
    .add_iter(["a.example", "b.example"])
    .unblock("mailinator.com");       // QA exception

let cfg = AuthConfig::builder(&pepper_b64)?
    .policy(Arc::new(policy))
    .build()?;

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

## Production deployment

### Trusting the client IP (CRITICAL)

Every per-IP defense — `issue_per_ip_cap`, `ip_permanent_block_threshold`,
`verify_per_ip_per_min_cap` — is only as good as the `IpAddr` you pass in. If you
naively read `X-Forwarded-For` from any incoming request, an attacker rotates the
header and resets every counter you have. Cap = fiction.

**Behind a reverse proxy** (Cloudflare, nginx, ALB), use a crate that validates the
header against a whitelist of trusted proxy CIDRs — for axum:

```rust
use axum_client_ip::{ClientIp, ClientIpSource};

// configure once, with the proxies YOU trust:
let app = Router::new()
    .route("/auth/magic-link", post(magic_link_handler))
    .layer(ClientIpSource::CloudflareConnectingIp.into_extension());
    // or RightmostXForwardedFor / RightmostForwarded with explicit trusted CIDRs

async fn magic_link_handler(ClientIp(ip): ClientIp, /* ... */) { /* ... */ }
```

Same applies to actix (`actix-web` `ConnectionInfo::realip_remote_addr` with explicit
trusted IPs) or any other framework. **Never** read `X-Forwarded-For` directly from
`HeaderMap` without a trust check on the peer address.

The example in `examples/axum.rs` uses `IpAddr::LOCALHOST` as a placeholder — replace
that before deploying.

### Outbound mail volume (out of scope)

This library caps **per-email** (mailbomb on a victim) and **per-IP** (distributed
issue from one source). It does **not** cap *total outbound mail across all callers* —
that's mailer-concern, not auth-concern, and the right limit depends on your provider
plan. Two clean seams to plug your own rate limiter:

**1. `EmailPolicy` — pre-flight veto (preferred for global caps).** Fires before token
generation and DB write, so rejected requests cost nothing. Silent-drop semantics
identical to disposable-domain rejection — attacker can't tell why they were dropped.

```rust
// `bucket` here is whatever rate-limiter you have (governor / leaky-bucket / Redis).
// `governor` example: `RateLimiter<NotKeyed, _, _>` with `.check().is_ok()`.
struct GlobalCapPolicy<L> { limiter: L, inner: DisposableBlocklist }

#[async_trait::async_trait]
impl<L: RateCheck + Send + Sync + 'static> EmailPolicy for GlobalCapPolicy<L> {
    async fn allow(&self, email: &Email) -> bool {
        if !self.limiter.try_acquire().await {
            tracing::warn!(outcome = "global_cap_hit", "outbound mail rate-limited");
            return false;
        }
        self.inner.allow(email).await   // chain disposable check
    }
}

let cfg = AuthConfig::builder(&pepper_b64)?
    .policy(Arc::new(GlobalCapPolicy {
        limiter: my_limiter,
        inner: DisposableBlocklist::with_default_list(),
    }))
    .build()?;
```

**2. `Mailer` wrapper — post-decision veto.** Fires after the row is in `magic_links`
but before the mail leaves. Use this if your token bucket should count *actual sends*
not *attempts*, or if your provider returns rate-limit errors you want to translate.

For cross-replica or cross-service quotas, back the bucket with Redis. Most mailer
providers (SES, Resend, Postmark) also enforce per-API-key rate limits server-side —
check yours before reinventing.

### IPv6 considerations

`auth_ip_blocks.ip` is matched as exact `INET`. An attacker with a /64 prefix (typical
ISP/VPS allocation) has 2^64 addresses. If you're seeing distributed abuse from IPv6,
group by /64 in your reverse proxy / WAF before the request reaches the auth lib —
or fork and change the cap queries to `set_masklen(ip, 64) >>= $1`.

---

## Operating it

### Pepper management

32-byte HMAC key, treated like a DB password:

- Generate once: `openssl rand -base64 32`
- Store in your secrets manager (Vault / 1Password / AWS SM / `.env` for dev)
- Pass the string to `AuthConfig::builder(&pepper)?.build()?`
- **Rotation = full invalidation** — changing the pepper invalidates every session, magic-link, and OTP code. There's no key versioning.

### Multi-instance

All state in Postgres. Two app instances with same `DATABASE_URL` + same pepper share auth state. No Redis needed.

### Cleanup

`magic_links` rows accumulate. Run nightly (e.g. `pg_cron` or sidecar):

```rust
let report = auth_rust::store::cleanup_expired(&pool).await?;
// report.{magic_links_deleted, sessions_deleted, verify_attempts_deleted,
//         email_blocks_deleted, ip_blocks_deleted, total()}
// The function emits its own `tracing::info!` with the counts — your `tracing-subscriber`
// picks it up. No extra logging code needed.
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
| `warn!` | `outcome="email_cap_hit"\|"ip_cap_hit"` | issue rate-limit tripped, email/IP block inserted |
| `warn!` | `outcome="ip_permanent_block"` | repeat-offender IP escalated to permanent block |
| `debug!` | `outcome="email_blocked"\|"ip_blocked"` | already-active block silent-drops the request |
| `debug!` | `outcome="format_invalid"\|"policy_denied"` | other silent drops in `issue_magic_link` |
| `debug!` | `outcome="invalid_token"\|"wrong_code"\|"no_live_row"\|"lost_consume_race"` | normal verify rejections |
| `debug!` | `outcome="no_cookie"\|"lookup_miss"` | normal session lookup misses |

**PII policy:** by default the `email` field contains only the domain (e.g. `gmail.com`) — full addresses don't reach Loki/Tempo. Pass `.log_full_email(true)` to the builder to log the complete address (useful for support debugging; remember the retention implications). Operator searching for a specific user can also use `user_id` (post-verify) or query the `users` table directly. Audit-grade events with full identifiers go through `SessionEventSink` (your audit log / SIEM), separate from observability stack. IP addresses are logged as standard for security investigations (GDPR "legitimate interest").

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
