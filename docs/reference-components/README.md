# Reference components

Snapshot of the prototype source from `~/Desktop/auth_rust/src/` as of
2026-05-01. **Not** library code — kept here as starting material for the
actual `src/` of this crate. Each file below has notes on what survives,
what gets refactored, and what gets dropped.

## Per-file mapping to library modules

### `auth/email.rs` → `auth_rust::core::email`
- Keep the `Email` newtype + `TryFrom<String>` (lowercase + 3..=254 + has `@`
  + no CR/LF). Move into `core` module.
- Keep validator permissiveness on the local-part — same reasoning as in the
  prototype: tightening requires real test cases.

### `auth/tokens.rs` → split between `core` and `store`
- `generate_token` (32 random bytes → base64url): keep, move to `core` as
  `MagicLinkToken::new()` / `SessionToken::new()`.
- `sha256_hex`: keep as private utility in `store` (used for hashing the
  URL token before INSERT and on lookup).
- **NEW**: add `VerifyCode::new()` returning a 6-digit numeric code, and
  argon2id hashing for the code (sha256 not enough — 20 bits of entropy needs
  computational cost protection).

### `auth/cookie.rs` → `auth_rust::core::session_cookie_header_value`
- Drops the axum `CookieJar` API. Replaces with a framework-agnostic
  `pub fn session_cookie_header_value(token, cfg) -> String` that returns the
  full `Set-Cookie` value with `HttpOnly; Secure; SameSite=Lax; Path=/`
  enforced (no knob).

### `auth/session.rs` → split
- `lookup_active_session` SQL → moves to `store::authenticate_session` (the
  one helper consumers wrap in their own middleware).
- `require_session` axum middleware + `UserId` extractor → **dropped from the
  library**; consumer writes their own (see `examples/axum.rs` in the plan).

### `auth/repo.rs` → `auth_rust::store` (mostly unchanged SQL)
- `insert_magic_link`: keep, but row now includes `code_hash`,
  `code_attempts`, `code_expires_at`. Drop `source_job_id` (apalis is gone).
- `recent_magic_link_for_email`, `distinct_recipients_from_ip`: keep — these
  power the per-email + per-IP rate limit inside `store::issue_magic_link`.
- `magic_link_reject_reason`: keep — used to log/metric the verify rejection
  cause.
- `delete_session`, `lookup_active_session`, `refresh_session_expiry`: keep,
  same SQL shape.

### `auth/jobs.rs` → **dropped**, but extract two pieces
- The apalis worker itself is gone (no background queue in the library).
- Move the `rate_limit_hit` logic (per-email window + per-IP distinct count)
  into the start of `store::issue_magic_link`.
- Move the `MAGIC_LINK_TTL` / window constants into `AuthConfig` (with the
  same defaults: 5 min window, 5 distinct-emails-per-IP cap, 15 min token TTL).

### `auth/magic_link.rs`, `auth/verify_token.rs`, `auth/logout.rs` → `examples/axum.rs`
- These are axum handlers — they become the reference integration in
  `examples/axum.rs`, NOT public API of the crate.
- `verify_token.rs` is the most informative: it has the lookup → consume
  flow that `store::verify_magic_link_or_code` has to enforce internally.

### `auth/error.rs` → `auth_rust::core::AuthError`
- `EmailError` becomes one variant of `AuthError`.
- `IntoResponse` impl is **dropped**; replaced by `AuthError::http_status() -> u16`
  so the library does not depend on axum.

### `middleware.rs` → split
- `constant_time` middleware → **dropped from public API**. The 100ms pad
  moves *inside* `store::issue_magic_link` (anti-enumeration is a security
  primitive, not a transport concern; we can't trust consumers to remember
  to wire it up).
- `stash_client_ip` + `TrustedIpKeyExtractor` → **dropped**. Consumer
  extracts IP themselves (e.g. from `axum-client-ip`) and passes `IpAddr`
  into `store::issue_magic_link`.

### `app.rs` → `examples/axum.rs`
- `build_router` shows router composition with CORS / body limit / IP source.
  This becomes the reference integration. The library does not own the router.
- Tracing setup with `request_id` from `x-request-id` header: nice pattern,
  worth preserving in the example, but library does not enforce it.

### `Cargo.toml.reference` → starting point for the library's `Cargo.toml`
- **Drop**: `apalis`, `apalis-postgres`, `axum`, `axum-client-ip`,
  `axum-prometheus`, `tower-http`, `tower_governor`, `dotenvy`, `tracing-appender`,
  `tracing-subscriber`. None are core auth concerns.
- **Keep**: `sqlx` (Postgres + macros + migrate + uuid + chrono + ipnetwork),
  `serde`, `sha2`, `base64`, `rand`, `uuid`, `tracing`.
- **Add**: `argon2` (for 6-digit code hashing), `thiserror`, `async-trait`
  (for `Mailer` / `UserResolver` traits).
