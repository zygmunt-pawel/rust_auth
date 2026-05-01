//! `auth_rust` — passwordless auth library: magic-link + 6-digit code, sessions on Postgres.
//!
//! See `examples/axum.rs` for the canonical integration. The library is transport-agnostic;
//! consumers wire the functions in `store` into their own HTTP framework (axum, actix, etc.).
//!
//! ## Security model (enforced)
//!
//! - HMAC-SHA256 with a server-side pepper for **all** stored hashes (token, code, session).
//! - `__Host-` prefixed cookies, `HttpOnly`, `Secure`, `SameSite=Strict` (default).
//! - Constant-time pad on issue and verify (~100ms) — anti-enumeration.
//! - Per-IP and per-email rate limits inside `issue_magic_link`.
//! - 5 attempts cap per code-row + 50/24h global cap per email → 1h lockout.
//! - Session rotation on refresh (within `session_refresh_threshold`) and via `rotate_session()`.
//!
//! ## Why no JWT?
//!
//! Instant revocation, no key rotation, no `alg: none` / RS-HS confusion CVEs, Postgres
//! lookups are sub-ms with the unique index. The perf "win" of JWT is largely mythical
//! for monolith deployments. If you need stateless, fork.

pub mod core;
pub mod store;
