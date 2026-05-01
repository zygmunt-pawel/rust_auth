# `auth_rust`

Reusable, security-hardened passwordless auth library for Rust.

- Magic-link + 6-digit code (one email, both work)
- Postgres-backed sessions (sliding + absolute TTL)
- Transport-agnostic — wire into axum/actix/anything in ~50 lines
- HMAC-SHA256 with server-side pepper for all stored hashes
- `__Host-` cookie prefix forced, `HttpOnly` / `Secure` / `SameSite=Strict`
- Constant-time pads on issue and verify
- Built-in rate limits (per-email + per-IP) and 24h global lockout

See `examples/axum.rs` for a complete reference integration.

## Why no JWT?

Instant revocation. No key rotation pain. No `alg: none` / RS-HS confusion CVEs.
DB lookup is sub-ms with the index. JWT's perf "win" is largely mythical for monoliths.

## Quick start

```toml
[dependencies]
auth_rust = { git = "https://github.com/zygmunt-pawel/rust_auth" }
```

```rust
use auth_rust::core::{AuthConfig, Pepper};
use auth_rust::store;

let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
store::migrator().run(&pool).await?;

let pepper = Pepper::from_base64(&std::env::var("AUTH_TOKEN_PEPPER")?);
let cfg = AuthConfig::new(pepper);

// In your magic-link handler:
store::issue_magic_link(&pool, &request.email, ip, &cfg, &mailer).await?;
// (always returns Ok to user — internal errors logged)

// In your verify handler:
let (session_token, _user_id) = store::verify_magic_link_or_code(
    &pool, input, ip, ua, &AutoSignupResolver, &cfg, &sink,
).await?;
```

## Pepper generation

```bash
openssl rand -base64 32  # store as AUTH_TOKEN_PEPPER env var
```

## Migrations namespace

Library migrations use plain integer versions (`001_*` through `004_*`). When running
the library migrator alongside your own consumer migrations, use a non-overlapping
version space — e.g. start your migrations at `100_*` or use timestamp prefixes
(`20260501000001_*`). sqlx's `_sqlx_migrations` table tracks unique integer versions
across all migrators run on the same database.

## License

MIT OR Apache-2.0
