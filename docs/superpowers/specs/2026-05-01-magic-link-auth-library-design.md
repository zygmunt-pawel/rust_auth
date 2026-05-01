# `auth_rust` — biblioteka auth dla Rusta (magic-link + 6-cyfrowy kod)

**Data:** 2026-05-01 (v2 — security hardening po audicie)
**Status:** zamknięty, gotowy do `writing-plans`

## Zmiany vs. v1 (audit-driven)

Po przeglądzie 4 niezależnych audytów (magic-link / session / rate-limit / crypto) zaktualizowane:

- **HMAC-SHA256 z server-side pepper** zastępuje plain sha256 dla wszystkich hashy (token, code, session). `argon2id` na 6-cyfrowy kod **wycięte** (DoS na verify, niepotrzebne gdy pepper jest w env a nie w DB). Bezpieczeństwo kodu kupują attempt-cap + krótki TTL + rate limit (zgodnie z NIST SP 800-63B §3.2.10 i podejściem Stytch/Clerk).
- **`__Host-` prefix wymuszony** na cookie sesji; `cookie_domain` usunięte z konfiguracji (cookie-tossing z subdomeny eliminowane na poziomie browser-enforced).
- **Per-IP rate limit na `/verify`** (30/min) + globalny licznik failed code attempts per email (>50 w 24h → lockout 1h) — atak "request → 5 prób → request → 5 prób → ...".
- **Constant-time pad na verify** (nie tylko issuance) — dummy HMAC operacja na miss path zapewnia parity CPU.
- **Uniform 200 z `issue_magic_link`** niezależnie od inputu (malformed, rate-limited, blocked, success). Walidacja wewnętrzna, błąd internie do logu, response identyczny.
- **`SameSite=Strict` jako default** (override do `Lax` przez config). Dla console-app brak crosss-site SSO = koszt UX zerowy, klasyczne Lax bypassy znikają.
- **Session rotation** też przy refresh w window <1d, plus publiczny `rotate_session()` helper dla privilege change.
- **Rejection sampling** dla 6-cyfrowego kodu (eliminuje 1.7×10⁻⁴ modulo bias).
- **`EmailPolicy` trait** — silent-skip dla disposable/blocklisted (default `AllowAll`).
- **`SessionEventSink` trait** — callbacki created/refreshed/rotated/revoked (default `NoOpSink`).
- Issuance per-email window **60s minimum** (Supabase default) zamiast flat 5min. Per-IP 5/h + 30/24h.
- Per-token URL attempt counter (cap 3) — defense-in-depth.
- `Set-Cookie` re-emit na refresh (browser-side expiry sync).
- Concurrent-row UPDATE fix: `UPDATE … WHERE expires_at < NOW() + interval '1 day' RETURNING …` zamiast LSP-styled (eliminuje thundering herd).

## Kontekst

Wydzielenie istniejącego prototypu auth (`/Users/pawel/Desktop/auth_rust/`) do reusable
biblioteki publikowanej z GitHuba (`zygmunt-pawel/rust_auth`). Cel: re-use w wielu
osobistych projektach, jak najmniej zależności, biblioteka **wymusza zasady
bezpieczeństwa** (no-knob na rzeczach security-critical).

## Scope MVP (v1)

- ✅ Magic-link issuance (`store::issue_magic_link`) — single email z linkiem + kodem
- ✅ 6-cyfrowy kod jako **alternatywa wymienna** dla URL tokena, dwa niezależne sekrety w
      jednym wierszu `magic_links` (oba HMAC-SHA256 z server-side pepperem)
- ✅ Verify (token *lub* {email, code}) → tworzy sesję
- ✅ Sessions (sliding TTL + absolute TTL, cookie HttpOnly/Secure/SameSite=Strict/__Host-)
- ✅ Logout
- ✅ `lookup_user_by_id` (do `/auth/me` po stronie konsumenta)
- ✅ `rotate_session` (publiczny helper dla privilege change)
- ✅ Auto-signup **przy konsumpcji** (nie przy wysyłce!) — pierwsze udane verify z nieznanym emailem zakłada konto
- ✅ `EmailPolicy` trait (silent-skip disposable / blocklist)
- ✅ `SessionEventSink` trait (audit log hook)
- ❌ Bez haseł, account lockout (poza per-email-failed-codes), change-password, email-verification, 2FA, OAuth, pwned-check, CAPTCHA, anomaly detection, SMTP circuit breaker, IP/UA session binding, magic-link cookie-binding (rozważyć w v1.1) — wszystko OUT z v1

## Architektura — biblioteka eksportuje **tylko funkcje**, transport-agnostic

Dwa publiczne moduły, jedna paczka, **zero feature flag, zero zależności od frameworka HTTP**.

### `auth_rust::core` — czyste, transport-agnostic

- typy: `Email`, `MagicLinkToken`, `VerifyCode`, `SessionToken`, `UserId(i64)`,
  `User { id, public_id, email, status, created_at }`, `ActiveSession`,
  `AuthenticatedUser { id, public_id, email, session_id }`, `AuthError`,
  `Pepper(SecretBytes)` (newtype na 32 bajty pepperu — tylko `Display: "***"`)
- traity: `Mailer`, `UserResolver` (default `AutoSignupResolver`),
  `EmailPolicy` (default `AllowAll`), `SessionEventSink` (default `NoOpSink`)
- konfig: `AuthConfig` (patrz niżej)
- helpery framework-agnostic:
  - `pub fn session_cookie_header_value(token: &SessionToken, cfg: &AuthConfig) -> String` —
    `"__Host-<name>=<value>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=<ttl>"`,
    flagi wymuszone, `__Host-` prefix wymuszony, `Domain` zabronione (no knob)
  - `pub fn session_cookie_clear_header_value(cfg: &AuthConfig) -> String` — wartość
    `Set-Cookie` do logoutu (Max-Age=0, ten sam name + flagi)
  - `pub fn extract_session_cookie_value<'a>(cookie_header: Option<&'a str>, cfg: &AuthConfig) -> Option<&'a str>` —
    parser raw cookie value (bez znajomości axum types)
  - `impl AuthError { pub fn http_status(&self) -> u16 }` — mapping na status:
    - 401: `Unauthorized` / `InvalidToken` / `TokenExpired` / `TokenReused` / `EmailLocked`
    - 429: `RateLimited`
    - 500: `Internal` / `MailerFailed`
- **deps**: `serde`, `thiserror`, `tracing`, `uuid`, `secrecy` (dla `Pepper`/`SecretBytes`).
  Zero DB/HTTP.

### `auth_rust::store` — high-level operacje na `&PgPool` (security-enforced)

```rust
pub async fn issue_magic_link(
    pool: &PgPool,
    email_input: &str,                    // raw input — walidacja wewnętrzna
    ip: IpAddr,
    cfg: &AuthConfig,
    mailer: &impl Mailer,
) -> Result<(), AuthError>;
// Wewnątrz: constant-time pad ~100ms total. Walidacja emaila — internie, błąd nie wycieka.
// Rate limit per-email (60s gap, max 5/24h) + per-IP (5/h + 30/24h distinct emails).
// Generacja dwóch sekretów (32B URL token, 6-digit code z rejection sampling).
// HMAC-SHA256(pepper, plaintext) → INSERT do magic_links.
// EmailPolicy::allow → silent-skip jeśli false (no INSERT, no mailer, ten sam timing).
// JEDNA synchroniczna próba mailer.send_magic_link.
// Każdy MailerError (Retryable | Permanent) propagowany jako AuthError::MailerFailed.
// PUBLICZNIE konsument ZAWSZE odpala wszystko po Ok(()) — nigdy nie zwraca błędu do usera.

pub async fn verify_magic_link_or_code(
    pool: &PgPool,
    input: VerifyInput,                   // { Token } | { Email, Code }
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &impl UserResolver,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError>;
// Wewnątrz: constant-time pad ~100ms. Per-IP throttle (30/min default, configurable).
// Token path: HMAC lookup → atomic UPDATE used_at WHERE used_at IS NULL AND expires_at > NOW() AND link_attempts < 3 RETURNING email.
//             Bump link_attempts na każdą próbę (też z błędem).
// Code path: lookup po (email, code_expires_at), HMAC verify, bump code_attempts.
//            Hard-invalid przy code_attempts >= 5.
// Global lockout: jeśli SUM(code_attempts) per email w 24h > 50 → AuthError::EmailLocked (1h).
// Dummy HMAC verify na miss path (timing parity).
// Resolver.resolve_or_create → create session → sink.session_created → return.

pub async fn authenticate_session(
    pool: &PgPool,
    cookie_value: Option<&str>,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(AuthenticatedUser, Option<String>), AuthError>;
// Returns (user, optional_set_cookie_to_re-emit).
// Lookup po HMAC(pepper, token). Atomic auto-refresh gdy expires_at < NOW() + refresh_threshold:
//   UPDATE sessions SET expires_at = LEAST(NOW() + sliding, absolute_expires_at)
//   WHERE id = $1 AND expires_at < NOW() + threshold RETURNING expires_at;
// Jeśli refresh nastąpił: zwracamy nowy Set-Cookie value (browser expiry sync) + sink.session_refreshed.
// Brak refresh → drugi element None.

pub async fn rotate_session(
    pool: &PgPool,
    cookie_value: &str,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<SessionToken, AuthError>;
// Privilege-change rotation: invalidate stary, INSERT nowy z zachowanym user_id,
// preserve absolute_expires_at z poprzedniej sesji (nie restart 30d cap). sink.session_rotated.

pub async fn delete_session(
    pool: &PgPool,
    cookie_value: Option<&str>,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<Option<UserId>, AuthError>;
// sink.session_revoked po DELETE.

pub async fn lookup_user_by_id(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<User>, AuthError>;

pub fn migrator() -> sqlx::migrate::Migrator;
```

**Hard deps**: `sqlx` (Postgres + macros + migrate + uuid + chrono + ipnetwork),
`sha2`, `hmac`, `subtle`, `rand`, `base64`, `uuid`, `serde`, `thiserror`, `tracing`,
`async-trait`, `secrecy`, `tokio` (z feature `time` — tylko `sleep_until`, brak spawn).

### Brak `auth_rust::axum` / żadnego frameworkowego modułu

Biblioteka **nie zna axum**. Konsument używa `core::session_cookie_header_value` +
`store::authenticate_session` + `AuthError::http_status` żeby zaimplementować swoje
middleware/extractor w ~10 linijkach. Tę integrację pokazujemy w `examples/axum.rs`.

### Czego biblioteka **nie** dostarcza

- Routów / handlerów — konsument pisze ~50 linii glue code'u
- HTTP rate-limit middleware (`tower_governor`) — defense-in-depth, konsument wpina sam
- Metryk Prometheusa
- Kolejki jobów / retry email-sendowe — wysyłka inline, jedna próba synchroniczna,
  każdy `MailerError` propagowany. Konsument decyduje: retry inline / kolejka / log+200.
  Biblioteka nie zarządza background-task lifecycle.

### `examples/axum.rs` — kanoniczne złożenie

W paczce, ale **nie** w public API:
- `AppState { pool, mailer, cfg, sink }`
- `require_session_mw` używające `store::authenticate_session` + obsługa Optional Set-Cookie z return value (~15 linii)
- Extractor `AuthUser`
- Handlery `POST /auth/magic-link`, `POST /auth/verify`, `POST /auth/logout`, `POST /auth/rotate-session`, `GET /auth/me`
- `impl IntoResponse for AuthError`
- Przykładowy `DisposableBlocklist: EmailPolicy` z embedded listą domen (`include_str!`)
- Przykładowy `TracingSink: SessionEventSink` (loguje przez `tracing::info!`)

## Co biblioteka WYMUSZA (zero knob)

Wszystko poniżej zaszyte w `core`/`store`, niedostępne do nadpisania:

- **HMAC-SHA256 z `cfg.token_pepper`** dla wszystkich hashy w DB:
  `magic_links.token_hash`, `magic_links.code_hash`, `sessions.session_token_hash`.
  Pepper **musi** być ustawiony przez konsumenta (32 bajty, base64 z env). Brak pepperu
  w configu = panic przy `AuthConfig::new()`.
- **Random source**: `rand::rngs::OsRng::try_fill_bytes`, propagacja błędu (rand 0.9 idiom).
  Tokeny URL/sesji = 32 bajty → base64url no-pad (43 chars).
  Kod 6-cyfrowy = rejection sampling (`OsRng.next_u32()`, reject jeśli ≥ 4_294_000_000, else `% 1_000_000`, format `{:06}`).
- **Constant-time porównania**: `subtle::ConstantTimeEq` wszędzie gdzie hashy są równouważne w Ruście (HMAC verify path).
- **Constant-time pad ~100 ms** na `issue_magic_link` AND `verify_magic_link_or_code`. Implementacja: `tokio::time::sleep_until(start + 100ms)` na końcu funkcji, niezależnie od ścieżki.
- **Dummy HMAC verify** na verify miss path (timing parity dla code path).
- **Uniform 200 z `issue_magic_link`**: malformed email, rate-limit, EmailPolicy block,
  mailer fail — wszystko zwraca `Ok(())` na zewnątrz po pad. Błędy idą do logu. Tylko `MailerFailed` propagowany dla decyzji konsumenta (retry/queue/log), ale konsumencki handler dalej zwraca 200.
- **Max 5 prób kodu per rekord** (kolumna `code_attempts INT`), potem rekord automatycznie unieważniony (`used_at = NOW()`).
- **Max 3 próby per URL token** (kolumna `link_attempts INT`).
- **Global per-email failed-attempts cap**: `SUM(code_attempts) per email w 24h > 50` → `EmailLocked` na 1h. Sprawdzane na początku verify code path.
- **Session cookie**: `__Host-<configured-name>`, `HttpOnly`, `Secure`, `SameSite=<config>` (default `Strict`), `Path=/`, brak `Domain`.
- **Per-email + per-IP rate limit issuance** wewnątrz `issue_magic_link`:
  - per-email: 60s minimum gap (od ostatniego created_at)
  - per-IP: max 5 distinct recipients w 1h, max 30 distinct w 24h
- **Per-IP rate limit verify** wewnątrz `verify_magic_link_or_code`: 30 prób/min/IP (configurable, default 30).
- **Session rotation przy każdej refresh-on-read** (gdy `expires_at < NOW() + refresh_threshold`): nowy plaintext token, INSERT nowej sesji z preserved `absolute_expires_at`, DELETE starej. Zwracamy `Some(set_cookie_value)` żeby konsument re-emit'ował.
- **Atomic refresh** żeby uniknąć thundering herd: `UPDATE … WHERE expires_at < NOW() + threshold RETURNING …` (jeden wątek wygrywa).
- **fixed `Mailer` trait API**; konsument dostarcza implementację.
- **auto-signup at consumption time**: domyślny `UserResolver::resolve_or_create` INSERT IF NOT EXISTS dopiero przy udanym verify; issuance nigdy nie dotyka tabeli `users`.

## Co konsument konfiguruje (`AuthConfig`)

```rust
pub struct AuthConfig {
    // Cookie
    pub cookie_name_suffix: String,      // np. "session"; finalna nazwa = "__Host-{suffix}"
    pub same_site: SameSite,             // Strict (default) | Lax
    pub session_sliding_ttl: Duration,   // default 7d
    pub session_absolute_ttl: Duration,  // default 30d
    pub session_refresh_threshold: Duration,  // default 1d (refresh gdy zostało <1d)

    // Magic link / code TTL
    pub magic_link_ttl: Duration,        // default 15min
    pub code_ttl: Duration,              // default 5min

    // Rate limits
    pub issue_per_email_min_gap: Duration,    // default 60s
    pub issue_per_email_24h_cap: u32,         // default 5
    pub issue_per_ip_1h_cap: u32,             // default 5 distinct emails
    pub issue_per_ip_24h_cap: u32,            // default 30 distinct emails
    pub verify_per_ip_per_min_cap: u32,       // default 30
    pub code_failures_per_email_24h_cap: u32, // default 50, lockout 1h
    pub email_lockout_duration: Duration,     // default 1h

    // Crypto
    pub token_pepper: Pepper,            // 32 bajty, REQUIRED, panika gdy < 32

    // Hooks
    pub policy: Arc<dyn EmailPolicy>,    // default Arc::new(AllowAll)
    pub event_sink: Arc<dyn SessionEventSink>,  // default Arc::new(NoOpSink)
    // Mailer i UserResolver przekazywane jako parametry funkcji store::, nie w AuthConfig
}

impl AuthConfig {
    pub fn new(token_pepper: Pepper) -> Self { /* defaults */ }
}

pub enum SameSite { Strict, Lax }
```

`token_pepper` jest jedynym wymaganym argumentem. Reszta ma sensible defaults.

Konsument trzyma `Mailer`/`UserResolver` w swoim `AppState` (np. `Arc<dyn Mailer>`).
`policy`/`event_sink` siedzą w `AuthConfig` bo zwykle są stateless lub strict-static
(blocklist załadowany z `include_str!` przy startup).

## Schema — 3 tabele

`users`, `magic_links`, `sessions`. Wszystkie w bibliotece. Migracje z prefiksem `auth_`
(`auth_001_helpers.up.sql`, `auth_002_users.up.sql`, `auth_003_magic_links.up.sql`,
`auth_004_sessions.up.sql`) — sortowanie spójne, łatwo odróżnić od migracji konsumenta.
`migrator()` zwraca `sqlx::migrate::Migrator` zbudowany przez `sqlx::migrate!("./migrations")`.
Konsument wywołuje go obok swojego migrator'a.

### `users`
- `id BIGINT IDENTITY PK`
- `public_id UUID DEFAULT uuidv7() UNIQUE`
- `email TEXT UNIQUE` (CHECK: format)
- `status TEXT DEFAULT 'active'` (`active` / `inactive` / `suspended`)
- `created_at`, `updated_at`
- Trigger `set_updated_at` na UPDATE

Konsument rozszerza przez własną `user_profiles(user_id BIGINT REFERENCES users(id), ...)`.

### `magic_links` — **jeden wiersz, dwa niezależne sekrety + dwa attempt counters**
- `id BIGINT IDENTITY PK`
- `token_hash TEXT NOT NULL UNIQUE` (HMAC-SHA256 hex, 64 chars)
- `code_hash TEXT NOT NULL` (HMAC-SHA256 hex, 64 chars)
- `link_attempts INT NOT NULL DEFAULT 0` (cap 3)
- `code_attempts INT NOT NULL DEFAULT 0` (cap 5)
- `email TEXT NOT NULL` (CHECK: format)
- `ip INET NOT NULL`
- `expires_at TIMESTAMPTZ NOT NULL` (= token TTL)
- `code_expires_at TIMESTAMPTZ NOT NULL` (krótszy niż `expires_at`)
- `used_at TIMESTAMPTZ`
- `created_at TIMESTAMPTZ DEFAULT NOW()`
- CHECK constraints: format emaila, temporal (expires > created etc.)
- Indeksy:
  - `(token_hash)` UNIQUE — lookup w token path
  - `(email, created_at DESC)` — lookup w code path + per-email throttle
  - `(ip, created_at DESC) INCLUDE (email)` — per-IP throttle
  - `(expires_at) WHERE used_at IS NULL` — cleanup
  - `(used_at) WHERE used_at IS NOT NULL` — cleanup

### `sessions`
- `id BIGINT IDENTITY PK`
- `public_id UUID DEFAULT uuidv7() UNIQUE`
- `session_token_hash TEXT NOT NULL UNIQUE` (HMAC-SHA256 hex, 64 chars)
- `user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE`
- `expires_at TIMESTAMPTZ NOT NULL` (sliding)
- `absolute_expires_at TIMESTAMPTZ NOT NULL` (twardy 30d cap, niezmienny)
- `last_seen_at TIMESTAMPTZ DEFAULT NOW()` (update tylko przy refresh, nie per request)
- `created_at TIMESTAMPTZ DEFAULT NOW()`
- `user_agent TEXT` (CHECK: length <= 1024)
- `ip INET`
- Indeksy:
  - `(session_token_hash)` UNIQUE — auth lookup
  - `(user_id)` — list/revoke wszystkich sesji usera
  - `(expires_at)` — cleanup wygasłych

## Mailer trait

```rust
#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send_magic_link(
        &self,
        email: &Email,
        link_token: &MagicLinkToken,    // plaintext do URL
        code: &VerifyCode,              // plaintext 6-cyfrowy
    ) -> Result<(), MailerError>;
}

pub enum MailerError {
    Retryable(Box<dyn std::error::Error + Send + Sync>),
    Permanent(Box<dyn std::error::Error + Send + Sync>),
}
```

Konsument decyduje o template'ie. Oba sekrety w jednym mailu.

## UserResolver trait

```rust
#[async_trait]
pub trait UserResolver: Send + Sync + 'static {
    async fn resolve_or_create(
        &self,
        pool: &PgPool,
        email: &Email,
    ) -> Result<UserId, ResolverError>;
}

pub struct AutoSignupResolver;  // INSERT IF NOT EXISTS, default
```

Wywoływany **wyłącznie** w `verify_magic_link_or_code` po pomyślnej weryfikacji sekretu.
Konsument może podmienić na whitelist domen / invite-only / merge-with-existing-OAuth.

## EmailPolicy trait

```rust
#[async_trait]
pub trait EmailPolicy: Send + Sync + 'static {
    /// Czy wysłać magic-linka? false = silent drop (no INSERT, no mailer, ten sam timing).
    /// MUSI być szybkie (<5ms). Pre-load list / config przy startup. NIE rób tu HTTP/DNS.
    async fn allow(&self, email: &Email) -> bool;
}

pub struct AllowAll;
#[async_trait]
impl EmailPolicy for AllowAll { async fn allow(&self, _: &Email) -> bool { true } }
```

Wywoływany w `issue_magic_link` po rate-limit, przed INSERT/mailer. Konsument używa do
disposable-email blocklist (lista typu `disposable-email-domains` GitHub, embedded
przez `include_str!`), tenant whitelisting itp.

## SessionEventSink trait

```rust
#[async_trait]
pub trait SessionEventSink: Send + Sync + 'static {
    async fn on_event(&self, event: SessionEvent);
}

pub enum SessionEvent {
    Created  { session_id: i64, user_id: i64, ip: IpAddr, user_agent: Option<String> },
    Refreshed{ session_id: i64, user_id: i64 },
    Rotated  { old_session_id: i64, new_session_id: i64, user_id: i64 },
    Revoked  { session_id: i64, user_id: i64 },
}

pub struct NoOpSink;
#[async_trait]
impl SessionEventSink for NoOpSink { async fn on_event(&self, _: SessionEvent) {} }
```

Konsument routuje do SIEM/Sentry/audit-log. Default no-op żeby nie wymuszać zależności.

## Pending decisions

— *(brak — wszystkie kluczowe decyzje zamknięte; security audit w pełni zintegrowany)*

## Następne kroki

1. ✅ Self-review v1
2. ✅ Audit security (4 niezależnych analiz: magic-link, session, rate-limit, crypto)
3. ✅ Spec v2 z hardening
4. → Implementation plan (`writing-plans`)
