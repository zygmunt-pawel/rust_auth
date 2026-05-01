# `auth_rust` — biblioteka auth dla Rusta (magic-link + 6-cyfrowy kod)

**Data:** 2026-05-01
**Status:** roboczy (brainstorm w toku — patrz "Pending decisions" na końcu)

## Kontekst

Wydzielenie istniejącego prototypu auth (`/Users/pawel/Desktop/auth_rust/`) do reusable
biblioteki publikowanej z GitHuba (`zygmunt-pawel/rust_auth`). Cel: re-use w wielu
osobistych projektach, jak najmniej zależności, biblioteka **wymusza zasady
bezpieczeństwa** (no-knob na rzeczach security-critical).

## Scope MVP (v1)

- ✅ Magic-link issuance (`/auth/magic-link` po stronie konsumenta woła `store::issue_magic_link`)
- ✅ 6-cyfrowy kod jako **alternatywa wymienna** dla URL tokena — **dwa niezależne
      sekrety** w jednym wierszu `magic_links`: token sha256 + kod argon2id, oba
      generowane osobno losowo, jeden konsumuje cały rekord
- ✅ Verify (token *lub* {email, code}) → tworzy sesję
- ✅ Sessions (sliding TTL + absolute TTL, cookie HttpOnly/Secure/SameSite=Lax)
- ✅ Logout
- ✅ `lookup_user_by_id` (do `/auth/me` po stronie konsumenta)
- ✅ Auto-signup **przy konsumpcji** (nie przy wysyłce!) — pierwsze udane verify
      z nieznanym emailem zakłada konto
- ❌ Bez haseł, account lockout, change-password, email-verification, 2FA, OAuth,
      pwned-check — wszystko OUT z v1

## Architektura — biblioteka eksportuje **funkcje + middleware**, nie routy

Trzy publiczne moduły, jedna paczka, axum opcjonalny (default-on).

### `auth_rust::core` — czyste, transport-agnostic
- typy: `Email`, `MagicLinkToken`, `VerifyCode`, `SessionToken`, `UserId(i64)`,
  `User { id, public_id, email, status, created_at }`, `ActiveSession`, `AuthError`
- traity: `Mailer`, `UserResolver` (z domyślnym `AutoSignupResolver`)
- konfig: `AuthConfig { magic_link_ttl, code_ttl, session_sliding_ttl,
  session_absolute_ttl, refresh_threshold, cookie_name, cookie_domain }`
- **deps**: `serde`, `thiserror`, `tracing`, `uuid`. Zero DB/HTTP.

### `auth_rust::store` — high-level operacje na `&PgPool` (security-enforced)
```rust
pub async fn issue_magic_link(
    pool: &PgPool,
    email: &Email,
    ip: IpAddr,
    cfg: &AuthConfig,
    mailer: &impl Mailer,
) -> Result<(), AuthError>;
// W środku: constant-time pad, rate limit per-email + per-IP, generacja
// dwóch sekretów, INSERT, wywołanie Mailer.

pub async fn verify_magic_link_or_code(
    pool: &PgPool,
    input: VerifyInput,                   // { Token } | { Email, Code }
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &impl UserResolver,
    cfg: &AuthConfig,
) -> Result<(SessionToken, UserId), AuthError>;
// W środku: lookup po token_hash lub (email, kod argon2id), bump
// code_attempts, automatyczne unieważnienie po 5 nieudanych, mark used_at,
// resolver.resolve_or_create, create session, return token + user_id.

pub async fn lookup_session(
    pool: &PgPool,
    token: &SessionToken,
    cfg: &AuthConfig,
) -> Result<Option<ActiveSession>, AuthError>;

pub async fn refresh_session_expiry(
    pool: &PgPool,
    session_id: i64,
    cfg: &AuthConfig,
) -> Result<(), AuthError>;

pub async fn delete_session(
    pool: &PgPool,
    token: &SessionToken,
) -> Result<Option<UserId>, AuthError>;

pub async fn lookup_user_by_id(
    pool: &PgPool,
    user_id: UserId,
) -> Result<Option<User>, AuthError>;

pub fn migrator() -> sqlx::migrate::Migrator;
```

**Hard deps**: `sqlx` (Postgres), `sha2`, `rand`, `base64`, `argon2`, `uuid`.

### `auth_rust::axum` — middleware + extractor + IntoResponse (feature `axum`, default-on)

**Tylko building blocks**, zero handlerów / routów:
- `pub async fn constant_time(req, next) -> Response` — fn middleware z 100ms deadline
- `pub async fn stash_client_ip(req, next) -> Response` — wstrzykuje TrustedIp z `axum-client-ip`
- `pub async fn require_session(State, req, next) -> Response` — czyta cookie, woła
  `lookup_session`, jeśli `None` → 401, jeśli `Some` → wstrzykuje `AuthUser(i64)` do
  request extensions, idzie dalej; auto-refresh sliding TTL gdy `needs_refresh`
- `pub struct AuthUser(pub i64)` — extractor, kompilator-enforced "tu jest zalogowany user"
- `pub fn build_session_cookie(token: &SessionToken, cfg: &AuthConfig) -> CookieJar` —
  HttpOnly + Secure + SameSite=Lax + Path=/, no-knob na flagi
- `impl IntoResponse for AuthError` — opaque body, status mapping (`InvalidToken`/
  `TokenExpired`/`TokenReused` → 401; `RateLimited` → 429; `Internal` → 500); konsument
  może re-mapować jeśli chce inny envelope

**Hard deps**: `axum`, `axum-client-ip`, `tower`, `cookie`.

### Czego biblioteka **nie** dostarcza i nie planuje

- Routów (`Router`, `pub fn router()`) — konsument pisze ~50 linii glue code'u
- Handlerów (`issue_magic_link_handler`, `verify_handler`) — j.w.
- HTTP rate-limit (`tower_governor`) — wewnętrzny rate-limit per-email/IP w
  `issue_magic_link` jest core security; HTTP-level to defense-in-depth, konsument
  wpina `tower_governor` ze swoim configem jeśli chce
- Metryk Prometheusa
- Kolejki jobów (`apalis`) — wysyłka maila inline w `issue_magic_link`. Pierwsza
  próba synchroniczna; jeśli `Mailer` zwróci `MailerError::Retryable`, `store`
  spawnuje `tokio::spawn` z exp-backoff retry (3 próby: ~1 s / 5 s / 25 s) i
  funkcja zwraca `Ok(())` natychmiast (wpis w DB już jest, idempotentny).
  `MailerError::Permanent` → propagowany do callera od razu.

### `examples/axum.rs` — kanoniczne złożenie

W paczce, ale **nie** w public API. Pokazuje jak konsument pisze:
- handler `POST /auth/magic-link` ze stackiem `[constant_time, stash_client_ip,
  (opcjonalny tower_governor)]`
- handler `POST /auth/verify`
- handler `POST /auth/logout` chroniony `require_session`
- handler `GET /auth/me` chroniony `require_session`, woła `lookup_user_by_id`
- `Router::new()...with_state(state)`

To jest **dokumentacja kolejności layerów + shape state'u**. Konsument copy-paste'uje
na start i modyfikuje (analytics, custom envelope, dodatkowy hook po signup itd.).

## Co biblioteka WYMUSZA (zero knob)

Wszystko poniżej zaszyte w `core`/`store`/`axum`, niedostępne do nadpisania:

- **argon2id** na hash kodu 6-cyfrowego (20 bitów entropii musi mieć computational-cost
  protection przeciwko brute-force-owi)
- **sha256** na hash URL tokena (32 bajty losowe → wysoka entropia, sha256 wystarczy)
- **constant-time pad 100 ms** na issuance (anti-enumeration)
- **max 5 prób kodu per rekord**, potem rekord automatycznie unieważniony
  (kolumna `code_attempts INT`, trigger lub UPDATE w `verify_magic_link_or_code`)
- **session cookie**: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`
- **per-email + per-IP rate limit issuance** wewnątrz `issue_magic_link` (5/IP distinct
  emails / 5 min, 1/email / 5 min — jak w obecnym kodzie)
- **fixed `Mailer` trait API**; konsument dostarcza implementację (lettre, resend,
  sendgrid, mock — biblioteka nie zna SMTP)
- **auto-signup at consumption time**: domyślny `UserResolver::resolve_or_create`
  INSERT do `users` IF NOT EXISTS dopiero przy udanym verify; issuance nigdy nie
  dotyka tabeli `users`

## Co konsument konfiguruje (`AuthConfig`)

- nazwa cookie sesji
- session sliding TTL + absolute TTL + refresh threshold
- magic-link token TTL (default 15 min)
- 6-cyfrowy kod TTL (default 5 min — krótszy bo niższa entropia)
- domain dla cookie
- `Mailer` impl (konsument trzyma w swoim app state, np. jako `Arc<dyn Mailer>`;
  biblioteka **nie** definiuje własnej struktury `AppState`)
- opcjonalnie własny `UserResolver` (domyślny: `AutoSignupResolver`)

## Schema — 3 tabele

`users`, `magic_links`, `sessions`. Wszystkie w bibliotece.

`users` — minimalna: `id`, `public_id` (UUIDv7), `email`, `status`, `created_at`,
`updated_at`. Konsument rozszerza przez własną `user_profiles(user_id BIGINT
REFERENCES users(id), ...)`.

`magic_links` — **jeden wiersz, dwa niezależne sekrety**:
- `id BIGINT IDENTITY PK`
- `token_hash TEXT NOT NULL UNIQUE` (sha256 URL tokena)
- `code_hash TEXT NOT NULL` (argon2id encoded — phc string)
- `code_attempts INT NOT NULL DEFAULT 0`
- `email TEXT NOT NULL`
- `ip INET NOT NULL`
- `expires_at TIMESTAMPTZ NOT NULL` (= token TTL)
- `code_expires_at TIMESTAMPTZ NOT NULL` (krótszy niż `expires_at`)
- `used_at TIMESTAMPTZ`
- `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
- CHECK constraints: format emaila, temporal (expires > created itd.)
- indexy: `(email, created_at)`, `(ip, created_at) INCLUDE (email)`, cleanup expired/used

`sessions` — jak w obecnym schemacie (`session_token_hash` sha256, `user_id` z FK
do `users(id)`, sliding `expires_at` + twardy `absolute_expires_at`, `last_seen_at`,
`user_agent`, `ip`).

Migracje z prefiksem `auth_` (`auth_001_helpers.up.sql`, `auth_002_users.up.sql`,
`auth_003_magic_links.up.sql`, `auth_004_sessions.up.sql`) — sortowanie spójne, łatwo
odróżnić od migracji konsumenta. `migrator()` zwraca `sqlx::migrate::Migrator`
zbudowany przez `sqlx::migrate!("./migrations")`. Konsument wywołuje go obok swojego
migrator'a (sqlx mergeuje po version_id).

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

Konsument decyduje o template'ie maila. Oba sekrety w jednym mailu (link + kod
działają wymiennie).

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

Wywoływany **wyłącznie** w `verify_magic_link_or_code` po pomyślnej weryfikacji
sekretu. Konsument może podmienić na whitelist domen / invite-only / merge-with-
existing-OAuth.

## Pending decisions

— *(brak — wszystkie kluczowe decyzje zamknięte)*

## Następne kroki

1. Self-review tego specu (placeholders, contradictions, ambiguity, scope)
2. User review
3. Przejście do `writing-plans` dla planu implementacji
