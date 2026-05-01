# `auth_rust` — biblioteka auth dla Rusta (magic-link + 6-cyfrowy kod)

**Data:** 2026-05-01
**Status:** roboczy (brainstorm w toku — patrz "Pending decisions" na końcu)

## Kontekst

Wydzielenie istniejącego prototypu auth (`/Users/pawel/Desktop/auth_rust/`) do reusable
biblioteki publikowanej z GitHuba (`zygmunt-pawel/rust_auth`). Cel: re-use w wielu
osobistych projektach, jak najmniej zależności, biblioteka **wymusza zasady
bezpieczeństwa** (no-knob na rzeczach security-critical).

## Decyzje już ustalone

### Scope MVP

- ✅ Magic-link issuance + consumption
- ✅ 6-cyfrowy kod jako **alternatywa wymienna** dla URL tokena (oba sekrety
      niezależnie generowane, zapisane w tym samym wierszu — verify akceptuje
      jeden lub drugi)
- ✅ Sessions (sliding TTL + absolute TTL, cookie-based)
- ✅ Logout
- ❌ **Bez haseł na razie** (passwordless only); password flow, account lockout,
      change-password, email-verification, 2FA, OAuth, pwned-check — wszystko OUT z v1

### Architektura — 3 warstwy w jednej paczce, axum default-on

**L3 `auth_rust::core` + `auth_rust::store`** — typy domenowe, traity, funkcje
na `&PgPool`, `migrator()`. Hard deps: `sqlx` (Postgres), `sha2`, `rand`,
`base64`, `uuid`, `serde`, `thiserror`, `tracing`, `argon2` (do hashowania
kodu — patrz "Dwa sekrety" niżej).

**L2 `auth_rust::axum::handlers`** *(feature `axum`, default-on)* — publiczne
handlery (`issue_magic_link_handler`, `verify_handler`, `logout_handler`,
ewentualnie `me_handler`). Plus middleware: `constant_time`, `stash_client_ip`,
`require_session`, extractor `AuthUser(i64)`.

**L1 `auth_rust::axum::router`** — `pub fn router() -> Router<AuthState>`
zwraca gotowy router z `/auth/magic-link`, `/auth/verify`, `/auth/logout`
(+ ewentualnie `/auth/me`), z poprawną kolejnością middleware i opaque error
envelope. Konsument: `Router::new().merge(auth_rust::axum::router()).with_state(state)`
lub `.nest("/api/v1", ...)`.

### Co biblioteka WYMUSZA (zero knob)

- argon2id na hash kodu 6-cyfrowego (sha256 niewystarczające — 20 bitów
  entropii musi mieć computational-cost protection)
- sha256 na hash URL tokena (32 bajty losowe → wysoka entropia, sha256 wystarczy)
- constant-time pad 100 ms na issuance (anti-enumeration)
- max **5 prób kodu per rekord**, potem rekord automatycznie unieważniony
  (`used_at = NOW()` lub osobne pole `code_attempts`)
- session cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`
- per-email + per-IP rate limit issuance wewnątrz `issue_magic_link`
  (5/IP distinct emails / 5 min, 1/email / 5 min — jak w obecnym kodzie)
- fixed `Mailer` trait API; konsument dostarcza implementację (lettre, resend,
  sendgrid, mock — biblioteka nie zna SMTP)

### Co konsument konfiguruje (`AuthConfig`)

- nazwa cookie sesji
- session sliding TTL + absolute TTL + refresh threshold
- magic-link token TTL (default 15 min)
- 6-cyfrowy kod TTL (default 5 min — krótszy bo niższa entropia)
- domain dla cookie
- `Mailer` impl
- opcjonalnie własny `UserResolver` (domyślny: auto-signup)

### Co WYRZUCAMY z obecnego prototypu

- `apalis` + `apalis-postgres` — wysyłka maila inline w handlerze przez
  `Mailer::send_magic_link`; jeśli `Mailer` zwróci `MailerError::Retryable`,
  handler robi `tokio::spawn` z prostym backoffem (no external job queue dep)
- `axum-prometheus` — metryki to problem konsumenta
- `tower_governor` — out z core; opcjonalnie za feature `governor` jako
  defense-in-depth obok wewnętrznego rate-limitu

### Schema — 3 tabele, `users` w bibliotece

`users`, `magic_links`, `sessions`. `users` jest w bibliotece (minimalna:
`id`, `public_id`, `email`, `status`, `created_at`, `updated_at`). Konsument
rozszerza przez własną tabelę `user_profiles(user_id BIGINT REFERENCES
users(id), …)`.

`magic_links` — **jeden wiersz, dwa niezależne sekrety**:
- `token_hash TEXT NOT NULL UNIQUE` (sha256 URL tokena)
- `code_hash TEXT NOT NULL` (argon2id kodu 6-cyfrowego)
- `code_attempts INT NOT NULL DEFAULT 0`
- `code_expires_at TIMESTAMPTZ NOT NULL` (krótszy niż token `expires_at`)
- reszta jak w obecnym schemacie

Migracje z prefiksem `auth_` (`auth_001_helpers`, `auth_002_users`,
`auth_003_magic_links`, `auth_004_sessions`) — sortowanie spójne, łatwo
odróżnić od migracji konsumenta.

### Mailer trait

```rust
#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send_magic_link(
        &self,
        email: &Email,
        link: &MagicLinkUrl,
        code: &VerifyCode,
    ) -> Result<(), MailerError>;
}

pub enum MailerError {
    Retryable(Box<dyn std::error::Error + Send + Sync>),
    Permanent(Box<dyn std::error::Error + Send + Sync>),
}
```

Konsument decyduje o template'ie maila (link + kod w jednym mailu, oba
działają wymiennie).

### UserResolver trait

```rust
#[async_trait]
pub trait UserResolver: Send + Sync + 'static {
    async fn resolve_or_create(&self, pool: &PgPool, email: &Email)
        -> Result<i64, ResolverError>;
}
```

Domyślny `AutoSignupResolver` — INSERT do `users` jeśli email nieznany.
Konsument może podmienić na whitelist / invite-only / merge-with-existing.

## Pending decisions (do dokończenia brainstormu)

1. **Dwa sekrety osobno (token + kod) — confirm OK?** (rekomenduję tak —
   standard branżowy: Slack/Auth0/Stripe)
2. **Default UserResolver: auto-signup czy login-only?** (auto-signup =
   pierwszy magic-link tworzy konto; login-only = nieznany email zwraca 401)
3. **`/auth/me` w L1 routerze** *(GET, zwraca `{user_public_id, email}`
   zalogowanego usera)* — czy potrzebny w v1?

## Następne kroki po dokończeniu brainstormu

1. Dopisać sygnatury wszystkich publicznych funkcji (`store::*`, handlery, errors)
2. Dopisać dokładną schemę SQL wszystkich migracji
3. Self-review, user review
4. Przejście do `writing-plans` dla planu implementacji
