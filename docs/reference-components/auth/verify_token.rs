use std::time::Duration;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use axum_client_ip::ClientIp;
use axum_prometheus::metrics::counter;
use serde::{Deserialize, Serialize};
use sqlx::postgres::types::PgInterval;
use tracing::{Span, field, info, instrument, warn};

use crate::app::AppState;

use super::cookie;
use super::error::ApiError;
use super::repo;
use super::tokens::{generate_token, sha256_hex};

// Jeden counter dla wszystkich outcome-ów logowania. Filter w Promie/Grafanie:
// `sum(rate(auth_login_attempts_total{result="token_expired"}[5m]))`.
const LOGIN_ATTEMPTS: &str = "auth_login_attempts_total";

// Capped sliding (plan ADR): aktywny user dostaje refresh expires_at,
// absolute_expires_at jest twardym capem 30d.
const SESSION_SLIDING_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const SESSION_ABSOLUTE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// Cookie Max-Age = sliding TTL. Po refreshu w bazie cookie zostaje to samo
// (nie zmieniamy wartości tokenu) — browser sam przedłuży expiry następnym
// requestem dopóki sesja żyje. 30d cap pilnuje absolute_expires_at w bazie.
const COOKIE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    status: &'static str,
}

// `email` i `user_id` rejestrujemy późno (po consume / po ensure_user) — `field::Empty`
// rezerwuje miejsce, żeby Span::current().record() miał gdzie wpisać.
#[instrument(
    name = "verify_token",
    skip(state, payload, headers),
    fields(ip = %ip, user_id = field::Empty, email = field::Empty),
)]
pub async fn verify_token(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, Json(payload): Json<VerifyTokenRequest>) -> Result<Response, ApiError> {
    let user_agent_owned = extract_user_agent(&headers);
    let user_agent = user_agent_owned.as_deref();

    // Hash zawsze — niezależnie od długości inputa. Brak wczesnego rejecta
    // żeby nie tworzyć timing oracle "format ok / format zły". SHA-256 i tak
    // produkuje deterministyczny hash z czegokolwiek.
    let token_hash = sha256_hex(&payload.token);

    let mut tx = state.pool.begin().await?;

    // Atomowy consume — RETURNING wpuszcza tylko gdy token był ważny i niezużyty.
    // None = nieistniejący / wygasły / już zużyty (świadomie nie rozróżniamy bez extra SELECT).
    let consumed: Option<String> = sqlx::query_scalar(
        "UPDATE magic_links SET used_at = NOW()
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
         RETURNING email",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?;

    let email = match consumed {
        Some(email) => email,
        None => {
            // ROLLBACK przez Drop tx. Brak / wygasły / już zużyty token — odpowiedź user-side
            // zawsze taka sama (nie wycieka który z trzech), ale internie rozróżniamy dla
            // metryki/logu. Token_hash jest opaque, więc info-leak przez extra SELECT zerowy.
            drop(tx);
            let reason = repo::magic_link_reject_reason(&state.pool, &token_hash).await?;
            warn!(event = "login_failure", reason, token_prefix = &token_hash[..12]);
            counter!(LOGIN_ATTEMPTS, "result" => reason).increment(1);
            return Ok(StatusCode::BAD_REQUEST.into_response());
        }
    };
    Span::current().record("email", field::display(&email));

    // INSERT lazy — Some(...) gdy konto utworzone teraz, None gdy email istniał.
    // status zwracany od razu żeby suspended check nie potrzebował drugiego SELECTa.
    let inserted: Option<(i64, String)> = sqlx::query_as(
        "INSERT INTO users (email, name) VALUES ($1, $2)
         ON CONFLICT (email) DO NOTHING
         RETURNING id, status",
    )
    .bind(&email)
    .bind(derive_name(&email))
    .fetch_optional(&mut *tx)
    .await?;

    let (user_id, status, created) = match inserted {
        Some((id, status)) => (id, status, true),
        None => {
            let (id, status): (i64, String) = sqlx::query_as("SELECT id, status FROM users WHERE email = $1")
                .bind(&email)
                .fetch_one(&mut *tx)
                .await?;
            (id, status, false)
        }
    };
    Span::current().record("user_id", user_id);

    if status != "active" {
        // ROLLBACK przez Drop tx — consume tokenu ginie razem z resztą tx.
        warn!(event = "login_failure", reason = "account_suspended");
        counter!(LOGIN_ATTEMPTS, "result" => "account_suspended").increment(1);
        return Ok(StatusCode::FORBIDDEN.into_response());
    }

    let session_plain = generate_token();
    let session_hash = sha256_hex(&session_plain);

    // expires_at / absolute_expires_at liczone w bazie (NOW() + interval) — bez clock skew app vs DB.
    sqlx::query(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip)
         VALUES ($1, $2, NOW() + $3, NOW() + $4, $5, $6)",
    )
    .bind(&session_hash)
    .bind(user_id)
    .bind(PgInterval::try_from(SESSION_SLIDING_TTL).expect("sliding TTL fits"))
    .bind(PgInterval::try_from(SESSION_ABSOLUTE_TTL).expect("absolute TTL fits"))
    .bind(user_agent)
    .bind(ip)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if created {
        info!(event = "account_created");
        counter!("auth_accounts_created_total").increment(1);
    }
    info!(event = "login_success");
    counter!(LOGIN_ATTEMPTS, "result" => "success").increment(1);

    let cookie_value = cookie::set_cookie(&session_plain, COOKIE_MAX_AGE_SECS);
    Ok((StatusCode::OK, [(SET_COOKIE, cookie_value)], Json(VerifyTokenResponse { status: "ok" })).into_response())
}

// Plan: name = split_part(email, '@', 1) z cleanupem. DB CHECK length 1-200.
// floor_char_boundary jest UTF-8 safe — `&s[..200]` panikuje przy multibyte.
fn derive_name(email: &str) -> &str {
    let local = email.split('@').next().unwrap_or("").trim();
    let base = if local.is_empty() { email } else { local };
    &base[..base.floor_char_boundary(200)]
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::USER_AGENT)?.to_str().ok()?;
    // DB CHECK: user_agent length <= 1024. Truncate UTF-8 safe.
    Some(raw[..raw.floor_char_boundary(1024)].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_name_from_local_part() {
        assert_eq!(derive_name("john.doe@example.com"), "john.doe");
    }

    #[test]
    fn derives_name_falls_back_to_email_when_local_empty() {
        // Email walidator akceptuje "@x.co" (3 chars, contains @). Local part pusty.
        assert_eq!(derive_name("@x.co"), "@x.co");
    }

    #[test]
    fn derives_name_truncates_long_local_part_safely() {
        // 250-znakowy local part — DB CHECK pozwala na 200.
        let local = "a".repeat(250);
        let email = format!("{local}@x.co");
        let name = derive_name(&email);
        assert_eq!(name.len(), 200);
        assert!(name.chars().all(|c| c == 'a'));
    }

    #[test]
    fn derives_name_handles_multibyte_truncation_without_panic() {
        // 100 emoji × 4 bajty = 400 bajtów. floor_char_boundary(200) musi
        // zaokrąglić W DÓŁ na granicę chara — bez tego &s[..200] panikuje.
        let local = "😀".repeat(100);
        let email = format!("{local}@x.co");
        let name = derive_name(&email);
        assert!(name.len() <= 200);
        // Każdy emoji to 4 bajty → max 50 emoji w 200 bajtach.
        assert!(name.chars().all(|c| c == '😀'));
    }
}
