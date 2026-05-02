use std::net::IpAddr;

use sqlx::PgPool;
use tracing::field;

use crate::core::{
    AuthConfig, AuthError, Email, MagicLinkToken, SessionEvent, SessionEventSink, SessionToken,
    UserId, UserResolver, VerifyInput,
};
use crate::store::hash::hmac_sha256_hex;
use crate::store::pad::{VERIFY_PAD, start_pad};
use crate::store::session::create_session;

#[tracing::instrument(
    name = "auth.verify",
    skip(pool, input, user_agent, resolver, cfg, sink),
    fields(
        path = field::Empty,
        email = field::Empty,
        %ip,
        user_id = field::Empty,
        session_id = field::Empty,
        outcome = field::Empty,
    ),
)]
pub async fn verify_magic_link_or_code(
    pool: &PgPool,
    input: VerifyInput,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &dyn UserResolver,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    let pad = start_pad(VERIFY_PAD);

    if !verify_rate_check_ip(pool, ip, cfg).await? {
        tracing::Span::current().record("outcome", "rate_limited");
        tracing::warn!(outcome = "rate_limited", "verify rate limit hit");
        pad.finish().await;
        return Err(AuthError::RateLimited);
    }

    let result = match input {
        VerifyInput::Token(t) => {
            tracing::Span::current().record("path", "token");
            verify_by_token(pool, &t, ip, user_agent, resolver, cfg, sink).await
        }
        VerifyInput::Code { email, code } => {
            tracing::Span::current().record("path", "code");
            tracing::Span::current().record("email", email.for_log(cfg.log_full_email));
            verify_by_code(pool, &email, &code, ip, user_agent, resolver, cfg, sink).await
        }
    };

    pad.finish().await;
    result
}

async fn verify_rate_check_ip(
    pool: &PgPool,
    ip: IpAddr,
    cfg: &AuthConfig,
) -> Result<bool, AuthError> {
    if cfg.verify_per_ip_per_min_cap == 0 {
        return Ok(true);
    }

    sqlx::query("INSERT INTO auth_verify_attempts (ip) VALUES ($1)")
        .bind(ip)
        .execute(pool)
        .await?;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM auth_verify_attempts
         WHERE ip = $1 AND attempted_at > NOW() - INTERVAL '1 minute'",
    )
    .bind(ip)
    .fetch_one(pool)
    .await?;

    let _ = sqlx::query(
        "DELETE FROM auth_verify_attempts WHERE attempted_at < NOW() - INTERVAL '5 minutes'",
    )
    .execute(pool)
    .await;

    Ok(count < cfg.verify_per_ip_per_min_cap as i64)
}

async fn verify_by_token(
    pool: &PgPool,
    token: &MagicLinkToken,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &dyn UserResolver,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, token.as_str());
    let token_prefix: &str = &token_hash[..12];

    sqlx::query("UPDATE magic_links SET link_attempts = link_attempts + 1 WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(pool)
        .await?;

    // `link_attempts <= $2` enforced via cfg (no magic numbers in SQL — config is SoT).
    let consumed: Option<(String,)> = sqlx::query_as(
        "UPDATE magic_links SET used_at = NOW()
         WHERE token_hash = $1
           AND used_at IS NULL
           AND expires_at > NOW()
           AND link_attempts <= $2
         RETURNING email",
    )
    .bind(&token_hash)
    .bind(cfg.link_attempts_per_token as i32)
    .fetch_optional(pool)
    .await?;

    let email_str = match consumed {
        Some((e,)) => e,
        None => {
            tracing::Span::current().record("outcome", "invalid_token");
            tracing::debug!(
                outcome = "invalid_token",
                token_prefix,
                "token rejected (missing/expired/used/over-attempts)"
            );
            return Err(AuthError::InvalidToken);
        }
    };

    let email = Email::try_from(email_str)
        .map_err(|_| AuthError::Internal("stored email invalid".into()))?;
    tracing::Span::current().record("email", email.for_log(cfg.log_full_email));

    let user_id = resolver
        .resolve_or_create(pool, &email)
        .await
        .map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;
    tracing::Span::current().record("user_id", user_id.0);

    let session = create_session(pool, user_id, ip, user_agent, cfg).await?;
    tracing::Span::current().record("session_id", session.session_id);
    sink.on_event(SessionEvent::Created {
        session_id: session.session_id,
        user_id: user_id.0,
        ip,
        user_agent: user_agent.map(String::from),
    })
    .await;

    tracing::Span::current().record("outcome", "success");
    tracing::info!(outcome = "success", token_prefix, "verify_token success");
    Ok((session.token, user_id))
}

#[allow(clippy::too_many_arguments)] // private helper; reshaping into a struct adds noise without value
async fn verify_by_code(
    pool: &PgPool,
    email: &Email,
    code: &crate::core::VerifyCode,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &dyn UserResolver,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    // Global lockout check — only active when explicitly opted in (cap > 0).
    // cap = 0 means "disabled" — see AuthConfig::code_failures_per_email_24h_cap docs.
    if cfg.code_failures_per_email_24h_cap > 0 {
        let total_failures: Option<i64> = sqlx::query_scalar(
            "SELECT COALESCE(SUM(code_attempts)::bigint, 0)
             FROM magic_links
             WHERE email = $1 AND created_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(email.as_str())
        .fetch_optional(pool)
        .await?;
        let failures = total_failures.unwrap_or(0);
        if failures >= cfg.code_failures_per_email_24h_cap as i64 {
            let _ = hmac_sha256_hex(&cfg.token_pepper, code.as_str()); // dummy HMAC for timing parity
            tracing::Span::current().record("outcome", "email_locked");
            tracing::warn!(
                outcome = "email_locked",
                failures_24h = failures,
                "email locked"
            );
            return Err(AuthError::EmailLocked);
        }
    }

    let provided_hash = hmac_sha256_hex(&cfg.token_pepper, code.as_str());

    // Note: burning the code via N wrong attempts sets `code_burned_at`, NOT `used_at`.
    // The link path (verify_by_token) ignores `code_burned_at`, so an attacker who only
    // knows the email cannot disable the magic link by spamming wrong codes.
    // Outer WHERE re-checks `used_at IS NULL AND code_burned_at IS NULL` after the row
    // lock fires — under concurrent verify_code calls, PG re-evaluates the outer WHERE
    // (not the subselect) when unblocked, so a row burned/consumed by the winner is
    // skipped by the loser instead of being incremented past the cap.
    let row: Option<(i64, String, i32)> = sqlx::query_as(
        "UPDATE magic_links
         SET code_attempts = code_attempts + 1,
             code_burned_at = CASE WHEN code_attempts + 1 >= $2 THEN NOW() ELSE code_burned_at END
         WHERE id = (
             SELECT id FROM magic_links
             WHERE email = $1
               AND used_at IS NULL
               AND code_burned_at IS NULL
               AND code_expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1
         )
           AND used_at IS NULL
           AND code_burned_at IS NULL
         RETURNING id, code_hash, code_attempts",
    )
    .bind(email.as_str())
    .bind(cfg.code_attempts_per_row as i32)
    .fetch_optional(pool)
    .await?;

    let (row_id, stored_hash, attempts_after) = match row {
        Some(r) => r,
        None => {
            let _ = crate::store::hash::ct_eq_hex(&provided_hash, &provided_hash); // dummy ct_eq
            tracing::Span::current().record("outcome", "no_live_row");
            tracing::debug!(outcome = "no_live_row", "no live magic_links row for email");
            return Err(AuthError::InvalidToken);
        }
    };

    if !crate::store::hash::ct_eq_hex(&provided_hash, &stored_hash) {
        tracing::Span::current().record("outcome", "wrong_code");
        tracing::debug!(
            outcome = "wrong_code",
            attempts_after,
            row_invalidated = attempts_after >= 5,
            "code mismatch"
        );
        return Err(AuthError::InvalidToken);
    }

    // One-time-use enforcement: if a concurrent verify already consumed the row, this
    // UPDATE matches 0 rows. Without the rows_affected check both racers would create a
    // session for the same code consumption.
    let consumed =
        sqlx::query("UPDATE magic_links SET used_at = NOW() WHERE id = $1 AND used_at IS NULL")
            .bind(row_id)
            .execute(pool)
            .await?
            .rows_affected();
    if consumed == 0 {
        tracing::Span::current().record("outcome", "lost_consume_race");
        tracing::debug!(
            outcome = "lost_consume_race",
            row_id,
            "code already consumed by concurrent verify"
        );
        return Err(AuthError::InvalidToken);
    }

    let user_id = resolver
        .resolve_or_create(pool, email)
        .await
        .map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;
    tracing::Span::current().record("user_id", user_id.0);

    let session = create_session(pool, user_id, ip, user_agent, cfg).await?;
    tracing::Span::current().record("session_id", session.session_id);
    sink.on_event(SessionEvent::Created {
        session_id: session.session_id,
        user_id: user_id.0,
        ip,
        user_agent: user_agent.map(String::from),
    })
    .await;

    tracing::Span::current().record("outcome", "success");
    tracing::info!(outcome = "success", "verify_code success");
    Ok((session.token, user_id))
}
