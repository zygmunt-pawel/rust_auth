use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;

use crate::core::{
    AuthConfig, AuthError, Email, MagicLinkToken, SessionEvent, SessionEventSink,
    SessionToken, UserId, UserResolver, VerifyInput,
};
use crate::store::hash::hmac_sha256_hex;
use crate::store::pad::{VERIFY_PAD, start_pad};

pub async fn verify_magic_link_or_code(
    pool: &PgPool,
    input: VerifyInput,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &impl UserResolver,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    let pad = start_pad(VERIFY_PAD);

    if !verify_rate_check_ip(pool, ip, cfg).await? {
        pad.finish().await;
        return Err(AuthError::RateLimited);
    }

    let result = match input {
        VerifyInput::Token(t) => verify_by_token(pool, &t, ip, user_agent, resolver, cfg, sink).await,
        VerifyInput::Code { email, code } => verify_by_code(pool, &email, &code, ip, user_agent, resolver, cfg, sink).await,
    };

    pad.finish().await;
    result
}

/// Stub — Task 23 lands the real implementation backed by auth_verify_attempts table.
async fn verify_rate_check_ip(_pool: &PgPool, _ip: IpAddr, _cfg: &AuthConfig) -> Result<bool, AuthError> {
    Ok(true)
}

async fn verify_by_token(
    pool: &PgPool,
    token: &MagicLinkToken,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &impl UserResolver,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, token.as_str());

    // Bump link_attempts for any matching row, capped at 10.
    sqlx::query(
        "UPDATE magic_links SET link_attempts = LEAST(link_attempts + 1, 10) WHERE token_hash = $1"
    ).bind(&token_hash).execute(pool).await?;

    // Atomic consume: succeeds only if not used, not expired, and link_attempts <= 3.
    let consumed: Option<(String,)> = sqlx::query_as(
        "UPDATE magic_links SET used_at = NOW()
         WHERE token_hash = $1
           AND used_at IS NULL
           AND expires_at > NOW()
           AND link_attempts <= 3
         RETURNING email"
    ).bind(&token_hash).fetch_optional(pool).await?;

    let email_str = match consumed {
        Some((e,)) => e,
        None => return Err(AuthError::InvalidToken),
    };

    let email = Email::try_from(email_str).map_err(|_| AuthError::Internal("stored email invalid".into()))?;
    let user_id = resolver.resolve_or_create(pool, &email).await
        .map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;

    let session = create_session(pool, user_id, ip, user_agent, cfg).await?;
    sink.on_event(SessionEvent::Created {
        session_id: session.session_id,
        user_id: user_id.0,
        ip,
        user_agent: user_agent.map(String::from),
    }).await;

    Ok((session.token, user_id))
}

async fn verify_by_code(
    pool: &PgPool,
    email: &Email,
    code: &crate::core::VerifyCode,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &impl UserResolver,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    // Global lockout check.
    let total_failures: Option<i64> = sqlx::query_scalar(
        "SELECT COALESCE(SUM(code_attempts)::bigint, 0)
         FROM magic_links
         WHERE email = $1 AND created_at > NOW() - INTERVAL '24 hours'"
    ).bind(email.as_str()).fetch_optional(pool).await?;
    if total_failures.unwrap_or(0) >= cfg.code_failures_per_email_24h_cap as i64 {
        // Dummy HMAC anyway for timing parity.
        let _ = hmac_sha256_hex(&cfg.token_pepper, code.as_str());
        return Err(AuthError::EmailLocked);
    }

    let provided_hash = hmac_sha256_hex(&cfg.token_pepper, code.as_str());

    // Find a live row, increment code_attempts atomically, hard-invalidate at 5.
    let row: Option<(i64, String, i32)> = sqlx::query_as(
        "UPDATE magic_links
         SET code_attempts = code_attempts + 1,
             used_at = CASE WHEN code_attempts + 1 >= 5 THEN NOW() ELSE used_at END
         WHERE id = (
             SELECT id FROM magic_links
             WHERE email = $1
               AND used_at IS NULL
               AND code_expires_at > NOW()
             ORDER BY created_at DESC
             LIMIT 1
         )
         RETURNING id, code_hash, code_attempts"
    ).bind(email.as_str()).fetch_optional(pool).await?;

    let (row_id, stored_hash, attempts_after) = match row {
        Some(r) => r,
        None => {
            // Dummy work: still HMAC, still time-equivalent.
            let _ = crate::store::hash::ct_eq_hex(&provided_hash, &provided_hash);
            return Err(AuthError::InvalidToken);
        }
    };

    if !crate::store::hash::ct_eq_hex(&provided_hash, &stored_hash) {
        // Wrong code. The UPDATE already incremented attempts and invalidated at 5.
        let _ = (row_id, attempts_after);
        return Err(AuthError::InvalidToken);
    }

    // Correct code. Mark used (idempotent — UPDATE above only set used_at on 5th).
    sqlx::query("UPDATE magic_links SET used_at = NOW() WHERE id = $1 AND used_at IS NULL")
        .bind(row_id).execute(pool).await?;

    let user_id = resolver.resolve_or_create(pool, email).await
        .map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;
    let session = create_session(pool, user_id, ip, user_agent, cfg).await?;
    sink.on_event(SessionEvent::Created {
        session_id: session.session_id, user_id: user_id.0, ip,
        user_agent: user_agent.map(String::from),
    }).await;

    Ok((session.token, user_id))
}

pub(crate) struct CreatedSession {
    pub session_id: i64,
    pub token: SessionToken,
}

pub(crate) async fn create_session(
    pool: &PgPool, user_id: UserId, ip: IpAddr, user_agent: Option<&str>, cfg: &AuthConfig,
) -> Result<CreatedSession, AuthError> {
    let token = SessionToken::generate();
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, token.as_str());

    let row: (i64,) = sqlx::query_as(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip)
         VALUES ($1, $2, NOW() + $3, NOW() + $4, $5, $6)
         RETURNING id"
    )
    .bind(&token_hash)
    .bind(user_id.0)
    .bind(to_interval(cfg.session_sliding_ttl))
    .bind(to_interval(cfg.session_absolute_ttl))
    .bind(user_agent)
    .bind(ip)
    .fetch_one(pool).await?;

    Ok(CreatedSession { session_id: row.0, token })
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
