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
    _pool: &PgPool, _email: &Email, _code: &crate::core::VerifyCode,
    _ip: IpAddr, _user_agent: Option<&str>,
    _resolver: &impl UserResolver, _cfg: &AuthConfig, _sink: &impl SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    Err(AuthError::Internal("code path not yet implemented".into()))
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
