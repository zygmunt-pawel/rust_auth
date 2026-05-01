use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;

use crate::core::{
    AuthConfig, AuthError, AuthenticatedUser, SessionEvent, SessionEventSink,
    SessionToken, UserId,
};
use crate::core::cookie::{
    extract_session_cookie_value, session_cookie_header_value,
};
use crate::store::hash::hmac_sha256_hex;

pub(crate) struct CreatedSession {
    pub session_id: i64,
    pub token: SessionToken,
}

pub(crate) async fn create_session(
    pool: &PgPool,
    user_id: UserId,
    ip: IpAddr,
    user_agent: Option<&str>,
    cfg: &AuthConfig,
) -> Result<CreatedSession, AuthError> {
    let token = SessionToken::generate();
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, token.as_str());

    let row: (i64,) = sqlx::query_as(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip)
         VALUES ($1, $2, NOW() + $3, NOW() + $4, $5, $6)
         RETURNING id"
    )
    .bind(&token_hash).bind(user_id.0)
    .bind(to_interval(cfg.session_sliding_ttl)).bind(to_interval(cfg.session_absolute_ttl))
    .bind(user_agent).bind(ip)
    .fetch_one(pool).await?;

    Ok(CreatedSession { session_id: row.0, token })
}

pub async fn authenticate_session(
    pool: &PgPool,
    cookie_header: Option<&str>,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<(AuthenticatedUser, Option<String>), AuthError> {
    let plaintext = extract_session_cookie_value(cookie_header, cfg).ok_or(AuthError::Unauthorized)?;
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let row: Option<(i64, i64, uuid::Uuid, String, bool, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT s.id, u.id, u.public_id, u.email,
                s.expires_at < NOW() + $2 AS needs_refresh,
                s.absolute_expires_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.session_token_hash = $1
           AND s.expires_at > NOW()
           AND s.absolute_expires_at > NOW()
           AND u.status = 'active'"
    )
    .bind(&token_hash)
    .bind(to_interval(cfg.session_refresh_threshold))
    .fetch_optional(pool).await?;

    let (session_id, user_id, user_public_id, email, needs_refresh, absolute_expires_at) = match row {
        Some(r) => r,
        None => return Err(AuthError::Unauthorized),
    };

    let user = AuthenticatedUser {
        id: UserId(user_id),
        public_id: user_public_id,
        email,
        session_id,
    };

    if !needs_refresh {
        return Ok((user, None));
    }

    // Rotation on refresh: insert new session, delete old, return new cookie value.
    // Preserve absolute_expires_at from the old session.
    let new_token = SessionToken::generate();
    let new_hash = hmac_sha256_hex(&cfg.token_pepper, new_token.as_str());
    let new_id: (i64,) = sqlx::query_as(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip,
             last_seen_at)
         SELECT $1, user_id, LEAST(NOW() + $2, $3), $3, user_agent, ip, NOW()
         FROM sessions WHERE id = $4
         RETURNING id"
    )
    .bind(&new_hash)
    .bind(to_interval(cfg.session_sliding_ttl))
    .bind(absolute_expires_at)
    .bind(session_id)
    .fetch_one(pool).await?;

    sqlx::query("DELETE FROM sessions WHERE id = $1").bind(session_id).execute(pool).await?;

    sink.on_event(SessionEvent::Rotated {
        old_session_id: session_id,
        new_session_id: new_id.0,
        user_id,
    }).await;

    let cookie = session_cookie_header_value(&new_token, cfg);
    let user = AuthenticatedUser {
        session_id: new_id.0,
        ..user
    };
    Ok((user, Some(cookie)))
}

pub async fn delete_session(
    pool: &PgPool,
    cookie_header: Option<&str>,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<Option<UserId>, AuthError> {
    let Some(plaintext) = extract_session_cookie_value(cookie_header, cfg) else { return Ok(None); };
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let row: Option<(i64, i64)> = sqlx::query_as(
        "DELETE FROM sessions WHERE session_token_hash = $1 RETURNING id, user_id"
    ).bind(&token_hash).fetch_optional(pool).await?;

    if let Some((session_id, user_id)) = row {
        sink.on_event(SessionEvent::Revoked { session_id, user_id }).await;
        return Ok(Some(UserId(user_id)));
    }
    Ok(None)
}

pub async fn rotate_session(
    pool: &PgPool,
    cookie_header: &str,
    cfg: &AuthConfig,
    sink: &impl SessionEventSink,
) -> Result<SessionToken, AuthError> {
    let plaintext = extract_session_cookie_value(Some(cookie_header), cfg).ok_or(AuthError::Unauthorized)?;
    let old_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let new_token = SessionToken::generate();
    let new_hash = hmac_sha256_hex(&cfg.token_pepper, new_token.as_str());

    let row: Option<(i64, i64, i64)> = sqlx::query_as(
        "WITH src AS (
            SELECT id, user_id, absolute_expires_at, user_agent, ip
            FROM sessions WHERE session_token_hash = $1
              AND expires_at > NOW() AND absolute_expires_at > NOW()
         ),
         ins AS (
            INSERT INTO sessions
              (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip)
            SELECT $2, user_id, LEAST(NOW() + $3, absolute_expires_at), absolute_expires_at, user_agent, ip
            FROM src
            RETURNING id
         ),
         del AS (
            DELETE FROM sessions WHERE id = (SELECT id FROM src)
            RETURNING id, user_id
         )
         SELECT del.id, ins.id, del.user_id FROM del, ins"
    )
    .bind(&old_hash)
    .bind(&new_hash)
    .bind(to_interval(cfg.session_sliding_ttl))
    .fetch_optional(pool).await?;

    let (old_id, new_id, user_id) = row.ok_or(AuthError::Unauthorized)?;
    sink.on_event(SessionEvent::Rotated { old_session_id: old_id, new_session_id: new_id, user_id }).await;
    Ok(new_token)
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
