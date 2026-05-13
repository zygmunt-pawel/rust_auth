use std::net::IpAddr;

use sqlx::PgPool;
use tracing::field;

use crate::core::cookie::{extract_session_cookie_value, session_cookie_header_value};
use crate::core::{
    AuthConfig, AuthError, AuthenticatedUser, Email, SessionEvent, SessionEventSink, SessionId,
    SessionToken, UserId, UserPublicId,
};
use crate::store::hash::hmac_sha256_hex;
use crate::store::to_interval;

#[derive(sqlx::FromRow)]
struct SessionRow {
    session_id: i64,
    user_id: i64,
    user_public_id: uuid::Uuid,
    email: String,
    sliding_expired: bool,
    absolute_expired: bool,
    status: String,
    needs_refresh: bool,
}

#[derive(sqlx::FromRow)]
struct DeletedSessionRow {
    id: i64,
    user_id: i64,
}

#[derive(sqlx::FromRow)]
struct RotatedSessionRow {
    old_id: i64,
    new_id: i64,
    user_id: i64,
}

pub(crate) struct CreatedSession {
    pub session_id: SessionId,
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

    let session_id: i64 = sqlx::query_scalar(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, user_agent, ip)
         VALUES ($1, $2, NOW() + $3, NOW() + $4, $5, $6)
         RETURNING id",
    )
    .bind(&token_hash)
    .bind(user_id.0)
    .bind(to_interval(cfg.session_sliding_ttl))
    .bind(to_interval(cfg.session_absolute_ttl))
    .bind(user_agent)
    .bind(ip)
    .fetch_one(pool)
    .await?;

    Ok(CreatedSession {
        session_id: SessionId(session_id),
        token,
    })
}

#[tracing::instrument(
    name = "auth.session.authenticate",
    skip_all,
    fields(
        user_id = field::Empty,
        session_id = field::Empty,
        outcome = field::Empty,
    ),
)]
pub async fn authenticate_session(
    pool: &PgPool,
    cookie_header: Option<&str>,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(AuthenticatedUser, Option<String>), AuthError> {
    let plaintext = match extract_session_cookie_value(cookie_header, cfg) {
        Some(p) => p,
        None => {
            tracing::Span::current().record("outcome", "no_cookie");
            tracing::debug!(outcome = "no_cookie", "no session cookie present");
            return Err(AuthError::Unauthorized);
        }
    };
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id AS session_id, u.id AS user_id, u.public_id AS user_public_id, u.email,
                s.expires_at <= NOW() AS sliding_expired,
                s.absolute_expires_at <= NOW() AS absolute_expired,
                u.status,
                s.expires_at < NOW() + $2 AS needs_refresh
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.session_token_hash = $1",
    )
    .bind(&token_hash)
    .bind(to_interval(cfg.session_refresh_threshold))
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => {
            tracing::Span::current().record("outcome", "not_found");
            tracing::debug!(outcome = "not_found", "session token not found");
            return Err(AuthError::Unauthorized);
        }
    };

    tracing::Span::current().record("user_id", row.user_id);
    tracing::Span::current().record("session_id", row.session_id);

    // Order matters: an expired cookie must NOT reveal the account status.
    if row.sliding_expired || row.absolute_expired {
        tracing::Span::current().record("outcome", "expired");
        tracing::debug!(outcome = "expired", "session expired");
        return Err(AuthError::Unauthorized);
    }

    match row.status.as_str() {
        "active" => {}
        "suspended" => {
            tracing::Span::current().record("outcome", "user_suspended");
            tracing::warn!(outcome = "user_suspended", "session for suspended account");
            return Err(AuthError::AccountSuspended);
        }
        other => {
            tracing::Span::current().record("outcome", "user_inactive");
            tracing::debug!(outcome = "user_inactive", status = other, "user not active");
            return Err(AuthError::Unauthorized);
        }
    }

    let SessionRow {
        session_id,
        user_id,
        user_public_id,
        email,
        needs_refresh,
        ..
    } = row;

    let email =
        Email::try_from(email).map_err(|_| AuthError::Internal("stored email invalid".into()))?;
    let user = AuthenticatedUser {
        id: UserId(user_id),
        public_id: UserPublicId(user_public_id),
        email,
        session_id: SessionId(session_id),
    };

    if !needs_refresh {
        tracing::Span::current().record("outcome", "ok");
        return Ok((user, None));
    }

    // Atomic in-place refresh — only the first concurrent request wins.
    // Cast to bigint here — sqlx::query_scalar wants a single typed column;
    // returning the timestamp directly works the same and we only care about
    // "did the update fire" via Option::is_some().
    let updated: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "UPDATE sessions
         SET expires_at = LEAST(NOW() + $1, absolute_expires_at),
             last_seen_at = NOW()
         WHERE id = $2
           AND expires_at < NOW() + $3
         RETURNING expires_at",
    )
    .bind(to_interval(cfg.session_sliding_ttl))
    .bind(session_id)
    .bind(to_interval(cfg.session_refresh_threshold))
    .fetch_optional(pool)
    .await?;

    if updated.is_some() {
        sink.on_event(SessionEvent::Refreshed {
            session_id: SessionId(session_id),
            user_id: UserId(user_id),
        })
        .await;
        let token_plain_for_cookie = SessionToken::from_string(plaintext.to_string());
        let cookie = session_cookie_header_value(&token_plain_for_cookie, cfg);
        tracing::Span::current().record("outcome", "refreshed");
        tracing::info!(outcome = "refreshed", "session sliding TTL bumped");
        return Ok((user, Some(cookie)));
    }
    // Another request beat us to the refresh — session is still valid for them.
    tracing::Span::current().record("outcome", "ok_lost_race");
    Ok((user, None))
}

#[tracing::instrument(
    name = "auth.session.delete",
    skip_all,
    fields(user_id = field::Empty, session_id = field::Empty, outcome = field::Empty),
)]
pub async fn delete_session(
    pool: &PgPool,
    cookie_header: Option<&str>,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<Option<(SessionId, UserId)>, AuthError> {
    let Some(plaintext) = extract_session_cookie_value(cookie_header, cfg) else {
        tracing::Span::current().record("outcome", "no_cookie");
        return Ok(None);
    };
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let row: Option<DeletedSessionRow> =
        sqlx::query_as("DELETE FROM sessions WHERE session_token_hash = $1 RETURNING id, user_id")
            .bind(&token_hash)
            .fetch_optional(pool)
            .await?;

    if let Some(DeletedSessionRow { id, user_id }) = row {
        tracing::Span::current().record("session_id", id);
        tracing::Span::current().record("user_id", user_id);
        tracing::Span::current().record("outcome", "revoked");
        tracing::info!(outcome = "revoked", "session revoked");
        sink.on_event(SessionEvent::Revoked {
            session_id: SessionId(id),
            user_id: UserId(user_id),
        })
        .await;
        return Ok(Some((SessionId(id), UserId(user_id))));
    }
    tracing::Span::current().record("outcome", "no_match");
    Ok(None)
}

#[tracing::instrument(
    name = "auth.session.rotate",
    skip_all,
    fields(
        user_id = field::Empty,
        old_session_id = field::Empty,
        new_session_id = field::Empty,
        outcome = field::Empty,
    ),
)]
pub async fn rotate_session(
    pool: &PgPool,
    cookie_header: &str,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<SessionToken, AuthError> {
    let plaintext = match extract_session_cookie_value(Some(cookie_header), cfg) {
        Some(p) => p,
        None => {
            tracing::Span::current().record("outcome", "no_cookie");
            tracing::warn!(
                outcome = "no_cookie",
                "rotate_session called without cookie"
            );
            return Err(AuthError::Unauthorized);
        }
    };
    let old_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let new_token = SessionToken::generate();
    let new_hash = hmac_sha256_hex(&cfg.token_pepper, new_token.as_str());

    let row: Option<RotatedSessionRow> = sqlx::query_as(
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
         SELECT del.id AS old_id, ins.id AS new_id, del.user_id FROM del, ins",
    )
    .bind(&old_hash)
    .bind(&new_hash)
    .bind(to_interval(cfg.session_sliding_ttl))
    .fetch_optional(pool)
    .await?;

    let RotatedSessionRow {
        old_id,
        new_id,
        user_id,
    } = match row {
        Some(r) => r,
        None => {
            tracing::Span::current().record("outcome", "stale_cookie");
            tracing::warn!(
                outcome = "stale_cookie",
                "rotate_session: cookie did not match a live session"
            );
            return Err(AuthError::Unauthorized);
        }
    };

    tracing::Span::current().record("user_id", user_id);
    tracing::Span::current().record("old_session_id", old_id);
    tracing::Span::current().record("new_session_id", new_id);
    tracing::Span::current().record("outcome", "rotated");
    tracing::info!(
        outcome = "rotated",
        "session token rotated (privilege change)"
    );

    sink.on_event(SessionEvent::Rotated {
        old_session_id: SessionId(old_id),
        new_session_id: SessionId(new_id),
        user_id: UserId(user_id),
    })
    .await;
    Ok(new_token)
}
