use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;
use tracing::field;

use crate::core::cookie::{extract_session_cookie_value, session_cookie_header_value};
use crate::core::{
    AuthConfig, AuthError, AuthenticatedUser, SessionEvent, SessionEventSink, SessionToken, UserId,
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
        session_id: row.0,
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

    let row: Option<(
        i64,
        i64,
        uuid::Uuid,
        String,
        bool,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT s.id, u.id, u.public_id, u.email,
                s.expires_at < NOW() + $2 AS needs_refresh,
                s.absolute_expires_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.session_token_hash = $1
           AND s.expires_at > NOW()
           AND s.absolute_expires_at > NOW()
           AND u.status = 'active'",
    )
    .bind(&token_hash)
    .bind(to_interval(cfg.session_refresh_threshold))
    .fetch_optional(pool)
    .await?;

    let (session_id, user_id, user_public_id, email, needs_refresh, _absolute_expires_at) =
        match row {
            Some(r) => r,
            None => {
                tracing::Span::current().record("outcome", "lookup_miss");
                tracing::debug!(
                    outcome = "lookup_miss",
                    "session token not found / expired / inactive user"
                );
                return Err(AuthError::Unauthorized);
            }
        };

    tracing::Span::current().record("user_id", user_id);
    tracing::Span::current().record("session_id", session_id);

    let user = AuthenticatedUser {
        id: UserId(user_id),
        public_id: user_public_id,
        email,
        session_id,
    };

    if !needs_refresh {
        tracing::Span::current().record("outcome", "ok");
        return Ok((user, None));
    }

    // Atomic in-place refresh — only the first concurrent request wins.
    let updated: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
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
            session_id,
            user_id,
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
) -> Result<Option<UserId>, AuthError> {
    let Some(plaintext) = extract_session_cookie_value(cookie_header, cfg) else {
        tracing::Span::current().record("outcome", "no_cookie");
        return Ok(None);
    };
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, plaintext);

    let row: Option<(i64, i64)> =
        sqlx::query_as("DELETE FROM sessions WHERE session_token_hash = $1 RETURNING id, user_id")
            .bind(&token_hash)
            .fetch_optional(pool)
            .await?;

    if let Some((session_id, user_id)) = row {
        tracing::Span::current().record("session_id", session_id);
        tracing::Span::current().record("user_id", user_id);
        tracing::Span::current().record("outcome", "revoked");
        tracing::info!(outcome = "revoked", "session revoked");
        sink.on_event(SessionEvent::Revoked {
            session_id,
            user_id,
        })
        .await;
        return Ok(Some(UserId(user_id)));
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
         SELECT del.id, ins.id, del.user_id FROM del, ins",
    )
    .bind(&old_hash)
    .bind(&new_hash)
    .bind(to_interval(cfg.session_sliding_ttl))
    .fetch_optional(pool)
    .await?;

    let (old_id, new_id, user_id) = match row {
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
        old_session_id: old_id,
        new_session_id: new_id,
        user_id,
    })
    .await;
    Ok(new_token)
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
