use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::core::{AuthError, Email, ResolverError, User, UserId, UserResolver, UserStatus};

pub struct AutoSignupResolver;

#[async_trait]
impl UserResolver for AutoSignupResolver {
    async fn resolve_or_create(
        &self,
        pool: &PgPool,
        email: &Email,
    ) -> Result<UserId, ResolverError> {
        let id: i64 = sqlx::query_scalar(
            "WITH ins AS (
                INSERT INTO users (email) VALUES ($1)
                ON CONFLICT (email) DO NOTHING
                RETURNING id
             )
             SELECT id FROM ins
             UNION ALL
             SELECT id FROM users WHERE email = $1
             LIMIT 1"
        )
        .bind(email.as_str())
        .fetch_one(pool)
        .await
        .map_err(|e| ResolverError::Internal(format!("sqlx: {e}")))?;

        Ok(UserId(id))
    }
}

#[tracing::instrument(name = "auth.lookup_user_by_id", skip(pool), fields(user_id = user_id.0))]
pub async fn lookup_user_by_id(pool: &PgPool, user_id: UserId) -> Result<Option<User>, AuthError> {
    let row: Option<(i64, Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, public_id, email, status, created_at FROM users WHERE id = $1"
    ).bind(user_id.0).fetch_optional(pool).await?;

    let Some((id, public_id, email, status_str, created_at)) = row else {
        return Ok(None);
    };

    // Unparseable status = data integrity issue (DB CHECK should prevent it; if it
    // doesn't, somebody altered the schema). Surface as Internal, not silent None —
    // callers must distinguish "no such user" from "user exists but in unknown state".
    let status = UserStatus::parse(&status_str).ok_or_else(|| {
        tracing::error!(user_id = id, status = %status_str, "user has unparseable status");
        AuthError::Internal(format!("user {id} has unknown status {status_str:?}"))
    })?;

    Ok(Some(User { id: UserId(id), public_id, email, status, created_at }))
}
