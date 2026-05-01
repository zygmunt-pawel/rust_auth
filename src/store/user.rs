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

pub async fn lookup_user_by_id(pool: &PgPool, user_id: UserId) -> Result<Option<User>, AuthError> {
    let row: Option<(i64, Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, public_id, email, status, created_at FROM users WHERE id = $1"
    ).bind(user_id.0).fetch_optional(pool).await?;

    Ok(row.and_then(|(id, public_id, email, status_str, created_at)| {
        UserStatus::parse(&status_str).map(|status| User {
            id: UserId(id), public_id, email, status, created_at,
        })
    }))
}
