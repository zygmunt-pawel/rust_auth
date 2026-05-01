use async_trait::async_trait;
use sqlx::PgPool;

use crate::core::{Email, ResolverError, UserId, UserResolver};

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
