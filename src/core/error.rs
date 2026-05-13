use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("token reused")]
    TokenReused,
    #[error("unauthorized")]
    Unauthorized,
    #[error("account suspended")]
    AccountSuspended,
    #[error("email locked")]
    EmailLocked,
    #[error("rate limited")]
    RateLimited,
    #[error("mailer failed")]
    MailerFailed,
    /// Database / storage failure. Wraps `sqlx::Error` directly so observability
    /// keeps the `source()` chain (pool timeout, RowNotFound, Database(..), ...).
    #[error("storage error")]
    Storage(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AuthError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidToken
            | Self::TokenExpired
            | Self::TokenReused
            | Self::Unauthorized
            | Self::AccountSuspended
            | Self::EmailLocked => 401,
            Self::RateLimited => 429,
            Self::MailerFailed | Self::Storage(_) | Self::Internal(_) => 500,
        }
    }
}

#[derive(Debug, Error)]
pub enum MailerError {
    #[error("retryable mailer failure")]
    Retryable(Box<dyn std::error::Error + Send + Sync>),
    #[error("permanent mailer failure")]
    Permanent(Box<dyn std::error::Error + Send + Sync>),
}

impl MailerError {
    /// Build a permanent failure from any string-ish message.
    /// Use for terminal errors (invalid recipient, suspended account, etc.).
    pub fn permanent(msg: impl Into<String>) -> Self {
        Self::Permanent(Box::new(StringErr(msg.into())))
    }

    /// Build a retryable failure from any string-ish message.
    /// Use for transient errors (timeout, 5xx from provider, rate-limit).
    pub fn retryable(msg: impl Into<String>) -> Self {
        Self::Retryable(Box::new(StringErr(msg.into())))
    }
}

/// String wrapper that satisfies `std::error::Error` for the constructors above.
struct StringErr(String);
impl std::fmt::Debug for StringErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::fmt::Display for StringErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for StringErr {}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("user creation rejected: {0}")]
    Rejected(String),
    #[error("internal resolver error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn http_status_mapping() {
        assert_eq!(AuthError::InvalidToken.http_status(), 401);
        assert_eq!(AuthError::TokenExpired.http_status(), 401);
        assert_eq!(AuthError::TokenReused.http_status(), 401);
        assert_eq!(AuthError::Unauthorized.http_status(), 401);
        assert_eq!(AuthError::AccountSuspended.http_status(), 401);
        assert_eq!(AuthError::EmailLocked.http_status(), 401);
        assert_eq!(AuthError::RateLimited.http_status(), 429);
        assert_eq!(AuthError::MailerFailed.http_status(), 500);
        assert_eq!(AuthError::Internal("x".into()).http_status(), 500);
        // Storage maps to 500 just like Internal — Database/Pool errors are not
        // client-recoverable.
        let storage = AuthError::Storage(sqlx::Error::RowNotFound);
        assert_eq!(storage.http_status(), 500);
    }

    #[test]
    fn storage_preserves_source_chain() {
        // Regression guard for the #[from] sqlx::Error wiring — `source()` must
        // surface the wrapped sqlx::Error so structured loggers can downcast it
        // back (e.g. distinguish PoolTimedOut from RowNotFound).
        let auth_err: AuthError = sqlx::Error::RowNotFound.into();
        assert!(matches!(
            auth_err,
            AuthError::Storage(sqlx::Error::RowNotFound)
        ));
        let source = auth_err
            .source()
            .expect("AuthError::Storage must expose its source");
        assert!(
            source.downcast_ref::<sqlx::Error>().is_some(),
            "source() must downcast back to sqlx::Error, got: {source:?}"
        );
    }

    #[test]
    fn sqlx_error_converts_via_question_mark() {
        // Sanity check that the `?` operator still works on sqlx::Error within
        // a function returning Result<_, AuthError> — the entire codebase relies
        // on this.
        fn returns_auth_err() -> Result<(), AuthError> {
            Err::<(), sqlx::Error>(sqlx::Error::RowNotFound)?;
            Ok(())
        }
        assert!(matches!(returns_auth_err(), Err(AuthError::Storage(_))));
    }
}
