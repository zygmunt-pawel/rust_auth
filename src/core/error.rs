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
    #[error("email locked")]
    EmailLocked,
    #[error("rate limited")]
    RateLimited,
    #[error("mailer failed")]
    MailerFailed,
    #[error("internal error: {0}")]
    Internal(String),
}

impl AuthError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidToken | Self::TokenExpired | Self::TokenReused
              | Self::Unauthorized | Self::EmailLocked => 401,
            Self::RateLimited => 429,
            Self::MailerFailed | Self::Internal(_) => 500,
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::fmt::Display for StringErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::error::Error for StringErr {}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("user creation rejected: {0}")]
    Rejected(String),
    #[error("internal resolver error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(format!("sqlx: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_mapping() {
        assert_eq!(AuthError::InvalidToken.http_status(), 401);
        assert_eq!(AuthError::TokenExpired.http_status(), 401);
        assert_eq!(AuthError::TokenReused.http_status(), 401);
        assert_eq!(AuthError::Unauthorized.http_status(), 401);
        assert_eq!(AuthError::EmailLocked.http_status(), 401);
        assert_eq!(AuthError::RateLimited.http_status(), 429);
        assert_eq!(AuthError::MailerFailed.http_status(), 500);
        assert_eq!(AuthError::Internal("x".into()).http_status(), 500);
    }
}
