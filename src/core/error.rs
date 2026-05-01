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

impl<S: Into<String>> From<S> for MailerError {
    fn from(s: S) -> Self {
        struct Msg(String);
        impl std::fmt::Debug for Msg { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) } }
        impl std::fmt::Display for Msg { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.0) } }
        impl std::error::Error for Msg {}
        Self::Permanent(Box::new(Msg(s.into())))
    }
}

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
