use async_trait::async_trait;
use sqlx::PgPool;

use crate::core::{
    Email, IdentitySubject, MagicLinkToken, MailerError, ProviderId, ResolverError, SessionId,
    UserId, VerifyCode,
};

#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send_magic_link(
        &self,
        email: &Email,
        link_token: &MagicLinkToken,
        code: &VerifyCode,
    ) -> Result<(), MailerError>;
}

#[async_trait]
pub trait UserResolver: Send + Sync + 'static {
    async fn resolve_or_create(
        &self,
        pool: &PgPool,
        email: &Email,
    ) -> Result<UserId, ResolverError>;
}

#[async_trait]
pub trait EmailPolicy: Send + Sync + 'static {
    async fn allow(&self, email: &Email) -> bool;

    /// Short identifier surfaced by `AuthConfig::log_settings()`. Override if you want
    /// your custom policy to show up in the startup log instead of the generic name.
    fn name(&self) -> &'static str {
        "custom"
    }
}

pub struct AllowAll;
#[async_trait]
impl EmailPolicy for AllowAll {
    async fn allow(&self, _email: &Email) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        "AllowAll"
    }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Created {
        session_id: SessionId,
        user_id: UserId,
        ip: std::net::IpAddr,
        user_agent: Option<String>,
    },
    Refreshed {
        session_id: SessionId,
        user_id: UserId,
    },
    Rotated {
        old_session_id: SessionId,
        new_session_id: SessionId,
        user_id: UserId,
    },
    Revoked {
        session_id: SessionId,
        user_id: UserId,
    },
    /// Emitted when an external identity (e.g. Google, Apple) is attached to a
    /// user — either at first sign-in (new user) or when the same email matched
    /// an existing magic-link account (auto-link). Not emitted on subsequent
    /// logins via an already-linked identity.
    IdentityLinked {
        user_id: UserId,
        provider: ProviderId,
        subject: IdentitySubject,
    },
}

#[async_trait]
pub trait SessionEventSink: Send + Sync + 'static {
    async fn on_event(&self, event: SessionEvent);
}

pub struct NoOpSink;
#[async_trait]
impl SessionEventSink for NoOpSink {
    async fn on_event(&self, _event: SessionEvent) {}
}
