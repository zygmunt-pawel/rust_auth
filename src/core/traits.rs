use async_trait::async_trait;

use crate::core::Email;

#[async_trait]
pub trait EmailPolicy: Send + Sync + 'static {
    async fn allow(&self, email: &Email) -> bool;
}

pub struct AllowAll;
#[async_trait]
impl EmailPolicy for AllowAll {
    async fn allow(&self, _email: &Email) -> bool { true }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Created  { session_id: i64, user_id: i64, ip: std::net::IpAddr, user_agent: Option<String> },
    Refreshed{ session_id: i64, user_id: i64 },
    Rotated  { old_session_id: i64, new_session_id: i64, user_id: i64 },
    Revoked  { session_id: i64, user_id: i64 },
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
