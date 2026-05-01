//! Shared test helpers. Each integration test gets a fresh DB via #[sqlx::test].
//!
//! sqlx::test reads `DATABASE_URL` from env, creates a fresh DB per test, runs
//! `migrations/` automatically, and tears down on success.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use auth_rust::core::{
    AuthConfig, Email, Mailer, MailerError, MagicLinkToken, Pepper, SameSite,
    SessionEvent, SessionEventSink, VerifyCode,
};

pub fn test_pepper() -> Pepper {
    Pepper::from_bytes([42u8; 32])
}

pub fn test_config() -> AuthConfig {
    AuthConfig::new(test_pepper())
}

pub fn loopback_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[derive(Default)]
pub struct CapturingMailer {
    pub sent: Mutex<Vec<(String, String, String)>>, // (email, link_token, code)
    pub fail_with: Mutex<Option<MailerError>>,
}

impl CapturingMailer {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    pub fn count(&self) -> usize { self.sent.lock().unwrap().len() }

    pub fn last_for(&self, email: &str) -> Option<(String, String)> {
        self.sent.lock().unwrap().iter().rev()
            .find(|(e, _, _)| e == email)
            .map(|(_, link, code)| (link.clone(), code.clone()))
    }
}

#[async_trait::async_trait]
impl Mailer for CapturingMailer {
    async fn send_magic_link(
        &self,
        email: &Email,
        link_token: &MagicLinkToken,
        code: &VerifyCode,
    ) -> Result<(), MailerError> {
        if let Some(_e) = self.fail_with.lock().unwrap().take() {
            return Err(MailerError::Permanent("forced failure".into()));
        }
        self.sent.lock().unwrap().push((
            email.as_str().to_string(),
            link_token.as_str().to_string(),
            code.as_str().to_string(),
        ));
        Ok(())
    }
}

#[derive(Default)]
pub struct CapturingSink {
    pub events: Mutex<Vec<SessionEvent>>,
}

impl CapturingSink {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }
    pub fn count(&self) -> usize { self.events.lock().unwrap().len() }
}

#[async_trait::async_trait]
impl SessionEventSink for CapturingSink {
    async fn on_event(&self, event: SessionEvent) {
        self.events.lock().unwrap().push(event);
    }
}
