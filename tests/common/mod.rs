//! Shared test helpers. Each integration test spawns its own Postgres 18-alpine
//! container via testcontainers and runs `store::migrator()` against it.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Mutex;

use auth_rust::core::{
    AuthConfig, AuthConfigBuilder, Email, MagicLinkToken, Mailer, MailerError, Pepper,
    SessionEvent, SessionEventSink, VerifyCode,
};
use sqlx::PgPool;
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;

/// Spin up a fresh PG18 container and return a connected pool with migrations
/// applied. Container handle MUST be held by the test (drop = stop container).
pub async fn pg_pool() -> (ContainerAsync<Postgres>, PgPool) {
    let (container, pool) = pg_container_no_migrate().await;
    auth_rust::store::migrator()
        .run(&pool)
        .await
        .expect("migrations apply cleanly");
    (container, pool)
}

/// Same as [`pg_pool`] but without running migrations — used by tests that
/// exercise the migrator itself.
pub async fn pg_container_no_migrate() -> (ContainerAsync<Postgres>, PgPool) {
    let container = Postgres::default()
        .with_tag("18-alpine")
        .start()
        .await
        .expect("docker available");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to PG container");
    (container, pool)
}

pub fn test_pepper() -> Pepper {
    Pepper::from_bytes([42u8; 32])
}

/// Default test config — same as production defaults, just with a fixed pepper.
pub fn test_config() -> AuthConfig {
    AuthConfig::builder_from_pepper(test_pepper())
        .build()
        .expect("default config must validate")
}

/// Builder pre-seeded with the test pepper, for tests that need to override fields.
pub fn test_builder() -> AuthConfigBuilder {
    AuthConfig::builder_from_pepper(test_pepper())
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
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    pub fn last_for(&self, email: &str) -> Option<(String, String)> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .rev()
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
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl SessionEventSink for CapturingSink {
    async fn on_event(&self, event: SessionEvent) {
        self.events.lock().unwrap().push(event);
    }
}
