mod common;

use std::sync::Arc;

use auth_rust::core::{Email, EmailPolicy};
use common::{CapturingMailer, loopback_ip, test_config};

struct DenyAll;
#[async_trait::async_trait]
impl EmailPolicy for DenyAll {
    async fn allow(&self, _: &Email) -> bool { false }
}

#[sqlx::test]
async fn issue_inserts_row_and_calls_mailer_once(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();

    let r = auth_rust::store::issue_magic_link(&pool, "user@example.com", loopback_ip(), &cfg, &*mailer).await;
    assert!(r.is_ok(), "expected Ok, got {r:?}");

    assert_eq!(mailer.count(), 1);
    let (link, code) = mailer.last_for("user@example.com").unwrap();
    assert_eq!(link.len(), 43);   // base64url 32B
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    // Verify a row landed in magic_links with hashed columns (NOT plaintext).
    let row: (String, String, String) = sqlx::query_as(
        "SELECT email, token_hash, code_hash FROM magic_links WHERE email = $1"
    ).bind("user@example.com").fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, "user@example.com");
    assert_eq!(row.1.len(), 64);
    assert_eq!(row.2.len(), 64);
    assert_ne!(row.1, link);   // stored = hash, not plaintext
    assert_ne!(row.2, code);
}

#[sqlx::test]
async fn second_request_within_60s_per_email_is_silent_dropped(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer).await.unwrap();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer).await.unwrap();
    assert_eq!(mailer.count(), 1, "second send should be throttled");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn per_ip_distinct_email_cap_blocks_after_5(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    for n in 0..7 {
        auth_rust::store::issue_magic_link(&pool, &format!("u{n}@e.com"), loopback_ip(), &cfg, &*mailer).await.unwrap();
    }
    assert_eq!(mailer.count(), 5, "at most 5 distinct recipients per IP/hour");
}

#[sqlx::test]
async fn email_policy_block_silent_drops(pool: sqlx::PgPool) {
    let mut cfg = test_config();
    cfg.policy = Arc::new(DenyAll);
    let mailer = CapturingMailer::new();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer).await.unwrap();
    assert_eq!(mailer.count(), 0);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
}
