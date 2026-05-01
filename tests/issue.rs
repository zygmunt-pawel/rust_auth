mod common;

use common::{CapturingMailer, loopback_ip, test_config};

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
