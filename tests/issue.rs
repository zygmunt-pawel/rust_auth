mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use auth_rust::core::{Email, EmailPolicy};
use common::{CapturingMailer, loopback_ip, test_builder, test_config};

struct DenyAll;
#[async_trait::async_trait]
impl EmailPolicy for DenyAll {
    async fn allow(&self, _: &Email) -> bool {
        false
    }
}

#[sqlx::test]
async fn issue_inserts_row_and_calls_mailer_once(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();

    let r = auth_rust::store::issue_magic_link(
        &pool,
        "user@example.com",
        loopback_ip(),
        &cfg,
        &*mailer,
    )
    .await;
    assert!(r.is_ok(), "expected Ok, got {r:?}");

    assert_eq!(mailer.count(), 1);
    let (link, code) = mailer.last_for("user@example.com").unwrap();
    assert_eq!(link.len(), 43);
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    let row: (String, String, String) =
        sqlx::query_as("SELECT email, token_hash, code_hash FROM magic_links WHERE email = $1")
            .bind("user@example.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, "user@example.com");
    assert_eq!(row.1.len(), 64);
    assert_eq!(row.2.len(), 64);
    assert_ne!(row.1, link);
    assert_ne!(row.2, code);
}

#[sqlx::test]
async fn fifteen_issues_pass_sixteenth_blocks_email(pool: sqlx::PgPool) {
    // Per-email cap is 15 in 30 min. 16th attempt → email block inserted, silent drop.
    // Disable per-IP cap so we can isolate the per-email behaviour (otherwise IP cap
    // fires first since both are 15).
    let cfg = test_builder().issue_per_ip_cap(0).build().unwrap();
    let mailer = CapturingMailer::new();

    for _ in 0..15 {
        auth_rust::store::issue_magic_link(&pool, "victim@e.com", loopback_ip(), &cfg, &*mailer)
            .await
            .unwrap();
    }
    assert_eq!(mailer.count(), 15);

    auth_rust::store::issue_magic_link(&pool, "victim@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    assert_eq!(mailer.count(), 15, "16th must be silent-dropped");

    // An active email block now exists.
    let blocks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_email_blocks WHERE email = $1 AND expires_at > NOW()",
    )
    .bind("victim@e.com")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(blocks, 1, "exactly one active block row");
}

#[sqlx::test]
async fn block_does_not_extend_on_repeat_attempts(pool: sqlx::PgPool) {
    // After cap hit, further attempts during the block must NOT insert another block
    // row (= must not extend cooldown).
    let cfg = test_builder().issue_per_ip_cap(0).build().unwrap();
    let mailer = CapturingMailer::new();

    for _ in 0..16 {
        auth_rust::store::issue_magic_link(&pool, "victim@e.com", loopback_ip(), &cfg, &*mailer)
            .await
            .unwrap();
    }
    let blocks_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_email_blocks WHERE email = $1")
            .bind("victim@e.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(blocks_before, 1);

    // Hammer 10 more times.
    for _ in 0..10 {
        auth_rust::store::issue_magic_link(&pool, "victim@e.com", loopback_ip(), &cfg, &*mailer)
            .await
            .unwrap();
    }
    let blocks_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_email_blocks WHERE email = $1")
            .bind("victim@e.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        blocks_after, 1,
        "no additional block row inserted while still blocked"
    );
    assert_eq!(mailer.count(), 15, "no extra mails sent during block");
}

#[sqlx::test]
async fn fifteen_issues_pass_sixteenth_blocks_ip(pool: sqlx::PgPool) {
    // Per-IP cap mirrors per-email: 15 issues from one IP, 16th blocks the IP.
    // Disable per-email cap so distinct emails from one IP don't trip it first.
    let cfg = test_builder().issue_per_email_cap(0).build().unwrap();
    let mailer = CapturingMailer::new();

    for n in 0..15 {
        auth_rust::store::issue_magic_link(
            &pool,
            &format!("u{n}@e.com"),
            loopback_ip(),
            &cfg,
            &*mailer,
        )
        .await
        .unwrap();
    }
    assert_eq!(mailer.count(), 15);

    auth_rust::store::issue_magic_link(&pool, "u15@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    assert_eq!(
        mailer.count(),
        15,
        "16th distinct email from same IP silent-dropped"
    );

    let ip_blocks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_ip_blocks WHERE ip = '127.0.0.1'::inet AND expires_at > NOW()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ip_blocks, 1);
}

#[sqlx::test]
async fn ip_permanent_block_after_three_blocks_in_24h(pool: sqlx::PgPool) {
    // Seed 3 expired blocks for an IP within the last 24h to simulate a repeat
    // offender. The 4th block should escalate to permanent (expires_at = 'infinity').
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    sqlx::query(
        "INSERT INTO auth_ip_blocks (ip, blocked_at, expires_at)
         SELECT $1, NOW() - INTERVAL '4 hours' * g, NOW() - INTERVAL '4 hours' * g + INTERVAL '30 minutes'
         FROM generate_series(1, 3) g"
    ).bind(ip).execute(&pool).await.unwrap();

    let cfg = test_builder().issue_per_email_cap(0).build().unwrap();
    let mailer = CapturingMailer::new();

    // Trip the cap once more (16 issues from this IP).
    for n in 0..16 {
        auth_rust::store::issue_magic_link(&pool, &format!("u{n}@e.com"), ip, &cfg, &*mailer)
            .await
            .unwrap();
    }

    // Newest block for this IP should be permanent.
    let is_permanent: bool = sqlx::query_scalar(
        "SELECT (expires_at = 'infinity'::timestamptz) FROM auth_ip_blocks
         WHERE ip = $1 ORDER BY blocked_at DESC LIMIT 1",
    )
    .bind(ip)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_permanent, "4th block in 24h must escalate to permanent");
}

#[sqlx::test]
async fn active_block_silent_drops_with_no_mailer_call(pool: sqlx::PgPool) {
    // Pre-seed an active email block; subsequent issue must be silent-dropped.
    sqlx::query(
        "INSERT INTO auth_email_blocks (email, expires_at) VALUES ($1, NOW() + INTERVAL '30 minutes')"
    ).bind("u@e.com").execute(&pool).await.unwrap();

    let cfg = test_config();
    let mailer = CapturingMailer::new();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    assert_eq!(mailer.count(), 0);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test]
async fn new_issue_invalidates_previous_link_and_code(pool: sqlx::PgPool) {
    // "Newest mail wins" — issuing a new magic link must invalidate every previously
    // live row for the same email, both link path AND code path. User-intuition match
    // (Auth0/Supabase pattern).
    use auth_rust::core::{Email, MagicLinkToken, VerifyCode, VerifyInput};
    use auth_rust::store::AutoSignupResolver;

    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = common::CapturingSink::new();

    // 1st issue — capture old token + code.
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (old_link, old_code) = mailer.last_for("u@e.com").unwrap();

    // 2nd issue — capture new token + code.
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (new_link, new_code) = mailer.last_for("u@e.com").unwrap();
    assert_ne!(old_link, new_link, "new issue must produce a new token");
    assert_ne!(old_code, new_code, "new issue must produce a new code");

    // Old LINK must NOT log in — the previous row's used_at is now set.
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(MagicLinkToken::from_string(old_link)),
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await;
    assert!(
        matches!(r, Err(auth_rust::core::AuthError::InvalidToken)),
        "old link must be invalidated; got {r:?}"
    );

    // Old CODE must NOT log in either.
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("u@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string(old_code),
        },
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await;
    assert!(
        matches!(r, Err(auth_rust::core::AuthError::InvalidToken)),
        "old code must be invalidated; got {r:?}"
    );

    // New LINK still works.
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(MagicLinkToken::from_string(new_link)),
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await;
    assert!(r.is_ok(), "new link must authenticate; got {r:?}");
}

#[sqlx::test]
async fn email_policy_block_silent_drops(pool: sqlx::PgPool) {
    let cfg = test_builder().policy(Arc::new(DenyAll)).build().unwrap();
    let mailer = CapturingMailer::new();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    assert_eq!(mailer.count(), 0);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
