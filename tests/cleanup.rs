mod common;

use auth_rust::core::{Email, VerifyCode, VerifyInput};
use auth_rust::store::AutoSignupResolver;
use common::{CapturingMailer, CapturingSink, loopback_ip, test_config};

#[sqlx::test]
async fn cleanup_with_no_old_rows_returns_zeros(pool: sqlx::PgPool) {
    let report = auth_rust::store::cleanup_expired(&pool).await.unwrap();
    assert_eq!(report.magic_links_deleted, 0);
    assert_eq!(report.sessions_deleted, 0);
    assert_eq!(report.verify_attempts_deleted, 0);
    assert_eq!(report.total(), 0);
}

#[sqlx::test]
async fn cleanup_removes_old_magic_links_keeps_fresh(pool: sqlx::PgPool) {
    // 10 fresh rows (different emails so per-email throttle doesn't kick in).
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    for n in 0..3 {
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
    // 5 old rows (created_at = 10 days ago) directly via SQL.
    sqlx::query(
        "INSERT INTO magic_links (token_hash, code_hash, email, ip, expires_at, code_expires_at, created_at)
         SELECT
            md5('t'||g)||md5('t'||g),
            md5('c'||g)||md5('c'||g),
            'old'||g||'@e.com', '127.0.0.1'::inet,
            (NOW() - INTERVAL '10 days') + INTERVAL '15 minutes',
            (NOW() - INTERVAL '10 days') + INTERVAL '5 minutes',
            NOW() - INTERVAL '10 days'
         FROM generate_series(1, 5) g"
    ).execute(&pool).await.unwrap();

    let report = auth_rust::store::cleanup_expired(&pool).await.unwrap();
    assert_eq!(
        report.magic_links_deleted, 5,
        "5 old rows should be deleted"
    );

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 3, "3 fresh rows survive");
}

#[sqlx::test]
async fn cleanup_removes_dead_sessions_keeps_live(pool: sqlx::PgPool) {
    // Create a live session via the full flow.
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let code = mailer.last_for("u@e.com").unwrap().1;
    auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("u@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string(code),
        },
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    // Now expire one session manually (set absolute_expires_at to past). Need to also push
    // related timestamps so the temporal CHECK doesn't fail. We do INSERT of a dead session
    // for a different user_id to keep the live one untouched.
    let dead_user_id: i64 =
        sqlx::query_scalar("INSERT INTO users (email) VALUES ('dead@e.com') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO sessions
            (session_token_hash, user_id, expires_at, absolute_expires_at, last_seen_at, created_at)
         VALUES (
            md5('dead-session')||md5('dead-session-2'),
            $1,
            NOW() - INTERVAL '40 days',
            NOW() - INTERVAL '1 day',
            NOW() - INTERVAL '41 days',
            NOW() - INTERVAL '41 days'
         )",
    )
    .bind(dead_user_id)
    .execute(&pool)
    .await
    .unwrap();

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, 2);

    let report = auth_rust::store::cleanup_expired(&pool).await.unwrap();
    assert_eq!(report.sessions_deleted, 1);

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after, 1, "live session survives");
}

#[sqlx::test]
async fn cleanup_removes_old_verify_attempts(pool: sqlx::PgPool) {
    // Insert 5 old + 3 fresh attempts.
    sqlx::query(
        "INSERT INTO auth_verify_attempts (ip, attempted_at)
         SELECT '127.0.0.1'::inet, NOW() - INTERVAL '10 minutes' FROM generate_series(1, 5)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO auth_verify_attempts (ip, attempted_at)
         SELECT '127.0.0.1'::inet, NOW() FROM generate_series(1, 3)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let report = auth_rust::store::cleanup_expired(&pool).await.unwrap();
    assert_eq!(report.verify_attempts_deleted, 5);

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_verify_attempts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 3);
}
