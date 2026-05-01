mod common;

use common::{loopback_ip, test_config, CapturingMailer, CapturingSink};
use auth_rust::core::{Email, VerifyCode, VerifyInput};
use auth_rust::store::AutoSignupResolver;

async fn issue_and_get_code(pool: &sqlx::PgPool, mailer: &common::CapturingMailer, email: &str) -> String {
    let cfg = test_config();
    auth_rust::store::issue_magic_link(pool, email, loopback_ip(), &cfg, mailer).await.unwrap();
    mailer.last_for(email).unwrap().1
}

#[sqlx::test]
async fn verify_with_correct_code_creates_session(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let code_str = issue_and_get_code(&pool, &mailer, "u@e.com").await;

    let (token, _user_id) = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("u@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string(code_str),
        },
        loopback_ip(), None, &AutoSignupResolver, &cfg, &*sink,
    ).await.unwrap();
    assert_eq!(token.as_str().len(), 43);
}

#[sqlx::test]
async fn verify_with_wrong_code_increments_attempts(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let _ = issue_and_get_code(&pool, &mailer, "u@e.com").await;

    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("u@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string("000000".into()),
        },
        loopback_ip(), None, &AutoSignupResolver, &cfg, &*sink,
    ).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)));

    let attempts: i32 = sqlx::query_scalar(
        "SELECT code_attempts FROM magic_links WHERE email = $1"
    ).bind("u@e.com").fetch_one(&pool).await.unwrap();
    assert_eq!(attempts, 1);
}

#[sqlx::test]
async fn five_wrong_attempts_invalidates_row(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let real_code = issue_and_get_code(&pool, &mailer, "u@e.com").await;

    for _ in 0..5 {
        let _ = auth_rust::store::verify_magic_link_or_code(
            &pool,
            VerifyInput::Code {
                email: Email::try_from("u@e.com".to_string()).unwrap(),
                code: VerifyCode::from_string("000000".into()),
            },
            loopback_ip(), None, &AutoSignupResolver, &cfg, &*sink,
        ).await;
    }

    // Now even the real code shouldn't work — row was hard-invalidated.
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("u@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string(real_code),
        },
        loopback_ip(), None, &AutoSignupResolver, &cfg, &*sink,
    ).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)));
}

#[sqlx::test]
async fn email_with_50_failed_attempts_in_24h_is_locked(pool: sqlx::PgPool) {
    // Seed 11 rows × 5 attempts = 55 failed attempts → above the 50 cap.
    sqlx::query(
        "INSERT INTO magic_links (token_hash, code_hash, email, ip, expires_at, code_expires_at, code_attempts)
         SELECT
            md5('t'||g)||md5('t'||g),
            md5('c'||g)||md5('c'||g),
            'locked@e.com', '127.0.0.1'::inet,
            NOW() + INTERVAL '15 minutes', NOW() + INTERVAL '5 minutes',
            5
         FROM generate_series(1, 11) g"
    ).execute(&pool).await.unwrap();

    let cfg = test_config();
    let sink = CapturingSink::new();
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Code {
            email: Email::try_from("locked@e.com".to_string()).unwrap(),
            code: VerifyCode::from_string("123456".into()),
        },
        loopback_ip(), None, &AutoSignupResolver, &cfg, &*sink,
    ).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::EmailLocked)));
}
