mod common;

use auth_rust::core::{MagicLinkToken, VerifyInput};
use auth_rust::store::AutoSignupResolver;
use common::{CapturingMailer, CapturingSink, loopback_ip, test_config};

#[sqlx::test]
async fn verify_with_valid_token_creates_session(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let resolver = AutoSignupResolver;

    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (link_token_str, _) = mailer.last_for("u@e.com").unwrap();
    let token = MagicLinkToken::from_string(link_token_str);

    let (session_token, user_id) = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(token),
        loopback_ip(),
        Some("test-ua"),
        &resolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("verify ok");

    assert_eq!(session_token.as_str().len(), 43);
    assert!(user_id.0 > 0);

    let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(session_count, 1);

    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM magic_links WHERE email = $1")
            .bind("u@e.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(used_at.is_some(), "magic_links row should be marked used");
}

#[sqlx::test]
async fn verify_with_unknown_token_returns_invalid_token(pool: sqlx::PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let resolver = AutoSignupResolver;
    let token = MagicLinkToken::from_string("totally-bogus-token-thats-43-characters-1234".into());

    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(token),
        loopback_ip(),
        None,
        &resolver,
        &cfg,
        &*sink,
    )
    .await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)));
}

#[sqlx::test]
async fn burning_code_does_not_disable_link(pool: sqlx::PgPool) {
    // Core DoS mitigation: an attacker who knows only the email can burn the 6-digit
    // code path with 5 wrong attempts (sets code_burned_at), but the magic link from
    // the original mail must still authenticate the legit user.
    use auth_rust::core::{Email, VerifyCode};
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let resolver = AutoSignupResolver;

    auth_rust::store::issue_magic_link(&pool, "victim@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (link_token_str, _real_code) = mailer.last_for("victim@e.com").unwrap();

    // Attacker burns the code path (5 wrong attempts → code_burned_at = NOW()).
    for _ in 0..5 {
        let _ = auth_rust::store::verify_magic_link_or_code(
            &pool,
            VerifyInput::Code {
                email: Email::try_from("victim@e.com".to_string()).unwrap(),
                code: VerifyCode::from_string("000000".into()),
            },
            loopback_ip(),
            None,
            &resolver,
            &cfg,
            &*sink,
        )
        .await;
    }

    // Sanity: code_burned_at is set, used_at is NOT.
    let (used_at, code_burned_at): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as("SELECT used_at, code_burned_at FROM magic_links WHERE email = $1")
        .bind("victim@e.com")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(used_at.is_none(), "row should not be consumed yet");
    assert!(code_burned_at.is_some(), "code path should be burned");

    // Legit user clicks the link — link path must succeed.
    let token = MagicLinkToken::from_string(link_token_str);
    let (session_token, user_id) = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(token),
        loopback_ip(),
        Some("legit-ua"),
        &resolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("link should still authenticate after code burn");
    assert_eq!(session_token.as_str().len(), 43);
    assert!(user_id.0 > 0);
}

#[sqlx::test]
async fn verify_with_already_used_token_returns_token_reused(pool: sqlx::PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    let resolver = AutoSignupResolver;

    auth_rust::store::issue_magic_link(&pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (link, _) = mailer.last_for("u@e.com").unwrap();
    let token = MagicLinkToken::from_string(link.clone());
    auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(token),
        loopback_ip(),
        None,
        &resolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    let token2 = MagicLinkToken::from_string(link);
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(token2),
        loopback_ip(),
        None,
        &resolver,
        &cfg,
        &*sink,
    )
    .await;
    assert!(matches!(
        r,
        Err(auth_rust::core::AuthError::InvalidToken | auth_rust::core::AuthError::TokenReused)
    ));
}
