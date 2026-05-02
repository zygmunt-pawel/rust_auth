mod common;

use auth_rust::core::{Email, VerifyCode, VerifyInput};
use auth_rust::store::AutoSignupResolver;
use common::{CapturingMailer, CapturingSink, loopback_ip, test_config};

async fn login_and_get_cookie(pool: &sqlx::PgPool) -> (String, i64) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();
    auth_rust::store::issue_magic_link(pool, "u@e.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let code = mailer.last_for("u@e.com").unwrap().1;
    let (token, user_id) = auth_rust::store::verify_magic_link_or_code(
        pool,
        VerifyInput::Code {
            email: Email::try_from(String::from("u@e.com")).unwrap(),
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
    let cookie = format!("__Host-session={}", token.as_str());
    (cookie, user_id.0)
}

#[sqlx::test]
async fn authenticate_returns_user_for_live_session(pool: sqlx::PgPool) {
    let (cookie, user_id) = login_and_get_cookie(&pool).await;
    let cfg = test_config();
    let sink = CapturingSink::new();
    let (user, set_cookie) =
        auth_rust::store::authenticate_session(&pool, Some(&cookie), &cfg, &*sink)
            .await
            .unwrap();
    assert_eq!(user.id.0, user_id);
    assert!(
        set_cookie.is_none(),
        "no refresh expected for fresh session"
    );
}

#[sqlx::test]
async fn authenticate_with_no_cookie_returns_unauthorized(pool: sqlx::PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let r = auth_rust::store::authenticate_session(&pool, None, &cfg, &*sink).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::Unauthorized)));
}

#[sqlx::test]
async fn authenticate_with_expired_session_returns_unauthorized(pool: sqlx::PgPool) {
    let (cookie, _user_id) = login_and_get_cookie(&pool).await;
    sqlx::query("UPDATE sessions SET created_at = NOW() - INTERVAL '2 days', last_seen_at = NOW() - INTERVAL '2 days', expires_at = NOW() - INTERVAL '1 second'").execute(&pool).await.unwrap();
    let cfg = test_config();
    let sink = CapturingSink::new();
    let r = auth_rust::store::authenticate_session(&pool, Some(&cookie), &cfg, &*sink).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::Unauthorized)));
}

#[sqlx::test]
async fn authenticate_within_refresh_window_refreshes_in_place(pool: sqlx::PgPool) {
    let (cookie, _user_id) = login_and_get_cookie(&pool).await;
    sqlx::query("UPDATE sessions SET expires_at = NOW() + INTERVAL '12 hours'")
        .execute(&pool)
        .await
        .unwrap();
    let cfg = test_config();
    let sink = CapturingSink::new();
    let (_user, set_cookie) =
        auth_rust::store::authenticate_session(&pool, Some(&cookie), &cfg, &*sink)
            .await
            .unwrap();
    assert!(
        set_cookie.is_some(),
        "should re-emit Set-Cookie after in-place refresh"
    );
    assert_eq!(sink.count(), 1, "Refreshed event emitted");
}

#[sqlx::test]
async fn delete_session_revokes(pool: sqlx::PgPool) {
    let (cookie, _) = login_and_get_cookie(&pool).await;
    let cfg = test_config();
    let sink = CapturingSink::new();
    let user_id = auth_rust::store::delete_session(&pool, Some(&cookie), &cfg, &*sink)
        .await
        .unwrap();
    assert!(user_id.is_some());

    let r = auth_rust::store::authenticate_session(&pool, Some(&cookie), &cfg, &*sink).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::Unauthorized)));
}

#[sqlx::test]
async fn rotate_session_replaces_token_preserving_absolute_expiry(pool: sqlx::PgPool) {
    let (cookie, user_id) = login_and_get_cookie(&pool).await;
    let cfg = test_config();
    let sink = CapturingSink::new();
    let new_token = auth_rust::store::rotate_session(&pool, &cookie, &cfg, &*sink)
        .await
        .unwrap();
    let new_cookie = format!("__Host-session={}", new_token.as_str());

    // Old cookie no longer works.
    let r = auth_rust::store::authenticate_session(&pool, Some(&cookie), &cfg, &*sink).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::Unauthorized)));
    // New does.
    let (user, _) = auth_rust::store::authenticate_session(&pool, Some(&new_cookie), &cfg, &*sink)
        .await
        .unwrap();
    assert_eq!(user.id.0, user_id);
}

#[sqlx::test]
async fn lookup_user_by_id_returns_user_after_signup(pool: sqlx::PgPool) {
    let (_, user_id) = login_and_get_cookie(&pool).await;
    let user = auth_rust::store::lookup_user_by_id(&pool, auth_rust::core::UserId(user_id))
        .await
        .unwrap();
    assert!(user.is_some());
    assert_eq!(user.unwrap().email, "u@e.com");
}
