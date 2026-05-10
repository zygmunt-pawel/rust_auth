//! `complete_identity_login` orchestration tests — provider-agnostic.
//!
//! Uses a `StubProvider` so we test the linking + session logic without
//! standing up a real Google verifier (that surface is covered in
//! `tests/google_verifier.rs`).

mod common;

use async_trait::async_trait;
use sqlx::PgPool;

use auth_rust::core::{
    AuthError, Email, IdentityError, IdentityProvider, IdentitySubject, ProviderId, SessionEvent,
    VerifiedIdentity, VerifyInput,
};
use auth_rust::store::{AutoSignupResolver, complete_identity_login, verify_magic_link_or_code};
use common::{CapturingMailer, CapturingSink, loopback_ip, test_config};

// ───────────────────────────── helpers ─────────────────────────────

struct StubProvider {
    provider_id: ProviderId,
    response: Result<VerifiedIdentity, IdentityError>,
}

impl StubProvider {
    fn ok(identity: VerifiedIdentity) -> Self {
        Self {
            provider_id: identity.provider,
            response: Ok(identity),
        }
    }
    fn err(provider_id: &'static str, e: IdentityError) -> Self {
        Self {
            provider_id: ProviderId(provider_id),
            response: Err(e),
        }
    }
}

#[async_trait]
impl IdentityProvider for StubProvider {
    fn provider_id(&self) -> ProviderId {
        self.provider_id
    }
    async fn verify(&self, _: &str) -> Result<VerifiedIdentity, IdentityError> {
        self.response.clone()
    }
}

fn google_identity(sub: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: ProviderId("google"),
        subject: IdentitySubject(sub.into()),
        email: Email::try_from(email.to_string()).expect("valid email"),
        email_verified: true,
        display_name: None,
        picture_url: None,
    }
}

fn apple_identity(sub: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: ProviderId("apple"),
        subject: IdentitySubject(sub.into()),
        email: Email::try_from(email.to_string()).expect("valid email"),
        email_verified: true,
        display_name: None,
        picture_url: None,
    }
}

async fn count(pool: &PgPool, query: &str) -> i64 {
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

// ─────────────────────────── test cases ────────────────────────────

#[sqlx::test]
async fn brand_new_user_creates_user_identity_and_session(pool: PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let provider = StubProvider::ok(google_identity("sub-google-1", "alice@example.com"));

    let (token, user_id) = complete_identity_login(
        &pool,
        &provider,
        "fake-token",
        loopback_ip(),
        Some("test-ua"),
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("login ok");

    assert_eq!(token.as_str().len(), 43);
    assert!(user_id.0 > 0);

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM users WHERE email = 'alice@example.com'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM auth_identities \
             WHERE provider = 'google' AND subject = 'sub-google-1'"
        )
        .await,
        1
    );
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sessions").await, 1);

    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2, "expected IdentityLinked + Created");
    assert!(matches!(events[0], SessionEvent::IdentityLinked { .. }));
    assert!(matches!(events[1], SessionEvent::Created { .. }));
}

#[sqlx::test]
async fn magic_link_user_then_google_same_email_links(pool: PgPool) {
    let cfg = test_config();
    let mailer = CapturingMailer::new();
    let sink = CapturingSink::new();

    // Magic-link sign-in first → creates user.
    auth_rust::store::issue_magic_link(&pool, "alice@example.com", loopback_ip(), &cfg, &*mailer)
        .await
        .unwrap();
    let (link_token_str, _) = mailer.last_for("alice@example.com").unwrap();
    let (_, original_user_id) = verify_magic_link_or_code(
        &pool,
        VerifyInput::Token(auth_rust::core::MagicLinkToken::from_string(link_token_str)),
        loopback_ip(),
        Some("test-ua"),
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("magic-link verify");

    let users_before = count(&pool, "SELECT COUNT(*) FROM users").await;
    sink.events.lock().unwrap().clear();

    // Now Google login with the same email → must link to the existing user.
    let provider = StubProvider::ok(google_identity("sub-google-2", "alice@example.com"));
    let (_, google_user_id) = complete_identity_login(
        &pool,
        &provider,
        "fake-token",
        loopback_ip(),
        Some("test-ua"),
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("google login");

    assert_eq!(
        google_user_id.0, original_user_id.0,
        "google login on matching email must reuse the magic-link user"
    );
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM users").await,
        users_before,
        "no new user row created"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM auth_identities \
             WHERE provider = 'google' AND subject = 'sub-google-2'"
        )
        .await,
        1
    );
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], SessionEvent::IdentityLinked { .. }));
    assert!(matches!(events[1], SessionEvent::Created { .. }));
}

#[sqlx::test]
async fn second_google_login_reuses_identity(pool: PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let provider = StubProvider::ok(google_identity("sub-google-3", "bob@example.com"));

    let (_, first_user_id) = complete_identity_login(
        &pool,
        &provider,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("first login");
    sink.events.lock().unwrap().clear();

    let identities_before = count(&pool, "SELECT COUNT(*) FROM auth_identities").await;

    let (_, second_user_id) = complete_identity_login(
        &pool,
        &provider,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .expect("second login");

    assert_eq!(first_user_id.0, second_user_id.0);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM auth_identities").await,
        identities_before,
        "second login must NOT insert a duplicate identity row"
    );
    let events = sink.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "second login emits Created only — no IdentityLinked"
    );
    assert!(matches!(events[0], SessionEvent::Created { .. }));
}

#[sqlx::test]
async fn different_email_creates_second_user(pool: PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();

    let alice = StubProvider::ok(google_identity("sub-google-4", "alice@example.com"));
    let (_, alice_id) = complete_identity_login(
        &pool,
        &alice,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    let bob = StubProvider::ok(google_identity("sub-google-5", "bob@example.com"));
    let (_, bob_id) = complete_identity_login(
        &pool,
        &bob,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    assert_ne!(alice_id.0, bob_id.0, "different emails → different users");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM users").await, 2);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM auth_identities").await,
        2
    );
}

#[sqlx::test]
async fn email_not_verified_returns_unauthorized(pool: PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let provider = StubProvider::err("google", IdentityError::EmailNotVerified);

    let err = complete_identity_login(
        &pool,
        &provider,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, AuthError::Unauthorized), "got {err:?}");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM users").await, 0);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM auth_identities").await,
        0
    );
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sessions").await, 0);
    assert_eq!(sink.events.lock().unwrap().len(), 0);
}

#[sqlx::test]
async fn invalid_token_returns_unauthorized(pool: PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let provider = StubProvider::err("google", IdentityError::Invalid("bad signature".into()));

    let err = complete_identity_login(
        &pool,
        &provider,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, AuthError::Unauthorized), "got {err:?}");
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM users").await, 0);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM auth_identities").await,
        0
    );
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM sessions").await, 0);
}

#[sqlx::test]
async fn two_providers_same_email_share_user(pool: PgPool) {
    // Google then Apple with the same email — both identities must point to
    // the same user (resolver auto-links by email each time).
    let cfg = test_config();
    let sink = CapturingSink::new();

    let google = StubProvider::ok(google_identity("sub-google-6", "carol@example.com"));
    let (_, google_uid) = complete_identity_login(
        &pool,
        &google,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    let apple = StubProvider::ok(apple_identity("sub-apple-1", "carol@example.com"));
    let (_, apple_uid) = complete_identity_login(
        &pool,
        &apple,
        "t",
        loopback_ip(),
        None,
        &AutoSignupResolver,
        &cfg,
        &*sink,
    )
    .await
    .unwrap();

    assert_eq!(
        google_uid.0, apple_uid.0,
        "both providers link to same user"
    );
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM users").await, 1);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM auth_identities").await,
        2
    );
}
