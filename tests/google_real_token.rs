//! Manual smoke test against a real Google-issued `id_token`.
//!
//! `#[ignore]` so CI skips it. Run on demand:
//!
//! ```
//! GOOGLE_CLIENT_ID=...apps.googleusercontent.com \
//! GOOGLE_TEST_ID_TOKEN=eyJhbGciOi... \
//!   cargo test --features google --test google_real_token -- --ignored --nocapture
//! ```
//!
//! Grab a fresh `id_token` from the [Google OAuth 2.0 Playground] (Step 2 →
//! "Exchange authorization code for tokens"), or capture it from your app's
//! frontend GIS callback. Tokens expire in 1 hour.
//!
//! [Google OAuth 2.0 Playground]: https://developers.google.com/oauthplayground

#![cfg(feature = "google")]

use auth_rust::core::IdentityProvider;
use auth_rust::providers::google::GoogleIdTokenVerifier;

#[tokio::test]
#[ignore = "manual: needs GOOGLE_CLIENT_ID + GOOGLE_TEST_ID_TOKEN env"]
async fn verifies_real_google_id_token() {
    let audience =
        std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID env var required");
    let token =
        std::env::var("GOOGLE_TEST_ID_TOKEN").expect("GOOGLE_TEST_ID_TOKEN env var required");

    let verifier = GoogleIdTokenVerifier::new(audience);
    let identity = verifier
        .verify(&token)
        .await
        .expect("verify against real Google JWKS");

    assert_eq!(identity.provider, "google");
    assert!(identity.email_verified, "Google must mark email_verified=true");
    assert!(!identity.subject.is_empty(), "sub claim required");
    println!(
        "verified — sub={} email={} name={:?}",
        identity.subject,
        identity.email.as_str(),
        identity.display_name
    );
}
