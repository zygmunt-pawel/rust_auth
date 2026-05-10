//! Google id_token verifier — security-critical JWT validation.
//!
//! Test strategy:
//! - One RSA-2048 keypair per test process (lazy via `OnceLock`).
//! - `wiremock` serves the public key as JWKS.
//! - Each test mints a JWT with controlled claims/headers and feeds it to
//!   `GoogleIdTokenVerifier::with_jwks_url(...)` pointed at the mock.
//!
//! `alg=none` is asserted by hand-rolling the token (jsonwebtoken's `Header`
//! type has no `None` variant — that's the *first* line of defense). The
//! second is our own `ALLOWED_ALGS` whitelist.

#![cfg(feature = "google")]

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use auth_rust::core::{IdentityError, IdentityProvider};
use auth_rust::providers::google::GoogleIdTokenVerifier;

const KID: &str = "test-kid-1";
const AUDIENCE: &str = "test-client-id.apps.googleusercontent.com";
const ISS: &str = "https://accounts.google.com";

struct Fixture {
    encoding_key: EncodingKey,
    n_b64: String,
    e_b64: String,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        // Use the rand 0.8 alias — rsa 0.9.6 binds to rand_core 0.6 traits,
        // which the lib's main rand 0.9 dep does not implement.
        let mut rng = rand08::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = RsaPublicKey::from(&priv_key);
        let n_b64 = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
        let pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem encode");
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("jwt encoding key");
        Fixture {
            encoding_key,
            n_b64,
            e_b64,
        }
    })
}

fn jwks_body(kid: &str) -> Value {
    jwks_keys(&[kid])
}

fn jwks_keys(kids: &[&str]) -> Value {
    let f = fixture();
    let keys: Vec<Value> = kids
        .iter()
        .map(|kid| {
            json!({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": f.n_b64,
                "e": f.e_b64,
            })
        })
        .collect();
    json!({ "keys": keys })
}

async fn mock_with_kid(kid: &str) -> (MockServer, String) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body(kid)))
        .mount(&server)
        .await;
    let url = format!("{}/jwks", server.uri());
    (server, url)
}

fn standard_claims(aud: &str, iss: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "sub": "google-user-123",
        "email": "alice@example.com",
        "email_verified": true,
        "iss": iss,
        "aud": aud,
        "exp": now + 600,
        "iat": now,
        "name": "Alice Example",
        "picture": "https://example.com/pic.png",
    })
}

fn mint_rs256(kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(&header, claims, &fixture().encoding_key).expect("mint rs256")
}

fn mint_hs256(kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.into());
    let key = EncodingKey::from_secret(b"shared-secret-attacker-controls");
    encode(&header, claims, &key).expect("mint hs256")
}

/// Hand-roll an `alg=none` JWT — jsonwebtoken's API refuses to do this for us
/// (the `Algorithm` enum has no `None` variant), which is itself a built-in
/// defense. We bypass that to confirm our `decode_header` call rejects the
/// token before any other code runs.
fn mint_alg_none(kid: &str, claims: &Value) -> String {
    let header = json!({"alg": "none", "typ": "JWT", "kid": kid}).to_string();
    let payload = claims.to_string();
    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{h}.{p}.")
}

#[tokio::test]
async fn happy_path_returns_verified_identity() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(KID, &standard_claims(AUDIENCE, ISS));

    let identity = verifier.verify(&token).await.expect("verify ok");

    assert_eq!(identity.provider, "google");
    assert_eq!(identity.subject, "google-user-123");
    assert_eq!(identity.email.as_str(), "alice@example.com");
    assert!(identity.email_verified);
    assert_eq!(identity.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(
        identity.picture_url.as_deref(),
        Some("https://example.com/pic.png")
    );
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(
        KID,
        &standard_claims("other-client.apps.googleusercontent.com", ISS),
    );

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(ref m) if m.contains("audience")),
        "want Invalid(\"...audience...\"), got {err:?}"
    );
}

#[tokio::test]
async fn wrong_issuer_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(
        KID,
        &standard_claims(AUDIENCE, "https://accounts.example.com"),
    );

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(ref m) if m.contains("issuer")),
        "want Invalid(\"...issuer...\"), got {err:?}"
    );
}

#[tokio::test]
async fn expired_token_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": "u", "email": "alice@example.com", "email_verified": true,
        "iss": ISS, "aud": AUDIENCE,
        "exp": now - 600, "iat": now - 1200,
    });
    let token = mint_rs256(KID, &claims);

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(ref m) if m.contains("expired")),
        "want Invalid(\"expired\"), got {err:?}"
    );
}

#[tokio::test]
async fn email_not_verified_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let mut claims = standard_claims(AUDIENCE, ISS);
    claims["email_verified"] = json!(false);
    let token = mint_rs256(KID, &claims);

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::EmailNotVerified),
        "want EmailNotVerified, got {err:?}"
    );
}

#[tokio::test]
async fn alg_none_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    // Hand-rolled token; signature is empty. Must be rejected by `decode_header`
    // (jsonwebtoken Algorithm enum has no None variant) before any key lookup.
    let token = mint_alg_none(KID, &standard_claims(AUDIENCE, ISS));

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(_)),
        "want Invalid (alg=none rejected), got {err:?}"
    );
}

#[tokio::test]
async fn alg_hs256_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    // HS256 token with attacker-known secret. The classic RS↔HS confusion
    // attack: if a verifier reads `alg` from the header without a whitelist,
    // it would HMAC-verify the token using the public key as the shared secret.
    // Our `ALLOWED_ALGS` rejects HS256 outright, before any decode.
    let token = mint_hs256(KID, &standard_claims(AUDIENCE, ISS));

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(ref m) if m.contains("alg")),
        "want Invalid(\"...alg...\") (HS256 rejected by whitelist), got {err:?}"
    );
}

#[tokio::test]
async fn unknown_kid_with_no_refresh_rejected() {
    // Mock returns JWKS containing only KID. Token references a different kid.
    // Even after the refresh attempt, the kid is still missing → Invalid.
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256("some-other-kid", &standard_claims(AUDIENCE, ISS));

    let err = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(ref m) if m.contains("kid")),
        "want Invalid(\"...kid...\"), got {err:?}"
    );
}

#[tokio::test]
async fn malformed_token_rejected() {
    let (_server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);

    let err = verifier.verify("not-a-jwt-at-all").await.unwrap_err();
    assert!(
        matches!(err, IdentityError::Invalid(_)),
        "want Invalid (malformed jwt), got {err:?}"
    );
}

// ───────────────────────── JWKS cache + refresh ─────────────────────────

#[tokio::test]
async fn unknown_kid_triggers_refresh_then_success() {
    // First GET: only KID_A (so the verifier's initial cache loads it).
    // Subsequent GETs: KID_A + KID_B → second verify with KID_B succeeds via
    // refresh-on-miss, demonstrating that an unknown kid drives a fetch.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_keys(&["kid-a"])))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_keys(&["kid-a", "kid-b"])))
        .mount(&server)
        .await;

    let url = format!("{}/jwks", server.uri());
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);

    // Loads initial JWKS via 1st GET.
    let token_a = mint_rs256("kid-a", &standard_claims(AUDIENCE, ISS));
    verifier.verify(&token_a).await.expect("verify kid-a");

    // KID_B not in cache → refresh fires → 2nd GET → KID_B present → success.
    let token_b = mint_rs256("kid-b", &standard_claims(AUDIENCE, ISS));
    verifier.verify(&token_b).await.expect("verify kid-b");

    let received = server.received_requests().await.expect("requests recorded");
    assert_eq!(
        received.len(),
        2,
        "expected exactly 2 GETs (initial load + refresh-on-miss)"
    );
}

#[tokio::test]
async fn cache_hit_no_http_on_second_verify() {
    let (server, url) = mock_with_kid(KID).await;
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(KID, &standard_claims(AUDIENCE, ISS));

    verifier.verify(&token).await.expect("verify 1");
    verifier.verify(&token).await.expect("verify 2");

    let received = server.received_requests().await.expect("requests recorded");
    assert_eq!(
        received.len(),
        1,
        "expected exactly 1 GET (initial load); subsequent verify hits cache"
    );
}

#[tokio::test]
async fn concurrent_unknown_kid_dedupe_one_fetch() {
    // Slow JWKS response so concurrent verifiers all observe the cache miss
    // before the first refresher finishes — exercising refresh_lock dedup.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_body(KID))
                .set_delay(std::time::Duration::from_millis(200)),
        )
        .mount(&server)
        .await;
    let url = format!("{}/jwks", server.uri());
    let verifier = std::sync::Arc::new(GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url));
    let token = std::sync::Arc::new(mint_rs256(KID, &standard_claims(AUDIENCE, ISS)));

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let v = verifier.clone();
        let t = token.clone();
        set.spawn(async move { v.verify(&t).await });
    }
    while let Some(r) = set.join_next().await {
        r.expect("task join").expect("verify ok");
    }

    let received = server.received_requests().await.expect("requests recorded");
    assert_eq!(
        received.len(),
        1,
        "refresh_lock should serialize 50 concurrent unknown-kid verifies into 1 GET"
    );
}

#[tokio::test]
async fn failed_refresh_cooldown_suppresses_retries() {
    // Mock returns 500 on every GET. First verify drives a refresh that fails
    // and records last_failed_refresh; the second verify (within the 30s
    // cooldown) short-circuits without any HTTP at all.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let url = format!("{}/jwks", server.uri());
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(KID, &standard_claims(AUDIENCE, ISS));

    let err1 = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err1, IdentityError::Transient(_)),
        "want Transient on 500, got {err1:?}"
    );
    let err2 = verifier.verify(&token).await.unwrap_err();
    assert!(
        matches!(err2, IdentityError::Transient(ref m) if m.contains("cooldown")),
        "want Transient(cooldown) on second attempt, got {err2:?}"
    );

    let received = server.received_requests().await.expect("requests recorded");
    assert_eq!(
        received.len(),
        1,
        "cooldown must prevent the second refresh from hitting Google"
    );
}

#[tokio::test]
async fn cache_control_max_age_respected() {
    // Mock advertises max-age=2. After 2.1s the cache is stale and the next
    // verify must hit HTTP again to refresh — even though the kid is still
    // present in the cached state.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(jwks_body(KID))
                .insert_header("cache-control", "max-age=2"),
        )
        .mount(&server)
        .await;
    let url = format!("{}/jwks", server.uri());
    let verifier = GoogleIdTokenVerifier::with_jwks_url(AUDIENCE, url);
    let token = mint_rs256(KID, &standard_claims(AUDIENCE, ISS));

    verifier.verify(&token).await.expect("verify 1");
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    verifier.verify(&token).await.expect("verify 2 after TTL");

    let received = server.received_requests().await.expect("requests recorded");
    assert_eq!(
        received.len(),
        2,
        "expired TTL must trigger a fresh GET on the next verify"
    );
}
