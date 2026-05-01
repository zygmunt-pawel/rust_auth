mod common;

use common::{loopback_ip, test_config, CapturingSink};
use auth_rust::core::{MagicLinkToken, VerifyInput};
use auth_rust::store::AutoSignupResolver;

#[sqlx::test]
async fn over_cap_returns_rate_limited(pool: sqlx::PgPool) {
    let cfg = test_config(); // default cap = 30/min
    let sink = CapturingSink::new();

    // 29 bogus verifies — all should return InvalidToken (not RateLimited).
    for n in 0..29 {
        let token = MagicLinkToken::from_string(format!("bogus-token-{n:040}"));
        let r = auth_rust::store::verify_magic_link_or_code(
            &pool, VerifyInput::Token(token), loopback_ip(), None,
            &AutoSignupResolver, &cfg, &*sink,
        ).await;
        assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)),
            "attempt {n} should be InvalidToken, got {r:?}");
    }

    // 30th: must be RateLimited.
    let token = MagicLinkToken::from_string("bogus-final-token-43-chars-padding-foo".into());
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool, VerifyInput::Token(token), loopback_ip(), None,
        &AutoSignupResolver, &cfg, &*sink,
    ).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::RateLimited)));
}

#[sqlx::test]
async fn cap_zero_disables_check(pool: sqlx::PgPool) {
    let mut cfg = test_config();
    cfg.verify_per_ip_per_min_cap = 0;
    let sink = CapturingSink::new();

    for n in 0..50 {
        let token = MagicLinkToken::from_string(format!("bogus-{n:040}"));
        let r = auth_rust::store::verify_magic_link_or_code(
            &pool, VerifyInput::Token(token), loopback_ip(), None,
            &AutoSignupResolver, &cfg, &*sink,
        ).await;
        // Always InvalidToken (never RateLimited because cap is 0 = disabled).
        assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)));
    }
}

#[sqlx::test]
async fn different_ips_have_independent_buckets(pool: sqlx::PgPool) {
    let cfg = test_config();
    let sink = CapturingSink::new();
    let ip_a = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    let ip_b = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    for n in 0..29 {
        let t = MagicLinkToken::from_string(format!("a-{n:040}"));
        let _ = auth_rust::store::verify_magic_link_or_code(
            &pool, VerifyInput::Token(t), ip_a, None, &AutoSignupResolver, &cfg, &*sink,
        ).await;
    }
    // ip_a bucket is filling up. ip_b should still be allowed (independent bucket).
    let t = MagicLinkToken::from_string("b-first-bogus-43-chars-pad-pad-pad-pad-foo".into());
    let r = auth_rust::store::verify_magic_link_or_code(
        &pool, VerifyInput::Token(t), ip_b, None, &AutoSignupResolver, &cfg, &*sink,
    ).await;
    assert!(matches!(r, Err(auth_rust::core::AuthError::InvalidToken)));
}
