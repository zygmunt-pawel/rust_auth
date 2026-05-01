use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;
use tracing::field;

use crate::core::{AuthConfig, AuthError, Email, Mailer, MagicLinkToken, VerifyCode};
use crate::store::hash::hmac_sha256_hex;
use crate::store::pad::{ISSUE_PAD, start_pad};

#[tracing::instrument(
    name = "auth.issue_magic_link",
    skip(pool, cfg, mailer, email_input),
    fields(email_domain = field::Empty, %ip, outcome = field::Empty),
)]
pub async fn issue_magic_link(
    pool: &PgPool,
    email_input: &str,
    ip: IpAddr,
    cfg: &AuthConfig,
    mailer: &dyn Mailer,
) -> Result<(), AuthError> {
    let pad = start_pad(ISSUE_PAD);

    let email_result = Email::try_from(email_input.to_string());
    let result = match email_result {
        Ok(email) => {
            tracing::Span::current().record("email_domain", domain_of(&email));
            issue_inner(pool, &email, ip, cfg, mailer).await
        }
        Err(_) => {
            tracing::Span::current().record("outcome", "format_invalid");
            tracing::debug!(outcome = "format_invalid", "silent drop: invalid email format");
            Ok(())
        }
    };

    pad.finish().await;
    result
}

async fn issue_inner(
    pool: &PgPool,
    email: &Email,
    ip: IpAddr,
    cfg: &AuthConfig,
    mailer: &dyn Mailer,
) -> Result<(), AuthError> {
    if !rate_check_per_email(pool, email, cfg).await? {
        tracing::Span::current().record("outcome", "rate_limited_email");
        tracing::debug!(outcome = "rate_limited_email", "silent drop: per-email throttle");
        return Ok(());
    }
    if !rate_check_per_ip(pool, ip, cfg).await? {
        tracing::Span::current().record("outcome", "rate_limited_ip");
        tracing::debug!(outcome = "rate_limited_ip", "silent drop: per-ip throttle");
        return Ok(());
    }
    if !cfg.policy.allow(email).await {
        tracing::Span::current().record("outcome", "policy_denied");
        tracing::debug!(outcome = "policy_denied", "silent drop: EmailPolicy denied");
        return Ok(());
    }

    let link_token = MagicLinkToken::generate();
    let code = VerifyCode::generate();
    let token_hash = hmac_sha256_hex(&cfg.token_pepper, link_token.as_str());
    let code_hash = hmac_sha256_hex(&cfg.token_pepper, code.as_str());

    sqlx::query(
        "INSERT INTO magic_links (token_hash, code_hash, email, ip, expires_at, code_expires_at)
         VALUES ($1, $2, $3, $4, NOW() + $5, NOW() + $6)",
    )
    .bind(&token_hash)
    .bind(&code_hash)
    .bind(email.as_str())
    .bind(ip)
    .bind(to_interval(cfg.magic_link_ttl))
    .bind(to_interval(cfg.code_ttl))
    .execute(pool)
    .await?;

    match mailer.send_magic_link(email, &link_token, &code).await {
        Ok(()) => {
            tracing::Span::current().record("outcome", "issued");
            tracing::info!(
                outcome = "issued",
                token_prefix = &token_hash[..12],
                "magic link issued"
            );
            Ok(())
        }
        Err(_) => {
            tracing::Span::current().record("outcome", "mailer_failed");
            tracing::warn!(
                outcome = "mailer_failed",
                token_prefix = &token_hash[..12],
                "mailer rejected send",
            );
            Err(AuthError::MailerFailed)
        }
    }
}

async fn rate_check_per_email(
    pool: &PgPool,
    email: &Email,
    cfg: &AuthConfig,
) -> Result<bool, AuthError> {
    let row: Option<(bool, i64)> = sqlx::query_as(
        "SELECT
            EXISTS(SELECT 1 FROM magic_links WHERE email = $1 AND created_at > NOW() - $2),
            (SELECT COUNT(*) FROM magic_links WHERE email = $1 AND created_at > NOW() - INTERVAL '24 hours')",
    )
    .bind(email.as_str())
    .bind(to_interval(cfg.issue_per_email_min_gap))
    .fetch_optional(pool)
    .await?;
    let (recent, daily) = row.unwrap_or((false, 0));
    if recent {
        return Ok(false);
    }
    if daily >= cfg.issue_per_email_24h_cap as i64 {
        return Ok(false);
    }
    Ok(true)
}

async fn rate_check_per_ip(pool: &PgPool, ip: IpAddr, cfg: &AuthConfig) -> Result<bool, AuthError> {
    let hour: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT email) FROM magic_links WHERE ip = $1 AND created_at > NOW() - INTERVAL '1 hour'",
    )
    .bind(ip)
    .fetch_one(pool)
    .await?;
    if hour >= cfg.issue_per_ip_1h_cap as i64 {
        return Ok(false);
    }

    let day: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT email) FROM magic_links WHERE ip = $1 AND created_at > NOW() - INTERVAL '24 hours'",
    )
    .bind(ip)
    .fetch_one(pool)
    .await?;
    if day >= cfg.issue_per_ip_24h_cap as i64 {
        return Ok(false);
    }
    Ok(true)
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}

/// Extract the domain part of an email for logging. Email is already lowercased.
fn domain_of(email: &Email) -> &str {
    email.as_str().rsplit('@').next().unwrap_or("?")
}
