use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;
use tracing::field;

use crate::core::{AuthConfig, AuthError, Email, MagicLinkToken, Mailer, VerifyCode};
use crate::store::hash::hmac_sha256_hex;
use crate::store::pad::{ISSUE_PAD, start_pad};

#[tracing::instrument(
    name = "auth.issue_magic_link",
    skip(pool, cfg, mailer, email_input),
    fields(email = field::Empty, %ip, outcome = field::Empty),
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
            tracing::Span::current().record("email", email.for_log(cfg.log_full_email));
            issue_inner(pool, &email, ip, cfg, mailer).await
        }
        Err(_) => {
            tracing::Span::current().record("outcome", "format_invalid");
            tracing::debug!(
                outcome = "format_invalid",
                "silent drop: invalid email format"
            );
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
    // Active block check (cheap lookup, both checks short-circuit on first hit).
    if email_is_blocked(pool, email).await? {
        tracing::Span::current().record("outcome", "email_blocked");
        tracing::debug!(
            outcome = "email_blocked",
            "silent drop: email under active block"
        );
        return Ok(());
    }
    if ip_is_blocked(pool, ip).await? {
        tracing::Span::current().record("outcome", "ip_blocked");
        tracing::debug!(outcome = "ip_blocked", "silent drop: ip under active block");
        return Ok(());
    }

    // Cap check: count mails sent for this email/IP in the rolling 30-min window.
    // If we hit the cap, insert a block (does NOT extend an existing one) and silent-drop.
    // Block events log email+ip explicitly so abuse triage in Loki/Grafana is trivial:
    // `{outcome="email_cap_hit"} | json | line_format "{{.email}} {{.ip}}"`.
    if email_cap_exceeded(pool, email, cfg).await? {
        insert_email_block(pool, email, cfg).await?;
        tracing::Span::current().record("outcome", "email_cap_hit");
        tracing::warn!(
            outcome = "email_cap_hit",
            email = email.for_log(cfg.log_full_email),
            %ip,
            "email blocked: 30-min cap exceeded",
        );
        return Ok(());
    }
    if ip_cap_exceeded(pool, ip, cfg).await? {
        insert_ip_block(pool, ip, cfg).await?;
        tracing::Span::current().record("outcome", "ip_cap_hit");
        tracing::warn!(
            outcome = "ip_cap_hit",
            email = email.for_log(cfg.log_full_email),
            %ip,
            "ip blocked: 30-min cap exceeded",
        );
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

    // Invalidate all previously-live rows for this email — only the just-issued mail
    // should be usable. Both link path and code path filter by `used_at IS NULL`, so
    // a single UPDATE covers both. Match the user-intuition "newest mail wins"
    // (Auth0 / Supabase pattern).
    sqlx::query(
        "UPDATE magic_links SET used_at = NOW()
         WHERE email = $1 AND used_at IS NULL",
    )
    .bind(email.as_str())
    .execute(pool)
    .await?;

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

async fn email_is_blocked(pool: &PgPool, email: &Email) -> Result<bool, AuthError> {
    let blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_email_blocks WHERE email = $1 AND expires_at > NOW())",
    )
    .bind(email.as_str())
    .fetch_one(pool)
    .await?;
    Ok(blocked)
}

async fn ip_is_blocked(pool: &PgPool, ip: IpAddr) -> Result<bool, AuthError> {
    let blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_ip_blocks WHERE ip = $1 AND expires_at > NOW())",
    )
    .bind(ip)
    .fetch_one(pool)
    .await?;
    Ok(blocked)
}

async fn email_cap_exceeded(
    pool: &PgPool,
    email: &Email,
    cfg: &AuthConfig,
) -> Result<bool, AuthError> {
    if cfg.issue_per_email_cap == 0 {
        return Ok(false);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM magic_links
         WHERE email = $1 AND created_at > NOW() - $2",
    )
    .bind(email.as_str())
    .bind(to_interval(cfg.issue_window))
    .fetch_one(pool)
    .await?;
    Ok(count >= cfg.issue_per_email_cap as i64)
}

async fn ip_cap_exceeded(pool: &PgPool, ip: IpAddr, cfg: &AuthConfig) -> Result<bool, AuthError> {
    if cfg.issue_per_ip_cap == 0 {
        return Ok(false);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM magic_links
         WHERE ip = $1 AND created_at > NOW() - $2",
    )
    .bind(ip)
    .bind(to_interval(cfg.issue_window))
    .fetch_one(pool)
    .await?;
    Ok(count >= cfg.issue_per_ip_cap as i64)
}

async fn insert_email_block(
    pool: &PgPool,
    email: &Email,
    cfg: &AuthConfig,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO auth_email_blocks (email, expires_at) VALUES ($1, NOW() + $2)")
        .bind(email.as_str())
        .bind(to_interval(cfg.issue_block_duration))
        .execute(pool)
        .await?;
    Ok(())
}

async fn insert_ip_block(pool: &PgPool, ip: IpAddr, cfg: &AuthConfig) -> Result<(), AuthError> {
    // Escalation: if this IP has been blocked >= ip_permanent_block_threshold times in
    // last 24h, the new block is permanent (expires_at = 'infinity'). Otherwise normal
    // block_duration.
    let recent_blocks: i64 = if cfg.ip_permanent_block_threshold > 0 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM auth_ip_blocks
             WHERE ip = $1 AND blocked_at > NOW() - INTERVAL '24 hours'",
        )
        .bind(ip)
        .fetch_one(pool)
        .await?
    } else {
        0
    };

    if cfg.ip_permanent_block_threshold > 0
        && recent_blocks >= cfg.ip_permanent_block_threshold as i64
    {
        sqlx::query(
            "INSERT INTO auth_ip_blocks (ip, expires_at) VALUES ($1, 'infinity'::timestamptz)",
        )
        .bind(ip)
        .execute(pool)
        .await?;
        tracing::warn!(
            outcome = "ip_permanent_block",
            %ip,
            recent_blocks,
            "ip permanently blocked (repeat offender)",
        );
    } else {
        sqlx::query("INSERT INTO auth_ip_blocks (ip, expires_at) VALUES ($1, NOW() + $2)")
            .bind(ip)
            .bind(to_interval(cfg.issue_block_duration))
            .execute(pool)
            .await?;
    }
    Ok(())
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
