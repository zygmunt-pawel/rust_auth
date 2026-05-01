use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;

use crate::core::{
    AuthConfig, AuthError, Email, Mailer, MagicLinkToken, VerifyCode,
};
use crate::store::hash::hmac_sha256_hex;
use crate::store::pad::{ISSUE_PAD, start_pad};

pub async fn issue_magic_link(
    pool: &PgPool,
    email_input: &str,
    ip: IpAddr,
    cfg: &AuthConfig,
    mailer: &impl Mailer,
) -> Result<(), AuthError> {
    let pad = start_pad(ISSUE_PAD);

    // Validate internally; never bubble format errors up. Uniform 200 is the contract.
    let email_result = Email::try_from(email_input.to_string());
    let result = match email_result {
        Ok(email) => issue_inner(pool, &email, ip, cfg, mailer).await,
        Err(_) => {
            tracing::debug!(target: "auth_rust::issue", "invalid email format, silent drop");
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
    mailer: &impl Mailer,
) -> Result<(), AuthError> {
    // Rate limits + EmailPolicy come in next task. For now: skip straight to insert+send.
    let link_token = MagicLinkToken::generate();
    let code = VerifyCode::generate();

    let token_hash = hmac_sha256_hex(&cfg.token_pepper, link_token.as_str());
    let code_hash = hmac_sha256_hex(&cfg.token_pepper, code.as_str());

    sqlx::query(
        "INSERT INTO magic_links (token_hash, code_hash, email, ip, expires_at, code_expires_at)
         VALUES ($1, $2, $3, $4, NOW() + $5, NOW() + $6)"
    )
    .bind(&token_hash)
    .bind(&code_hash)
    .bind(email.as_str())
    .bind(ip)
    .bind(to_interval(cfg.magic_link_ttl))
    .bind(to_interval(cfg.code_ttl))
    .execute(pool)
    .await?;

    mailer.send_magic_link(email, &link_token, &code).await
        .map_err(|_| AuthError::MailerFailed)?;

    Ok(())
}

fn to_interval(d: Duration) -> PgInterval {
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
