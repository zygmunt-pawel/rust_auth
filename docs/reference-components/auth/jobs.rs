use std::net::IpAddr;
use std::time::Duration;

use apalis::prelude::*;
use apalis_postgres::PgTaskId;
use axum_prometheus::metrics::counter;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use super::repo::{self, NewMagicLink};
use super::tokens::{generate_token, sha256_hex};

const MAGIC_LINKS: &str = "auth_magic_links_total";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMagicLink {
    pub email: String,
    pub ip: IpAddr,
}

// Per-email: każdy świeży request (≤ window od poprzedniego) jest dropowany.
// Per-IP: max N różnych emaili z tego IP w tym samym oknie.
// Tower-governor (12/s, burst 2) blokuje wcześniej, te liczby to belt+suspenders
// żeby ograniczyć enumerację adresów.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(5 * 60);
const RATE_LIMIT_PER_IP_DISTINCT_EMAILS: i64 = 5;

const MAGIC_LINK_TTL: Duration = Duration::from_secs(15 * 60);

#[instrument(
    name = "handle_magic_link",
    skip(pool, job, task_id),
    fields(email = %job.email, ip = %job.ip, task_id = %task_id.inner().0),
)]
pub async fn handle_magic_link(job: SendMagicLink, pool: Data<PgPool>, task_id: PgTaskId) -> Result<(), BoxDynError> {
    let pool: &PgPool = &pool;

    if rate_limit_hit(pool, &job.email, job.ip).await? {
        warn!(event = "rate_limit_hit");
        counter!(MAGIC_LINKS, "outcome" => "rate_limited").increment(1);
        return Ok(()); // ack joba — celowo nie wysyłamy maila i nie wpisujemy linku
    }

    // Plaintext NIGDY nie ląduje w bazie — tylko w (mockowanym) mailu.
    let plaintext = generate_token();
    let hash = sha256_hex(&plaintext);

    // MOCK. W prawdziwej implementacji rozróżniamy:
    //   - retryable (network/SMTP 4xx) → return Err → apalis retry
    //   - non-retryable (invalid recipient, 5xx permanent) → AbortError
    send_email_mock(&job.email, &plaintext).await;

    // Idempotentny INSERT — jeśli worker padnie po SMTP a przed ack, drugi worker
    // wyśle DRUGI mail (innego tokena), ale wpis zachowa pierwszy. Worst case: 2 maile,
    // 1 valid token — akceptowalne; alternatywa to brak idempotencji w ogóle.
    repo::insert_magic_link(
        pool,
        NewMagicLink {
            token_hash: &hash,
            source_job_id: Uuid::from_u128(task_id.inner().0),
            email: &job.email,
            ip: job.ip,
            ttl: MAGIC_LINK_TTL,
        },
    )
    .await?;

    info!(event = "magic_link_issued", token_prefix = &hash[..12]);
    counter!(MAGIC_LINKS, "outcome" => "issued").increment(1);
    Ok(())
}

async fn rate_limit_hit(pool: &PgPool, email: &str, ip: IpAddr) -> sqlx::Result<bool> {
    if repo::recent_magic_link_for_email(pool, email, RATE_LIMIT_WINDOW).await? {
        return Ok(true);
    }
    let distinct = repo::distinct_recipients_from_ip(pool, ip, RATE_LIMIT_WINDOW).await?;
    Ok(distinct >= RATE_LIMIT_PER_IP_DISTINCT_EMAILS)
}

// Stub w miejsce lettre/SMTP. Loguje przez tracing czego BY zostało wysłane.
// Sleep imituje latencję sieci — chcemy żeby integ-testy widziały realistyczne timingi.
async fn send_email_mock(email: &str, plaintext_token: &str) {
    info!(
        target: "auth_rust::mock_mail",
        email,
        link = %format!("https://app.example.com/auth/landing?login_token={plaintext_token}"),
        "mock_mail_sent"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
}
