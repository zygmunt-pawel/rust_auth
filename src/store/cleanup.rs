//! Periodic cleanup of expired auth rows.
//!
//! Run [`cleanup_expired`] from a cron / `pg_cron` / sidecar job (e.g. nightly).
//! All three auth tables grow unbounded otherwise.
//!
//! Hardcoded retention windows (sensible defaults — write your own DELETE if you need
//! stricter RODO policy or different forensics windows):
//!
//! - `magic_links`: deleted after 7 days. Long enough to preserve the 24h failed-attempt
//!   lockout window with a 6-day forensics buffer for incident debugging.
//! - `sessions`: deleted as soon as `absolute_expires_at < NOW()` — those sessions
//!   are already dead and no code path can resurrect them.
//! - `auth_verify_attempts`: deleted after 5 minutes. The verify rate limit only reads
//!   the last 60s, so 5 min keeps a small audit window.
//! - `auth_email_blocks` / `auth_ip_blocks`: expired blocks deleted after 7 days
//!   (kept for audit / repeat-offender escalation lookback). Permanent IP blocks
//!   (`expires_at = 'infinity'`) are never deleted — they're the whole point.

use sqlx::PgPool;

use crate::core::AuthError;

/// Counts of rows deleted from each table during a cleanup pass. Useful for logging /
/// metrics ("how much auth garbage did we collect tonight").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub magic_links_deleted: u64,
    pub sessions_deleted: u64,
    pub verify_attempts_deleted: u64,
    pub email_blocks_deleted: u64,
    pub ip_blocks_deleted: u64,
}

impl CleanupReport {
    pub fn total(&self) -> u64 {
        self.magic_links_deleted
            + self.sessions_deleted
            + self.verify_attempts_deleted
            + self.email_blocks_deleted
            + self.ip_blocks_deleted
    }
}

/// Delete expired / old rows from `magic_links`, `sessions`, `auth_verify_attempts`.
///
/// Idempotent — running twice is safe; second run finds nothing to delete.
///
/// ```ignore
/// // In a daily cron job:
/// let report = auth_rust::store::cleanup_expired(&pool).await?;
/// tracing::info!(
///     magic_links = report.magic_links_deleted,
///     sessions = report.sessions_deleted,
///     verify_attempts = report.verify_attempts_deleted,
///     "auth cleanup",
/// );
/// ```
#[tracing::instrument(name = "auth.cleanup_expired", skip_all)]
pub async fn cleanup_expired(pool: &PgPool) -> Result<CleanupReport, AuthError> {
    let magic_links_deleted =
        sqlx::query("DELETE FROM magic_links WHERE created_at < NOW() - INTERVAL '7 days'")
            .execute(pool)
            .await?
            .rows_affected();

    let sessions_deleted = sqlx::query("DELETE FROM sessions WHERE absolute_expires_at < NOW()")
        .execute(pool)
        .await?
        .rows_affected();

    let verify_attempts_deleted = sqlx::query(
        "DELETE FROM auth_verify_attempts WHERE attempted_at < NOW() - INTERVAL '5 minutes'",
    )
    .execute(pool)
    .await?
    .rows_affected();

    // Permanent blocks (expires_at = 'infinity') survive — they were established
    // intentionally and shouldn't be auto-purged.
    let email_blocks_deleted = sqlx::query(
        "DELETE FROM auth_email_blocks
         WHERE expires_at < NOW() - INTERVAL '7 days'
           AND expires_at < 'infinity'::timestamptz",
    )
    .execute(pool)
    .await?
    .rows_affected();

    let ip_blocks_deleted = sqlx::query(
        "DELETE FROM auth_ip_blocks
         WHERE expires_at < NOW() - INTERVAL '7 days'
           AND expires_at < 'infinity'::timestamptz",
    )
    .execute(pool)
    .await?
    .rows_affected();

    let report = CleanupReport {
        magic_links_deleted,
        sessions_deleted,
        verify_attempts_deleted,
        email_blocks_deleted,
        ip_blocks_deleted,
    };

    tracing::info!(
        magic_links = magic_links_deleted,
        sessions = sessions_deleted,
        verify_attempts = verify_attempts_deleted,
        email_blocks = email_blocks_deleted,
        ip_blocks = ip_blocks_deleted,
        total = report.total(),
        "auth cleanup pass complete"
    );

    Ok(report)
}
