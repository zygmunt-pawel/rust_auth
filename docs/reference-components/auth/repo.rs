// Cały SQL modułu auth siedzi tutaj. Reszta kodu (handlery, joby) używa
// tylko metod tego modułu — nie wstrzykuje własnego SQL-a, nie wie nic o
// nazwach tabel/kolumn ani o INTERVAL/NOW(). Dzięki temu zmiana schematu
// = zmiana w jednym pliku, a callery zostają bez modyfikacji.

use std::net::IpAddr;
use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::types::PgInterval;
use uuid::Uuid;

#[derive(Debug)]
pub struct NewMagicLink<'a> {
    pub token_hash: &'a str,
    pub source_job_id: Uuid,
    pub email: &'a str,
    pub ip: IpAddr,
    pub ttl: Duration,
}

// Używane przez session::require_session — middleware nie ma jeszcze chronionego
// route'a, ale cała ścieżka jest przygotowana.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct ActiveSession {
    pub id: i64,
    pub user_id: i64,
    pub needs_refresh: bool,
}

pub async fn insert_magic_link(pool: &PgPool, p: NewMagicLink<'_>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO magic_links (token_hash, source_job_id, email, ip, expires_at)
         VALUES ($1, $2, $3, $4, NOW() + $5)
         ON CONFLICT (source_job_id) DO NOTHING",
    )
    .bind(p.token_hash)
    .bind(p.source_job_id)
    .bind(p.email)
    .bind(p.ip)
    .bind(to_interval(p.ttl))
    .execute(pool)
    .await?;
    Ok(())
}

// Czy w oknie czasowym istnieje już request dla tego emaila?
// EXISTS żeby planner mógł zatrzymać się na pierwszym trafieniu.
pub async fn recent_magic_link_for_email(pool: &PgPool, email: &str, window: Duration) -> sqlx::Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM magic_links
             WHERE email = $1 AND created_at > NOW() - $2
         )",
    )
    .bind(email)
    .bind(to_interval(window))
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

// Ile RÓŻNYCH adresatów obsłużyliśmy z tego IP w oknie czasowym.
// Caller decyduje co zrobić z liczbą — repo nie zna progów biznesowych.
pub async fn distinct_recipients_from_ip(pool: &PgPool, ip: IpAddr, window: Duration) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT email) FROM magic_links
         WHERE ip = $1 AND created_at > NOW() - $2",
    )
    .bind(ip)
    .bind(to_interval(window))
    .fetch_one(pool)
    .await
}

// Wykonywane PO `consume_token` gdy ten zwrócił None — żeby rozróżnić
// expired / reused / invalid dla logu i metryki. Wynik to gotowy string-label
// (Prometheus convention + LogQL filter), nie enum — caller go bezpośrednio
// bind'uje. None branch UPDATE-a + None branch tutaj = token_invalid.
pub async fn magic_link_reject_reason(pool: &PgPool, token_hash: &str) -> sqlx::Result<&'static str> {
    let row: Option<(bool,)> = sqlx::query_as("SELECT used_at IS NOT NULL FROM magic_links WHERE token_hash = $1").bind(token_hash).fetch_optional(pool).await?;
    Ok(match row {
        None => "token_invalid",
        Some((true,)) => "token_reused",
        // not used and UPDATE failed → expired (jedyny pozostały powód odrzutu).
        Some((false,)) => "token_expired",
    })
}

// Logout: jeden DELETE, RETURNING żeby od razu mieć id+user_id.
// None gdy cookie nie pasuje do żadnej żywej sesji (już wygasła / nigdy nie istniała).
pub async fn delete_session(pool: &PgPool, token_hash: &str) -> sqlx::Result<Option<(i64, i64)>> {
    let row: Option<(i64, i64)> = sqlx::query_as("DELETE FROM sessions WHERE session_token_hash = $1 RETURNING id, user_id")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

// Per-request auth lookup. JOIN z users.status='active' żeby suspended user
// (z żywym cookie) dostał 401 zamiast 200. `needs_refresh` wyliczany w bazie —
// caller nie musi parsować TIMESTAMPTZ.
#[allow(dead_code)]
pub async fn lookup_active_session(pool: &PgPool, token_hash: &str, refresh_threshold: Duration) -> sqlx::Result<Option<ActiveSession>> {
    let row: Option<(i64, i64, bool)> = sqlx::query_as(
        "SELECT s.id, s.user_id, s.expires_at < NOW() + $2
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.session_token_hash = $1
           AND s.expires_at > NOW()
           AND s.absolute_expires_at > NOW()
           AND u.status = 'active'",
    )
    .bind(token_hash)
    .bind(to_interval(refresh_threshold))
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(id, user_id, needs_refresh)| ActiveSession { id, user_id, needs_refresh }))
}

// Throttled refresh — wywołujemy tylko gdy `needs_refresh` z lookupa.
// LEAST z absolute_expires_at: nie podnosimy slidingu PONAD twardy 30d cap.
#[allow(dead_code)]
pub async fn refresh_session_expiry(pool: &PgPool, session_id: i64, sliding_ttl: Duration) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE sessions
         SET expires_at = LEAST(NOW() + $2, absolute_expires_at)
         WHERE id = $1",
    )
    .bind(session_id)
    .bind(to_interval(sliding_ttl))
    .execute(pool)
    .await?;
    Ok(())
}

fn to_interval(d: Duration) -> PgInterval {
    // PgInterval::try_from failuje tylko gdy Duration nie mieści się w i64 µs (~292 tys. lat).
    // Tu używamy go dla minutowych okien — niemożliwe.
    PgInterval::try_from(d).expect("duration fits in PgInterval")
}
