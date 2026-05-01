use std::time::Duration;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::SET_COOKIE},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{Span, debug, error, field, instrument, warn};

use crate::app::AppState;

use super::cookie;
use super::repo;
use super::tokens::sha256_hex;

// Plan: refresh dopiero gdy zostało < 1d do wygaśnięcia (a sliding TTL = 7d).
// Próg jako CONST żeby trzymać wszystkie stałe sesyjne razem.
const SESSION_SLIDING_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const REFRESH_WHEN_LESS_THAN: Duration = Duration::from_secs(24 * 60 * 60);

// Wstrzykiwane do request extensions po udanej walidacji sesji.
// Handler protected route'a wyciąga przez `Extension(UserId(id))`.
// `allow(dead_code)`: gotowa infrastruktura — żaden route jeszcze nie wymaga sesji,
// ale chronione endpointy (np. /me, /api/*) wpinają się przez `route_layer(from_fn_with_state(state, require_session))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct UserId(pub i64);

#[allow(dead_code)]
#[instrument(name = "require_session", skip(state, req, next), fields(user_id = field::Empty))]
pub async fn require_session(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let Some(plaintext) = cookie::extract_session_cookie(req.headers()) else {
        debug!(event = "session_invalid", reason = "no_cookie");
        return unauthorized();
    };

    let hash = sha256_hex(plaintext);

    let session = match repo::lookup_active_session(&state.pool, &hash, REFRESH_WHEN_LESS_THAN).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            debug!(event = "session_invalid", reason = "lookup_miss");
            return unauthorized();
        }
        Err(e) => {
            error!(error = %e, "session_lookup_failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    Span::current().record("user_id", session.user_id);

    // Throttled — bez tego mielibyśmy UPDATE na każdy request (HOT row + WAL bloat).
    // Refresh side-effect; nawet jak nie pójdzie, sesja jest jeszcze ważna ≥1d.
    if session.needs_refresh
        && let Err(e) = repo::refresh_session_expiry(&state.pool, session.id, SESSION_SLIDING_TTL).await
    {
        warn!(error = %e, event = "session_refresh_failed");
    }

    req.extensions_mut().insert(UserId(session.user_id));
    next.run(req).await
}

// 401 + clear cookie — gnijące cookie po stronie browsera nic nie daje, lepiej je zabić.
#[allow(dead_code)]
fn unauthorized() -> Response {
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    resp.headers_mut().insert(SET_COOKIE, HeaderValue::from_static(cookie::CLEAR_COOKIE));
    resp
}
