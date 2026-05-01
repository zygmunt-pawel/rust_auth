use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use tracing::{Span, debug, error, field, info, instrument};

use crate::app::AppState;

use super::cookie;
use super::repo;
use super::tokens::sha256_hex;

#[instrument(name = "logout", skip(state, headers), fields(user_id = field::Empty))]
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Idempotentne — bez cookie zwracamy 200 i czyścimy (no-op od strony usera).
    // Niespójne 4xx tutaj wprowadza tylko UX szum przy double-clicku "wyloguj".
    let Some(plaintext) = cookie::extract_session_cookie(&headers) else {
        debug!(event = "logout_no_cookie");
        return cleared(StatusCode::OK);
    };

    let token_hash = sha256_hex(plaintext);

    match repo::delete_session(&state.pool, &token_hash).await {
        Ok(Some((_, user_id))) => {
            Span::current().record("user_id", user_id);
            info!(event = "logout");
        }
        Ok(None) => debug!(event = "logout_noop"),
        Err(e) => error!(error = %e, "delete_session_failed"),
        // Nie blokujemy — chcemy żeby user MÓGŁ się "wylogować" nawet jak DB padło.
        // Cookie zostanie wyczyszczone, najgorsze co się dzieje to martwy rekord
        // sesji w bazie do cleanupa.
    }

    cleared(StatusCode::OK)
}

fn cleared(status: StatusCode) -> Response {
    (status, [(SET_COOKIE, cookie::CLEAR_COOKIE)]).into_response()
}
