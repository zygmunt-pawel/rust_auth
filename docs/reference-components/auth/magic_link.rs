use apalis::prelude::TaskSink;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_client_ip::ClientIp;
use serde::{Deserialize, Serialize};
use tracing::{Span, error, field, info, instrument};

use crate::app::AppState;

use super::email::{Email, EmailError};
use super::jobs::SendMagicLink;

#[derive(Deserialize)]
pub struct MagicLinkRequest {
    email: String,
}

#[derive(Serialize)]
pub struct MagicLinkResponse {
    status: &'static str,
}

impl IntoResponse for EmailError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, "invalid email").into_response()
    }
}

// `email` rejestrujemy po walidacji — nie chcemy w spanie surowego inputu z requesta.
#[instrument(
    name = "magic_link",
    skip(state, payload),
    fields(ip = %ip, email = field::Empty),
)]
pub async fn magic_link(ClientIp(ip): ClientIp, State(state): State<AppState>, Json(payload): Json<MagicLinkRequest>) -> Result<Json<MagicLinkResponse>, StatusCode> {
    let email = Email::try_from(payload.email).map_err(|_| StatusCode::BAD_REQUEST)?;
    Span::current().record("email", field::display(email.as_str()));

    let mut storage = state.magic_link_storage;
    storage
        .push(SendMagicLink {
            email: email.as_str().to_string(),
            ip,
        })
        .await
        .map_err(|e| {
            error!(error = %e, "apalis_push_failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(event = "magic_link_requested");
    Ok(Json(MagicLinkResponse { status: "ok" }))
}
