// Wspólny typ błędu dla handlerów auth — pozwala używać `?` zamiast
// `match { Ok(v) => v, Err(e) => return internal(e) }` w każdym DB callu.
//
// Każdy wariant ma jednoznaczne mapowanie na status code w `IntoResponse`.
// Body trzymamy opaque (sam status) — auth surface nie wycieka diagnostyki
// na zewnątrz, szczegóły lecą do logu serwera.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug)]
pub enum ApiError {
    // Wszystko co przeleci `?` z sqlx (z `From<sqlx::Error>` poniżej).
    // Trzymamy oryginalny error żeby był w logach przy IntoResponse.
    Db(sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Db(e) => {
                eprintln!("api error (db): {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Db(e)
    }
}
