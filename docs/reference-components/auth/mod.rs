mod cookie;
mod email;
mod error;
mod jobs;
mod logout;
mod magic_link;
mod repo;
mod session;
mod tokens;
mod verify_token;

pub use jobs::{SendMagicLink, handle_magic_link};
// Re-eksport infrastruktury sesyjnej dla przyszłych chronionych route'ów
// (`route_layer(from_fn_with_state(state, require_session))`). Brak callera
// w obecnym kodzie — `allow` zdejmuje warning do czasu wpięcia pierwszego endpointu.
#[allow(unused_imports)]
pub use session::{UserId, require_session};

use std::sync::Arc;

use axum::{Router, middleware::from_fn, routing::post};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use crate::app::AppState;
use crate::middleware::{TrustedIpKeyExtractor, constant_time, stash_client_ip};

pub fn routes() -> Router<AppState> {
    // /auth/magic-link: 12/s burst 2 — agresywny, bo ten endpoint może być
    // bombardowany enumeracją emaili. Worker robi drugą warstwę (per email + per IP).
    let magic_link_governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(12)
            .burst_size(2)
            .key_extractor(TrustedIpKeyExtractor)
            .finish()
            .unwrap(),
    );

    // /api/verify_token: 30/min per IP. Niższy limit bo legitimate user kliknie
    // link najwyżej kilka razy; wszystko ponad to to brute force po `token_hash`.
    // per_millisecond(2000) = 1 req per 2s → ~30/min, burst 5 dla retry-friendly UX.
    let verify_governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(2000)
            .burst_size(5)
            .key_extractor(TrustedIpKeyExtractor)
            .finish()
            .unwrap(),
    );

    // pierwszy `.layer()` jest INNERMOST, ostatni OUTERMOST.
    let magic_link_route = post(magic_link::magic_link)
        .layer(GovernorLayer::new(magic_link_governor)) // (innermost) 12/s burst 2 → 429
        .layer(from_fn(stash_client_ip)) //            wstrzykuje TrustedIp dla governora
        .layer(from_fn(constant_time)); // (outermost) deadline 100ms

    // verify_token: bez constant_time — user już ma ważny token, timing leak
    // tutaj jest mniej krytyczny niż na magic-link issuance (tam leak = enumeracja kont).
    let verify_token_route = post(verify_token::verify_token).layer(GovernorLayer::new(verify_governor)).layer(from_fn(stash_client_ip));

    Router::new()
        .route("/auth/magic-link", magic_link_route)
        .route("/api/verify_token", verify_token_route)
        .route("/auth/logout", post(logout::logout))
}
