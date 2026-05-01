use std::net::IpAddr;
use std::time::Duration;

use axum::{extract::Request, http, middleware::Next, response::Response};
use axum_client_ip::ClientIp;
use tokio::time::{Instant, sleep_until};
use tower_governor::{GovernorError, key_extractor::KeyExtractor};

const RESPONSE_DEADLINE: Duration = Duration::from_millis(100);

// wszystkie odpowiedzi padają w stały czas (anti-timing attack)
pub async fn constant_time(req: Request, next: Next) -> Response {
    let deadline = Instant::now() + RESPONSE_DEADLINE;
    let response = next.run(req).await;
    sleep_until(deadline).await;
    response
}

// wstrzykuje zaufany IP do extensions, żeby tower_governor (inner) miał skąd go wziąć
#[derive(Clone, Debug)]
pub struct TrustedIp(pub IpAddr);

pub async fn stash_client_ip(ClientIp(ip): ClientIp, mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(TrustedIp(ip));
    next.run(req).await
}

#[derive(Clone, Debug)]
pub struct TrustedIpKeyExtractor;

impl KeyExtractor for TrustedIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        req.extensions().get::<TrustedIp>().map(|t| t.0).ok_or(GovernorError::UnableToExtractKey)
    }
}
