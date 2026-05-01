use std::time::Duration;

use apalis_postgres::PostgresStorage;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, Request, header::CONTENT_TYPE},
    routing::get,
};
use axum_client_ip::ClientIpSource;
use axum_prometheus::PrometheusMetricLayerBuilder;
use sqlx::PgPool;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultOnFailure, TraceLayer},
};
use tracing::{Level, Span, info_span};
use uuid::Uuid;

use crate::auth::{self, SendMagicLink};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub magic_link_storage: PostgresStorage<SendMagicLink>,
}

pub fn build_router(ip_source: ClientIpSource, state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE])
        .allow_credentials(true)
        .max_age(Duration::from_secs(86400)); // cache preflight 24h

    // Outer-most span dla każdego requestu. request_id z headera `x-request-id` jeśli klient
    // przyśle (gateway/edge); inaczej generujemy lokalnie. Wszystkie nested spany handlerów
    // dziedziczą ten span jako parent → request_id widoczny we wszystkich eventach.
    //
    // /metrics scrape (Prometheus, co 15s) → Span::none(): brak parent-spanu i on_response
    // wczesnie wychodzi. Bez tego mieliśmy ~5k log lines/dobę za nic.
    let trace = TraceLayer::new_for_http()
        .make_span_with(|req: &Request<_>| {
            if req.uri().path() == "/metrics" {
                return Span::none();
            }
            let request_id = req.headers().get("x-request-id").and_then(|v| v.to_str().ok()).map(String::from).unwrap_or_else(|| Uuid::now_v7().to_string());
            info_span!(
                "http.request",
                method = %req.method(),
                uri = %req.uri(),
                request_id = %request_id,
                status = tracing::field::Empty,
            )
        })
        .on_response(|res: &axum::http::Response<_>, latency: Duration, span: &Span| {
            // Span::none() z make_span_with → /metrics, nie logujemy nic.
            if span.is_none() {
                return;
            }
            span.record("status", res.status().as_u16());
            // Status leveling: 5xx = error, 4xx = warn (poza 401/404 = debug żeby nie spamowało),
            // reszta = debug. Sukcesy nie potrzebują poziomu INFO bo handlery same logują eventy biznesowe.
            let status = res.status();
            let latency_ms = latency.as_millis() as u64;
            if status.is_server_error() {
                tracing::error!(latency_ms, status = %status, "request failed");
            } else if status.is_client_error() && status != axum::http::StatusCode::UNAUTHORIZED && status != axum::http::StatusCode::NOT_FOUND {
                tracing::warn!(latency_ms, status = %status, "request rejected");
            } else {
                tracing::debug!(latency_ms, status = %status, "request done");
            }
        })
        .on_failure(DefaultOnFailure::new().level(Level::ERROR));

    // Prometheus: auto-counter `axum_http_requests_total{method,status,endpoint}` +
    // histogram latency. `/metrics` zwraca text format który Prometheus scrape'uje.
    // `with_default_metrics` rejestruje też `axum_http_requests_pending` (gauge in-flight).
    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new().with_default_metrics().build_pair();

    Router::new()
        .route("/metrics", get(move || {
            let handle = metric_handle.clone();
            async move { handle.render() }
        }))
        .merge(auth::routes())
        // .merge(billing::routes())
        // .merge(website_analysis::routes())
        .layer(prometheus_layer) // metryki PRZED tracingiem — pomiar pełnego czasu requesta
        .layer(trace) // request span — outer-most dla logów
        .layer(cors) // CORS — globalnie dla całego API
        .layer(DefaultBodyLimit::max(8 * 1024)) // body 8KB — sensible default
        .layer(ip_source.into_extension()) // IP source dla ClientIp extractora
        .with_state(state)
}
