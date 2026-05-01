//! Reference integration of `auth_rust` with axum 0.8.
//!
//! NOT public API — copy-paste this into your own crate, do not depend on it.
//! Demonstrates: AppState, require_session middleware, AuthError → Response,
//! DisposableBlocklist as EmailPolicy, TracingSink as SessionEventSink.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::{COOKIE, SET_COOKIE}},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use auth_rust::core::{
    AuthConfig, AuthError, AuthenticatedUser, Email, EmailPolicy, MagicLinkToken,
    Mailer, MailerError, Pepper, SameSite, SessionEvent, SessionEventSink,
    VerifyCode, VerifyInput,
};
use auth_rust::core::cookie::{session_cookie_clear_header_value, session_cookie_header_value};
use auth_rust::store::{
    AutoSignupResolver, authenticate_session, delete_session, issue_magic_link,
    lookup_user_by_id, rotate_session, verify_magic_link_or_code,
};

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    mailer: Arc<dyn Mailer>,
    cfg: Arc<AuthConfig>,
    sink: Arc<dyn SessionEventSink>,
}

// ---------- Mailer (stub) ----------
struct LogMailer;
#[async_trait::async_trait]
impl Mailer for LogMailer {
    async fn send_magic_link(
        &self,
        email: &Email,
        link: &MagicLinkToken,
        code: &VerifyCode,
    ) -> Result<(), MailerError> {
        tracing::info!(email = email.as_str(), link = link.as_str(), code = code.as_str(), "mock_mail");
        Ok(())
    }
}

// ---------- EmailPolicy: simple disposable blocklist ----------
struct DisposableBlocklist { blocked: HashSet<String> }

impl DisposableBlocklist {
    fn from_embedded() -> Self {
        // Replace with `include_str!("../disposable_domains.txt")` in production.
        let raw = "mailinator.com\nguerrillamail.com\n10minutemail.com";
        let blocked = raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect();
        Self { blocked }
    }
}

#[async_trait::async_trait]
impl EmailPolicy for DisposableBlocklist {
    async fn allow(&self, email: &Email) -> bool {
        let domain = email.as_str().rsplit('@').next().unwrap_or("");
        !self.blocked.contains(domain)
    }
}

// ---------- SessionEventSink: tracing ----------
struct TracingSink;
#[async_trait::async_trait]
impl SessionEventSink for TracingSink {
    async fn on_event(&self, event: SessionEvent) {
        tracing::info!(event = ?event, "session_event");
    }
}

// ---------- AuthError → axum Response ----------
struct ApiError(AuthError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        status.into_response()
    }
}
impl From<AuthError> for ApiError { fn from(e: AuthError) -> Self { Self(e) } }

// ---------- middleware ----------
async fn require_session(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let cookie_header = req.headers().get(COOKIE).and_then(|v| v.to_str().ok());
    match authenticate_session(&state.pool, cookie_header, &state.cfg, &*state.sink).await {
        Ok((user, refresh_cookie)) => {
            req.extensions_mut().insert(user);
            let mut resp = next.run(req).await;
            if let Some(c) = refresh_cookie {
                resp.headers_mut().insert(SET_COOKIE, c.parse().unwrap());
            }
            resp
        }
        Err(_) => {
            let mut resp = StatusCode::UNAUTHORIZED.into_response();
            resp.headers_mut().insert(
                SET_COOKIE,
                session_cookie_clear_header_value(&state.cfg).parse().unwrap(),
            );
            resp
        }
    }
}

// ---------- handlers ----------
#[derive(Deserialize)]
struct MagicLinkRequest { email: String }

async fn magic_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> StatusCode {
    let ip = client_ip(&headers);
    if let Err(e) = issue_magic_link(&state.pool, &req.email, ip, &state.cfg, &*state.mailer).await {
        tracing::warn!(error = %e, "mailer failed");
    }
    StatusCode::OK
}

#[derive(Deserialize)]
#[serde(untagged)]
enum VerifyBody {
    Token { token: String },
    Code { email: String, code: String },
}

async fn verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers);
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    let input = match body {
        VerifyBody::Token { token } => VerifyInput::Token(MagicLinkToken::from_string(token)),
        VerifyBody::Code { email, code } => VerifyInput::Code {
            email: Email::try_from(email).map_err(|_| AuthError::InvalidToken)?,
            code: VerifyCode::from_string(code),
        },
    };
    let (token, _user_id) = verify_magic_link_or_code(
        &state.pool, input, ip, ua, &AutoSignupResolver, &state.cfg, &*state.sink,
    ).await?;
    let cookie = session_cookie_header_value(&token, &state.cfg);
    Ok((StatusCode::OK, [(SET_COOKIE, cookie)]).into_response())
}

async fn logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let cookie_header = headers.get(COOKIE).and_then(|v| v.to_str().ok());
    let _ = delete_session(&state.pool, cookie_header, &state.cfg, &*state.sink).await;
    let clear = session_cookie_clear_header_value(&state.cfg);
    (StatusCode::OK, [(SET_COOKIE, clear)]).into_response()
}

#[derive(Serialize)]
struct MeResponse { id: i64, email: String }

async fn me_handler(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<MeResponse>, ApiError> {
    let u = lookup_user_by_id(&state.pool, user.id).await?
        .ok_or(AuthError::Unauthorized)?;
    Ok(Json(MeResponse { id: u.id.0, email: u.email }))
}

fn client_ip(_headers: &HeaderMap) -> IpAddr {
    // Use axum-client-ip in real apps; placeholder here.
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    auth_rust::store::migrator().run(&pool).await?;

    let pepper = Pepper::from_base64(&std::env::var("AUTH_TOKEN_PEPPER")?);
    let mut cfg = AuthConfig::new(pepper);
    cfg.policy = Arc::new(DisposableBlocklist::from_embedded());
    cfg.event_sink = Arc::new(TracingSink);
    cfg.same_site = SameSite::Strict;

    let state = AppState {
        pool,
        mailer: Arc::new(LogMailer),
        cfg: Arc::new(cfg),
        sink: Arc::new(TracingSink),
    };

    let protected = Router::new()
        .route("/auth/me", get(me_handler))
        .route("/auth/logout", post(logout_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_session));

    let public = Router::new()
        .route("/auth/magic-link", post(magic_link_handler))
        .route("/auth/verify", post(verify_handler));

    let app = public.merge(protected).with_state(state);

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0,0,0,0], 3000))).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
