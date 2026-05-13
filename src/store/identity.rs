//! `complete_identity_login` — orchestrates external identity sign-in.
//!
//! Provider-agnostic: takes any `IdentityProvider` and a raw token, hands the
//! token to the provider for verification, then links by `(provider, subject)`
//! to either an existing identity row or a new one (auto-link by email via
//! the `UserResolver`). Always ends in a fresh session via `create_session`.

use std::net::IpAddr;

use sqlx::PgPool;
use tracing::field;

use crate::core::{
    AuthConfig, AuthError, IdentityError, IdentityProvider, SessionEvent, SessionEventSink,
    SessionToken, UserId, UserResolver,
};
use crate::store::session::create_session;

#[allow(clippy::too_many_arguments)] // public entry point — reshaping into a struct adds noise without value
#[tracing::instrument(
    name = "auth.identity.login",
    skip_all,
    fields(
        provider = field::Empty,
        email = field::Empty,
        subject = field::Empty,
        user_id = field::Empty,
        session_id = field::Empty,
        outcome = field::Empty,
        linked = field::Empty,
    ),
)]
pub async fn complete_identity_login(
    pool: &PgPool,
    provider: &dyn IdentityProvider,
    raw_token: &str,
    ip: IpAddr,
    user_agent: Option<&str>,
    resolver: &dyn UserResolver,
    cfg: &AuthConfig,
    sink: &dyn SessionEventSink,
) -> Result<(SessionToken, UserId), AuthError> {
    tracing::Span::current().record("provider", provider.provider_id().as_str());

    // 1. Verify the provider-issued token. Map identity errors onto AuthError;
    //    transient (e.g. JWKS down) becomes Internal so the consumer surfaces
    //    a 5xx, while genuine rejection (bad/expired/email-unverified token)
    //    stays Unauthorized.
    let identity = match provider.verify(raw_token).await {
        Ok(i) => i,
        Err(IdentityError::EmailNotVerified) => {
            tracing::Span::current().record("outcome", "email_not_verified");
            tracing::warn!(
                outcome = "email_not_verified",
                "provider rejected: email not verified"
            );
            return Err(AuthError::Unauthorized);
        }
        Err(IdentityError::Invalid(reason)) => {
            tracing::Span::current().record("outcome", "invalid_token");
            tracing::debug!(
                outcome = "invalid_token",
                reason = %reason,
                "provider rejected token"
            );
            return Err(AuthError::Unauthorized);
        }
        Err(IdentityError::Transient(reason)) => {
            tracing::Span::current().record("outcome", "provider_transient");
            tracing::warn!(
                outcome = "provider_transient",
                reason = %reason,
                "provider transient error"
            );
            return Err(AuthError::Internal(format!(
                "identity provider transient: {reason}"
            )));
        }
    };

    tracing::Span::current().record("email", identity.email.for_log(cfg.log_full_email));
    tracing::Span::current().record("subject", identity.subject.as_str());

    // 2. Lookup existing identity by stable (provider, subject) key.
    #[derive(sqlx::FromRow)]
    struct IdentityRow {
        user_id: i64,
    }
    let existing: Option<IdentityRow> =
        sqlx::query_as("SELECT user_id FROM auth_identities WHERE provider = $1 AND subject = $2")
            .bind(identity.provider.as_str())
            .bind(identity.subject.as_str())
            .fetch_optional(pool)
            .await?;

    let (user_id, linked) = match existing {
        Some(IdentityRow { user_id: uid }) => {
            // 3a. Known identity — bump last_login_at, reuse the user.
            sqlx::query(
                "UPDATE auth_identities SET last_login_at = NOW()
                 WHERE provider = $1 AND subject = $2",
            )
            .bind(identity.provider.as_str())
            .bind(identity.subject.as_str())
            .execute(pool)
            .await?;
            (UserId(uid), false)
        }
        None => {
            // 3b. New identity — resolve-or-create the user by email
            //     (auto-link to an existing magic-link account if email matches),
            //     then attach the identity row.
            let user_id = resolver
                .resolve_or_create(pool, &identity.email)
                .await
                .map_err(|e| AuthError::Internal(format!("resolver: {e}")))?;
            sqlx::query(
                "INSERT INTO auth_identities (user_id, provider, subject, email_at_link)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(user_id.0)
            .bind(identity.provider.as_str())
            .bind(identity.subject.as_str())
            .bind(identity.email.as_str())
            .execute(pool)
            .await?;
            sink.on_event(SessionEvent::IdentityLinked {
                user_id,
                provider: identity.provider,
                subject: identity.subject.clone(),
            })
            .await;
            (user_id, true)
        }
    };

    tracing::Span::current().record("user_id", user_id.0);

    // 4. Mint the session.
    let session = create_session(pool, user_id, ip, user_agent, cfg).await?;
    tracing::Span::current().record("session_id", session.session_id.0);

    sink.on_event(SessionEvent::Created {
        session_id: session.session_id,
        user_id,
        ip,
        user_agent: user_agent.map(String::from),
    })
    .await;

    tracing::Span::current().record("outcome", "success");
    tracing::Span::current().record("linked", linked);
    tracing::info!(outcome = "success", linked, "identity login success");

    Ok((session.token, user_id))
}
