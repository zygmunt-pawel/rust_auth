//! External identity providers (Google, Apple, GitHub, ...).
//!
//! `IdentityProvider` is the seam: a verifier turns a raw provider-issued token
//! into a `VerifiedIdentity`. Orchestration (`store::complete_identity_login`)
//! is provider-agnostic — it only sees `VerifiedIdentity` and links by
//! `(provider, subject)`.
//!
//! `subject` MUST be the provider's stable, opaque user id (Google's `sub`
//! claim). Email is mutable on the provider side and is intentionally NOT used
//! as the identity key — see `auth_identities.email_at_link`.

use async_trait::async_trait;

use crate::core::Email;

#[async_trait]
pub trait IdentityProvider: Send + Sync + 'static {
    /// Stable provider tag stored in `auth_identities.provider` (e.g. `"google"`).
    /// MUST match the value set on `VerifiedIdentity::provider` returned by `verify`.
    fn provider_id(&self) -> &'static str;

    /// Validate a provider-issued credential (e.g. Google id_token JWT) and return
    /// the verified identity. The implementation is expected to enforce all
    /// provider-specific security checks (signature, audience, issuer, expiry,
    /// `email_verified`, etc.); orchestration trusts the returned `VerifiedIdentity`
    /// fully.
    async fn verify(&self, raw_token: &str) -> Result<VerifiedIdentity, IdentityError>;
}

/// Outcome of a successful provider verification. Consumed by orchestration to
/// link or create a local user.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub provider: &'static str,
    pub subject: String,
    pub email: Email,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum IdentityError {
    #[error("token invalid: {0}")]
    Invalid(String),
    #[error("email not verified by provider")]
    EmailNotVerified,
    #[error("provider transient error: {0}")]
    Transient(String),
}
