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

/// Stable identifier of an external identity provider as stored in
/// `auth_identities.provider`. The value must be a `'static` literal — providers
/// hardcode it at build time (e.g. `ProviderId("google")`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderId(pub &'static str);

impl ProviderId {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl From<&'static str> for ProviderId {
    fn from(v: &'static str) -> Self {
        Self(v)
    }
}

/// Provider-issued stable user identifier (e.g. Google's `sub` claim). Opaque
/// to this crate — never used as a join key on email, always on `(provider, subject)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentitySubject(pub String);

impl IdentitySubject {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for IdentitySubject {
    fn from(v: String) -> Self {
        Self(v)
    }
}

impl From<&str> for IdentitySubject {
    fn from(v: &str) -> Self {
        Self(v.to_owned())
    }
}

#[async_trait]
pub trait IdentityProvider: Send + Sync + 'static {
    /// Stable provider tag stored in `auth_identities.provider` (e.g. `ProviderId("google")`).
    /// MUST match the value set on `VerifiedIdentity::provider` returned by `verify`.
    fn provider_id(&self) -> ProviderId;

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
    pub provider: ProviderId,
    pub subject: IdentitySubject,
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
