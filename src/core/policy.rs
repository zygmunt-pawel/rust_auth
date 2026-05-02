//! Built-in [`EmailPolicy`] implementations.
//!
//! ## `DisposableBlocklist`
//!
//! Bundled list of ~5400 disposable email domains, sourced from
//! <https://github.com/disposable-email-domains/disposable-email-domains> (CC0 license).
//! Snapshot date is whenever you last refreshed `assets/disposable_domains.txt`
//! in this crate. Lib does NOT fetch anything at runtime.
//!
//! NOT enabled by default — disposable-email blocking is policy. The library doesn't
//! decide for you whether your B2C trial flow should accept `@mailinator.com` or not.
//! Opt in by setting `AuthConfig.policy = Arc::new(DisposableBlocklist::with_default_list())`.

use std::collections::HashSet;

use async_trait::async_trait;

use crate::core::{Email, EmailPolicy};

const BUNDLED_LIST: &str = include_str!("../../assets/disposable_domains.txt");

/// Blocks email domains known to be disposable / temporary.
///
/// Build with [`with_default_list`] (bundled snapshot) or [`empty`] (Your Own Custom Set).
/// Add more with [`add`] / [`add_iter`]. Carve exceptions with [`allow`].
///
/// ```ignore
/// let policy = DisposableBlocklist::with_default_list()
///     .add("internal-bad.example")          // domain you also want blocked
///     .unblock("mailinator.com");           // QA mailbox exception
/// cfg.policy = std::sync::Arc::new(policy);
/// ```
///
/// [`with_default_list`]: Self::with_default_list
/// [`empty`]: Self::empty
/// [`add`]: Self::add
/// [`add_iter`]: Self::add_iter
/// [`unblock`]: Self::unblock
pub struct DisposableBlocklist {
    blocked: HashSet<String>,
    explicitly_allowed: HashSet<String>,
}

impl DisposableBlocklist {
    /// Start with the bundled list of ~5400 known disposable domains.
    pub fn with_default_list() -> Self {
        let blocked = BUNDLED_LIST
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_ascii_lowercase())
            .collect();
        Self {
            blocked,
            explicitly_allowed: HashSet::new(),
        }
    }

    /// Start empty. Build up explicitly via [`add`] / [`add_iter`].
    ///
    /// [`add`]: Self::add
    /// [`add_iter`]: Self::add_iter
    pub fn empty() -> Self {
        Self {
            blocked: HashSet::new(),
            explicitly_allowed: HashSet::new(),
        }
    }

    /// Add one domain to the blocklist (case-insensitive).
    pub fn add(mut self, domain: impl Into<String>) -> Self {
        self.blocked.insert(domain.into().to_ascii_lowercase());
        self
    }

    /// Add many domains in one go.
    pub fn add_iter<I, S>(mut self, domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for d in domains {
            self.blocked.insert(d.into().to_ascii_lowercase());
        }
        self
    }

    /// Carve an exception — domain bypasses the blocklist (e.g. QA / staging mailboxes).
    /// Method named `unblock` to avoid conflict with the `EmailPolicy::allow` trait method.
    pub fn unblock(mut self, domain: impl Into<String>) -> Self {
        self.explicitly_allowed
            .insert(domain.into().to_ascii_lowercase());
        self
    }

    /// Number of blocked domains (post-allowlist).
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }
}

impl DisposableBlocklist {
    /// Direct domain lookup against the blocked set, ignoring the per-instance allowlist.
    /// Useful when composing your own [`EmailPolicy`] and you only want the disposable
    /// check without `DisposableBlocklist::allow`'s full email-routing logic.
    pub fn contains_domain(&self, domain: &str) -> bool {
        self.blocked.contains(&domain.to_ascii_lowercase())
    }
}

#[async_trait]
impl EmailPolicy for DisposableBlocklist {
    async fn allow(&self, email: &Email) -> bool {
        // `Email::try_from` already lowercases — domain extracted here is lowercase.
        let domain = match email.as_str().rsplit('@').next() {
            Some(d) => d,
            None => return false,
        };
        if self.explicitly_allowed.contains(domain) {
            return true;
        }
        !self.blocked.contains(domain)
    }

    fn name(&self) -> &'static str { "DisposableBlocklist" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_list_has_thousands_of_entries() {
        let p = DisposableBlocklist::with_default_list();
        assert!(p.blocked_count() > 1000, "got {}", p.blocked_count());
    }

    #[tokio::test]
    async fn default_list_blocks_known_disposable() {
        let p = DisposableBlocklist::with_default_list();
        let bad = Email::try_from("user@mailinator.com".to_string()).unwrap();
        assert!(!p.allow(&bad).await);
    }

    #[tokio::test]
    async fn default_list_allows_normal_email() {
        let p = DisposableBlocklist::with_default_list();
        let good = Email::try_from("user@example.com".to_string()).unwrap();
        assert!(p.allow(&good).await);
    }

    #[tokio::test]
    async fn empty_blocks_nothing() {
        let p = DisposableBlocklist::empty();
        let any = Email::try_from("user@mailinator.com".to_string()).unwrap();
        assert!(p.allow(&any).await);
    }

    #[tokio::test]
    async fn add_extends_blocklist() {
        let p = DisposableBlocklist::empty().add("internal-bad.example");
        let bad = Email::try_from("user@internal-bad.example".to_string()).unwrap();
        assert!(!p.allow(&bad).await);
    }

    #[tokio::test]
    async fn add_iter_works() {
        let p = DisposableBlocklist::empty().add_iter(["a.example", "b.example"]);
        assert!(!p.allow(&Email::try_from("u@a.example".to_string()).unwrap()).await);
        assert!(!p.allow(&Email::try_from("u@b.example".to_string()).unwrap()).await);
    }

    #[tokio::test]
    async fn unblock_overrides_default_list() {
        let p = DisposableBlocklist::with_default_list().unblock("mailinator.com");
        let qa = Email::try_from("qa@mailinator.com".to_string()).unwrap();
        assert!(p.allow(&qa).await);
    }

    #[tokio::test]
    async fn case_insensitive_on_add() {
        let p = DisposableBlocklist::empty().add("Bad-Domain.COM");
        let e = Email::try_from("user@bad-domain.com".to_string()).unwrap();
        assert!(!p.allow(&e).await);
    }
}
