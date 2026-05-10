//! External identity providers.
//!
//! Each provider lives behind its own Cargo feature flag — the default build
//! pulls no extra dependencies. Enable `google` for `Sign in with Google`.

#[cfg(feature = "google")]
pub mod google;
