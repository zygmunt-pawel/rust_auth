mod cleanup;
pub(crate) mod hash;
mod issue;
pub(crate) mod pad;
pub(crate) mod session;
pub mod user;
mod verify;

pub use cleanup::{CleanupReport, cleanup_expired};
pub use issue::issue_magic_link;
pub use session::{authenticate_session, delete_session, rotate_session};
pub use user::{AutoSignupResolver, lookup_user_by_id};
pub use verify::verify_magic_link_or_code;

use sqlx::migrate::Migrator;
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub fn migrator() -> &'static Migrator {
    &MIGRATOR
}
