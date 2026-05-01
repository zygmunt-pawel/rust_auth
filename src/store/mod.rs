pub(crate) mod hash;
pub(crate) mod pad;
pub(crate) mod session;
mod cleanup;
mod issue;
mod verify;
pub mod user;

pub use cleanup::{cleanup_expired, CleanupReport};
pub use issue::issue_magic_link;
pub use verify::verify_magic_link_or_code;
pub use session::{authenticate_session, delete_session, rotate_session};
pub use user::{AutoSignupResolver, lookup_user_by_id};

use sqlx::migrate::Migrator;
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub fn migrator() -> &'static Migrator { &MIGRATOR }
