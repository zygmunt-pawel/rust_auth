pub(crate) mod hash;
pub(crate) mod pad;
mod issue;
mod verify;
pub mod user;

pub use issue::issue_magic_link;
pub use verify::verify_magic_link_or_code;
pub use user::AutoSignupResolver;

use sqlx::migrate::Migrator;
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub fn migrator() -> &'static Migrator { &MIGRATOR }
