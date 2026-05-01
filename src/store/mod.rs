pub(crate) mod hash;
pub(crate) mod pad;
mod issue;

pub use issue::issue_magic_link;

use sqlx::migrate::Migrator;
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
pub fn migrator() -> &'static Migrator { &MIGRATOR }
