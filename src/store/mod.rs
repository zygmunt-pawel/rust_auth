pub(crate) mod hash;
pub(crate) mod pad;

use sqlx::migrate::Migrator;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub fn migrator() -> &'static Migrator {
    &MIGRATOR
}
