pub mod config;
pub mod email;
pub mod error;
pub mod tokens;
pub mod traits;
pub mod user;

pub use config::{AuthConfig, Pepper, SameSite};
pub use email::{Email, EmailError};
pub use error::{AuthError, MailerError, ResolverError};
pub use tokens::{MagicLinkToken, SessionToken, VerifyCode};
pub use traits::{AllowAll, EmailPolicy, NoOpSink, SessionEvent, SessionEventSink};
pub use user::{ActiveSession, AuthenticatedUser, User, UserId, UserStatus};
