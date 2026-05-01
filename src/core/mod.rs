pub mod config;
pub mod cookie;
pub mod email;
pub mod error;
pub mod tokens;
pub mod traits;
pub mod user;

pub use config::{AuthConfig, Pepper, SameSite};
pub use cookie::{
    extract_session_cookie_value, session_cookie_clear_header_value, session_cookie_header_value,
};
pub use email::{Email, EmailError};
pub use error::{AuthError, MailerError, ResolverError};
pub use tokens::{MagicLinkToken, SessionToken, VerifyCode};
pub use traits::{AllowAll, EmailPolicy, NoOpSink, SessionEvent, SessionEventSink};
pub use user::{ActiveSession, AuthenticatedUser, User, UserId, UserStatus};
