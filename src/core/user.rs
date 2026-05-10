use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::email::Email;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub i64);

impl From<i64> for UserId {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserPublicId(pub Uuid);

impl From<Uuid> for UserPublicId {
    fn from(v: Uuid) -> Self {
        Self(v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub i64);

impl From<i64> for SessionId {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub public_id: UserPublicId,
    pub email: Email,
    pub status: UserStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
}

impl UserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Suspended => "suspended",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveSession {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub needs_refresh: bool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: UserId,
    pub public_id: UserPublicId,
    pub email: Email,
    pub session_id: SessionId,
}
