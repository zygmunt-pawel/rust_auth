use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub public_id: Uuid,
    pub email: String,
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
    pub session_id: i64,
    pub user_id: UserId,
    pub needs_refresh: bool,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: UserId,
    pub public_id: Uuid,
    pub email: String,
    pub session_id: i64,
}
