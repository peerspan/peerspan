use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub public_key: String,
    pub created_at: String,
}

/// Owner is a local label, not an authenticated network member identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub capabilities: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgent {
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Registry metadata only; attachment does not prove integration readiness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub agent_id: String,
    pub integration: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachSession {
    pub agent_id: String,
    pub integration: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub sequence: i64,
    pub kind: String,
    pub subject_id: String,
    pub created_at: String,
}

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Forbidden,
    NotFound,
    Conflict(String),
    /// A required remote service (coordination) could not be reached.
    Unavailable(String),
    /// A request body over its size limit (413).
    TooLarge(String),
    /// Not enough artifact storage quota (507).
    InsufficientStorage(String),
    Internal(anyhow::Error),
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::QueryReturnedNoRows => Self::NotFound,
            other => Self::Internal(other.into()),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid request: {message}"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::NotFound => write!(f, "not found"),
            Self::Conflict(message) => write!(f, "conflict: {message}"),
            Self::Unavailable(message) => write!(f, "unavailable: {message}"),
            Self::TooLarge(message) => write!(f, "too large: {message}"),
            Self::InsufficientStorage(message) => write!(f, "insufficient storage: {message}"),
            Self::Internal(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}
