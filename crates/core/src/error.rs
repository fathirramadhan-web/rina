//! Unified error type for the Vera core crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("wrong master password")]
    WrongPassword,

    #[error("{0}")]
    Invalid(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("database error: {0}")]
    Db(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("vault is locked")]
    Locked,

    #[error("io error: {0}")]
    Io(String),

    #[error("{0}")]
    Other(String),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match &e {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound("row".into()),
            _ => Error::Db(e.to_string()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Other(format!("json: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
