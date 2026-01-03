//! Error type for the Vera SSH layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("connection error: {0}")]
    Connect(String),

    #[error("host key rejected")]
    HostKeyRejected,

    #[error("sftp error: {0}")]
    Sftp(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("core error: {0}")]
    Core(#[from] rina_core::Error),
}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        SshError::Connect(e.to_string())
    }
}

impl From<std::io::Error> for SshError {
    fn from(e: std::io::Error) -> Self {
        SshError::Connect(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SshError>;
