//! Vera core: data model, encrypted vault, SQLite store, ssh_config import.

pub mod crypto;
pub mod db;
pub mod error;
pub mod models;
pub mod sshconfig;
pub mod vault;

pub use error::{Error, Result};
