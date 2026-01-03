//! Vera SSH layer built on `russh` (pure Rust, async).
//!
//! * [`client`]: connection config, host-key fingerprints, interaction hooks

pub mod client;
pub mod error;
pub mod sftp;
pub mod shell;

pub use client::{
    fingerprint, AuthMethod, ConnectConfig, HostKeyInfo, HostKeyStore, Interaction, SshConnection,
};
pub use error::{Result, SshError};
pub use shell::{ShellEvent, ShellHandle, ShellOptions};
