//! Vera SSH layer built on `russh` (pure Rust, async).
//!
//! * [`client`]: connection config, host-key fingerprints, interaction hooks

pub mod client;
pub mod error;
pub mod sftp;
pub mod shell;

pub use client::{
    authenticate_keyboard_interactive, fingerprint, AuthMethod, ConnectConfig, HeadlessInteraction,
    HostKeyInfo, HostKeyStore, Interaction, MemHostKeyStore, SshConnection, VeraHandler,
};
pub use error::{Result, SshError};
pub use shell::{ShellEvent, ShellHandle, ShellOptions};
