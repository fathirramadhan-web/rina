//! Data model for Vera. Synced entities implement [`Entity`] so the database
//! layer and sync engine share one generic code path.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Authentication kind for a host connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Password,
    PrivateKey,
    Agent,
}

/// A credential (password or private key material), stored encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub label: String,
    pub kind: AuthKind,
    /// Encrypted secret (password bytes, or PEM private key).
    pub secret_enc: Vec<u8>,
    /// Encrypted passphrase for the private key, if any.
    pub passphrase_enc: Option<Vec<u8>>,
    pub public_key: Option<String>,
    pub updated_at: i64,
    pub deleted: bool,
}

/// A saved SSH host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub group_id: Option<String>,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub credential_id: Option<String>,
    /// Optional ProxyJump host id.
    pub jump_host_id: Option<String>,
    pub tags: Vec<String>,
    pub options: HostOptions,
    pub updated_at: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostOptions {
    /// Request an initial shell command on connect.
    pub initial_command: Option<String>,
    pub keepalive_seconds: u32,
    pub auto_reconnect: bool,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            id: String::new(),
            group_id: None,
            label: String::new(),
            hostname: String::new(),
            port: 22,
            username: "root".into(),
            credential_id: None,
            jump_host_id: None,
            tags: Vec::new(),
            options: HostOptions { initial_command: None, keepalive_seconds: 30, auto_reconnect: true },
            updated_at: 0,
            deleted: false,
        }
    }
}

/// A nested group (folder) for organizing hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub updated_at: i64,
    pub deleted: bool,
}

/// A saved command snippet, possibly with `{{placeholders}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snippet {
    pub id: String,
    pub name: String,
    pub body: String,
    pub placeholders: Vec<String>,
    pub updated_at: i64,
    pub deleted: bool,
}

/// TOFU-pinned host key. `id` is deterministic (`kh:<host>:<port>`) so devices
/// converge to the same record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub key_blob: Vec<u8>,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Trait binding an entity to a table name and id for the generic sync path.
pub trait Entity: Serialize + DeserializeOwned + Clone {
    const KIND: &'static str;
    fn id(&self) -> &str;
    fn updated_at(&self) -> i64;
    fn deleted(&self) -> bool;
}

macro_rules! impl_entity {
    ($t:ty, $kind:literal) => {
        impl Entity for $t {
            const KIND: &'static str = $kind;
            fn id(&self) -> &str {
                &self.id
            }
            fn updated_at(&self) -> i64 {
                self.updated_at
            }
            fn deleted(&self) -> bool {
                self.deleted
            }
        }
    };
}

impl_entity!(Host, "host");
impl_entity!(Group, "group");
impl_entity!(Snippet, "snippet");
impl_entity!(KnownHost, "known_host");
impl_entity!(Credential, "credential");

/// A plaintext secret that is zeroized on drop. Used to carry decrypted
/// credential material in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl std::ops::Deref for Secret {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_kinds_distinct() {
        assert_ne!(Host::KIND, Group::KIND);
        assert_ne!(Credential::KIND, Snippet::KIND);
    }

    #[test]
    fn host_serializes_auth() {
        let h = Host { label: "web".into(), ..Default::default() };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.contains("\"port\":22"));
    }
}
