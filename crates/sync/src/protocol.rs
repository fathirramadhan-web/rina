//! Wire types for the optional zero-knowledge sync server.
//!
//! The server stores ciphertext plus minimal ordering metadata. It never sees
//! the master password, master key, DEK, or any plaintext record.

use serde::{Deserialize, Serialize};

/// What a client sends to push one local change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushItem {
    pub id: String,
    pub kind: String,
    /// Opaque ciphertext produced by [`crate::envelope::seal_entity`].
    pub blob: Vec<u8>,
    pub updated_at: i64,
    pub deleted: bool,
}

/// A record returned by the server in a pull delta.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecord {
    pub id: String,
    pub kind: String,
    pub blob: Vec<u8>,
    pub updated_at: i64,
    pub deleted: bool,
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub records: Vec<SyncRecord>,
    pub cursor: u64,
}

/// Register request. `auth_hash` is an HKDF-derived proof of the master
/// password; the server stores only its Argon2id PHC hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_hash: String,
    pub kdf_salt: Vec<u8>,
    pub kdf: rina_core::crypto::KdfParams,
    pub wrapped_dek: Vec<u8>,
    pub wrapped_dek_recovery: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub device_id: String,
}

/// Merge policy: last-write-wins per record, keyed by updated_at.
/// Equal timestamps are idempotent (no content tie-break).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    /// Apply the remote version (it is newer).
    TakeRemote,
    /// Keep the local version (it is newer or equal).
    KeepLocal,
}

pub fn decide(local_updated_at: i64, remote: &SyncRecord) -> MergeDecision {
    if remote.updated_at > local_updated_at {
        MergeDecision::TakeRemote
    } else {
        MergeDecision::KeepLocal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lww_merge() {
        let r = SyncRecord {
            id: "x".into(),
            kind: "host".into(),
            blob: vec![],
            updated_at: 100,
            deleted: false,
            seq: 1,
        };
        assert_eq!(decide(50, &r), MergeDecision::TakeRemote);
        assert_eq!(decide(100, &r), MergeDecision::KeepLocal);
        assert_eq!(decide(200, &r), MergeDecision::KeepLocal);
    }
}
