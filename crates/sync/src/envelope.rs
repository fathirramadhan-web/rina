//! Record encryption envelope: seal a sync record with the DEK.

use rina_core::crypto::{self, KEY_LEN};
use rina_core::error::{Error, Result};

const AAD_RECORD: &[u8] = b"rina/record/v1: ";

/// Seal a JSON-serializable entity payload with the DEK.
/// Wire format: nonce || ciphertext || tag (base64 on the wire).
pub fn seal_record(dek: &[u8; KEY_LEN], payload_json: &[u8]) -> Result<Vec<u8>> {
    crypto::seal(dek, payload_json, AAD_RECORD)
}

/// Open a sealed record. Returns the plaintext JSON bytes.
pub fn open_record(dek: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>> {
    let pt = crypto::open(dek, sealed, AAD_RECORD)?;
    Ok(pt.to_vec())
}

/// Convenience: seal any Serialize value.
pub fn seal_entity<T: serde::Serialize>(
    dek: &[u8; KEY_LEN],
    value: &T,
) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(value)?;
    seal_record(dek, &json)
}

/// Convenience: open and deserialize any DeserializeOwned value.
pub fn open_entity<T: serde::de::DeserializeOwned>(
    dek: &[u8; KEY_LEN],
    sealed: &[u8],
) -> Result<T> {
    let json = open_record(dek, sealed)?;
    serde_json::from_slice(&json).map_err(|e| Error::Other(format!("record json: {e}")))
}

/// A helper that keeps the DEK handy for a batch of operations.
pub struct RecordCrypto {
    dek: [u8; KEY_LEN],
}

impl RecordCrypto {
    pub fn new(dek: [u8; KEY_LEN]) -> Self {
        Self { dek }
    }

    pub fn seal<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        seal_entity(&self.dek, value)
    }

    pub fn open<T: serde::de::DeserializeOwned>(&self, sealed: &[u8]) -> Result<T> {
        open_entity(&self.dek, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rina_core::models::Host;

    #[test]
    fn roundtrip_entity() {
        let dek = rina_core::crypto::random_key();
        let rc = RecordCrypto::new(*dek);
        let host = Host { label: "web".into(), ..Default::default() };
        let sealed = rc.seal(&host).unwrap();
        let opened: Host = rc.open(&sealed).unwrap();
        assert_eq!(opened.label, "web");
        let other = RecordCrypto::new(*rina_core::crypto::random_key());
        assert!(other.open::<Host>(&sealed).is_err());
    }
}
