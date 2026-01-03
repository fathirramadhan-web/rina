//! Cryptographic primitives for Vera: KDF, key derivation, AEAD.
//!
//! Same zero-knowledge hierarchy as a Bitwarden-style vault:
//! master password -> Argon2id -> master key -> HKDF -> KEK / auth key.
//! A random DEK encrypts every secret; the DEK is wrapped by the KEK.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Argon2id cost parameters. Serialized into the vault so future devices can
/// reproduce the derivation even if defaults change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 4 }
    }
}

impl KdfParams {
    /// Cheap parameters for unit tests only. Never use in release.
    pub fn insecure_for_tests() -> Self {
        Self { m_cost_kib: 8 * 1024, t_cost: 1, p_cost: 1 }
    }
}

/// A key that is wiped when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        Self::new(random_key_bytes())
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for SecretKey {
    type Target = [u8; KEY_LEN];
    fn deref(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn random_key() -> SecretKey {
    SecretKey::new(random_bytes::<KEY_LEN>())
}

fn random_key_bytes() -> [u8; KEY_LEN] {
    random_bytes::<KEY_LEN>()
}

/// Run Argon2id to derive the 32-byte master key from a password and salt.
pub fn derive_master_key(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<SecretKey> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| Error::Crypto(format!("bad kdf params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
    Ok(SecretKey::new(out))
}

/// HKDF-SHA256 to derive an independent subkey from the master key.
pub fn derive_subkey(ikm: &[u8], info: &str) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info.as_bytes(), &mut okm).expect("hkdf expand");
    SecretKey::new(okm)
}

/// Encrypt `plaintext` under `key` with XChaCha20-Poly1305.
///
/// AAD binds the ciphertext to a context (record id or key label) so a
/// malicious server cannot swap blobs between records.
///
/// Wire format: nonce (24) || ciphertext || tag (16), base64 not applied here.
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher(key)?;
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("encrypt failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a value produced by [`seal`].
pub fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("ciphertext too short".into()));
    }
    let cipher = cipher(key)?;
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| Error::Crypto("decrypt failed (wrong key or tampered)".into()))?;
    Ok(Zeroizing::new(pt))
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    let k: [u8; 32] = key.try_into().map_err(|_| Error::Crypto("bad key length".into()))?;
    Ok(XChaCha20Poly1305::new((&k).into()))
}

/// Encode a raw recovery key as human-friendly base32 groups.
pub fn encode_recovery_key(raw: &[u8; KEY_LEN]) -> String {
    // Crockford-ish base32 for readability; groups of 5.
    const ALPHA: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::new();
    for &b in raw {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1f) as usize;
            if out.len() > 0 && out.len() % 6 == 0 {
                out.push('-');
            }
            out.push(ALPHA[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1f) as usize;
        if out.len() % 6 == 0 {
            out.push('-');
        }
        out.push(ALPHA[idx] as char);
    }
    out
}

/// Decode a recovery key produced by [`encode_recovery_key`].
pub fn decode_recovery_key(s: &str) -> Result<[u8; KEY_LEN]> {
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    const ALPHA: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = [0u8; KEY_LEN];
    let mut oi = 0usize;
    for c in clean.chars() {
        let idx = ALPHA
            .iter()
            .position(|&a| a as char == c.to_ascii_uppercase())
            .ok_or_else(|| Error::Invalid("invalid recovery key character".into()))?;
        bits = (bits << 5) | idx as u32;
        nbits += 5;
        if nbits >= 8 && oi < KEY_LEN {
            nbits -= 8;
            out[oi] = ((bits >> nbits) & 0xff) as u8;
            oi += 1;
        }
    }
    if oi != KEY_LEN {
        return Err(Error::Invalid("recovery key wrong length".into()));
    }
    Ok(out)
}

pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>> {
    B64.decode(data).map_err(|_| Error::Invalid("invalid base64".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let key = random_key();
        let ct = seal(key.as_ref(), b"hello", b"ctx-a").unwrap();
        assert_eq!(&open(key.as_ref(), &ct, b"ctx-a").unwrap()[..], b"hello");
        assert!(open(key.as_ref(), &ct, b"ctx-b").is_err());
        let wrong = random_key();
        assert!(open(wrong.as_ref(), &ct, b"ctx-a").is_err());
    }

    #[test]
    fn master_key_depends_on_salt_and_password() {
        let kdf = KdfParams::insecure_for_tests();
        let a = derive_master_key("pw", &[0u8; SALT_LEN], &kdf).unwrap();
        let b = derive_master_key("pw", &[1u8; SALT_LEN], &kdf).unwrap();
        let c = derive_master_key("px", &[0u8; SALT_LEN], &kdf).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn recovery_key_roundtrip() {
        let raw = random_bytes::<KEY_LEN>();
        let s = encode_recovery_key(&raw);
        assert_eq!(decode_recovery_key(&s).unwrap(), raw);
    }
}
