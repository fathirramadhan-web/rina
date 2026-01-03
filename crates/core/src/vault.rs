//! Encrypted credential vault.
//!
//! Key hierarchy:
//! ```text
//! master password --Argon2id(salt)--> master key (MK)
//!   MK --HKDF "rina/enc/v1"--> KEK   (wraps the DEK)
//!   MK --HKDF "rina/auth/v1"--> auth key (proves the password to the sync server)
//! DEK (random 32 bytes) encrypts every secret and every sync record.
//! recovery key (random 32 bytes) also wraps the DEK, for password recovery.
//! ```
//! Changing the master password re-wraps the DEK only; records are never re-encrypted.

use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SecretKey, KEY_LEN, SALT_LEN};
use crate::error::{Error, Result};

const INFO_ENC: &str = "rina/enc/v1";
const INFO_AUTH: &str = "rina/auth/v1";
const INFO_RECOVERY_AUTH: &str = "rina/recovery-auth/v1";
const AAD_DEK: &[u8] = b"rina/dek/v1";
const AAD_DEK_RECOVERY: &[u8] = b"rina/dek-recovery/v1";

/// Persisted (non-secret) vault metadata, stored in the database / on disk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultMeta {
    pub kdf_salt: Vec<u8>,
    pub kdf: KdfParams,
    /// DEK sealed with the KEK derived from the master password.
    pub wrapped_dek: Vec<u8>,
    /// DEK sealed with the recovery key (if a recovery kit was generated).
    pub wrapped_dek_recovery: Option<Vec<u8>>,
}

/// Secrets held in memory while the vault is unlocked.
pub struct UnlockedKeys {
    pub dek: SecretKey,
    /// Proof of the master password for the sync server. Never stored on disk.
    pub auth_key: SecretKey,
}

impl std::fmt::Debug for UnlockedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockedKeys(..)")
    }
}

/// Keys derived from the master password.
pub struct PasswordKeys {
    pub kek: SecretKey,
    pub auth_key: SecretKey,
}

pub fn password_keys(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<PasswordKeys> {
    let mk = crypto::derive_master_key(password, salt, kdf)?;
    Ok(PasswordKeys {
        kek: crypto::derive_subkey(mk.as_ref(), INFO_ENC),
        auth_key: crypto::derive_subkey(mk.as_ref(), INFO_AUTH),
    })
}

pub fn recovery_auth_key(recovery_key: &[u8; KEY_LEN]) -> SecretKey {
    crypto::derive_subkey(recovery_key, INFO_RECOVERY_AUTH)
}

pub fn wrap_dek(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    crypto::seal(kek, dek, AAD_DEK)
}

pub fn unwrap_dek(kek: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<SecretKey> {
    let raw = crypto::open(kek, wrapped, AAD_DEK).map_err(|_| Error::WrongPassword)?;
    to_key(&raw)
}

pub fn wrap_dek_recovery(recovery_key: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    crypto::seal(recovery_key, dek, AAD_DEK_RECOVERY)
}

pub fn unwrap_dek_recovery(recovery_key: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<SecretKey> {
    let raw = crypto::open(recovery_key, wrapped, AAD_DEK_RECOVERY)
        .map_err(|_| Error::Invalid("recovery key does not match this vault".into()))?;
    to_key(&raw)
}

fn to_key(raw: &[u8]) -> Result<SecretKey> {
    if raw.len() != KEY_LEN {
        return Err(Error::Crypto("unexpected key length".into()));
    }
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(raw);
    Ok(SecretKey::new(*k))
}

/// Result of creating a new vault.
pub struct NewVault {
    pub meta: VaultMeta,
    pub keys: UnlockedKeys,
    /// Human-readable recovery key; shown to the user once, never stored.
    pub recovery_key: String,
}

impl VaultMeta {
    /// Create a brand-new vault with a random DEK and a recovery key.
    pub fn create(password: &str, kdf: KdfParams) -> Result<NewVault> {
        if password.chars().count() < 8 {
            return Err(Error::Invalid(
                "master password must be at least 8 characters".into(),
            ));
        }
        let salt = crypto::random_bytes::<SALT_LEN>().to_vec();
        let pk = password_keys(password, &salt, &kdf)?;
        let dek = crypto::random_key();
        let recovery = crypto::random_key();
        let meta = VaultMeta {
            kdf_salt: salt,
            kdf,
            wrapped_dek: wrap_dek(&pk.kek, &dek)?,
            wrapped_dek_recovery: Some(wrap_dek_recovery(&recovery, &dek)?),
        };
        Ok(NewVault {
            meta,
            keys: UnlockedKeys { dek, auth_key: pk.auth_key },
            recovery_key: crypto::encode_recovery_key(&recovery),
        })
    }

    pub fn unlock(&self, password: &str) -> Result<UnlockedKeys> {
        let pk = password_keys(password, &self.kdf_salt, &self.kdf)?;
        let dek = unwrap_dek(&pk.kek, &self.wrapped_dek)?;
        Ok(UnlockedKeys { dek, auth_key: pk.auth_key })
    }

    /// Re-wrap the DEK under a new password (fresh salt). Records are untouched.
    pub fn rewrap(
        &self,
        dek: &[u8; KEY_LEN],
        new_password: &str,
        kdf: KdfParams,
    ) -> Result<(VaultMeta, SecretKey)> {
        if new_password.chars().count() < 8 {
            return Err(Error::Invalid(
                "master password must be at least 8 characters".into(),
            ));
        }
        let salt = crypto::random_bytes::<SALT_LEN>().to_vec();
        let pk = password_keys(new_password, &salt, &kdf)?;
        Ok((
            VaultMeta {
                kdf_salt: salt,
                kdf,
                wrapped_dek: wrap_dek(&pk.kek, dek)?,
                wrapped_dek_recovery: self.wrapped_dek_recovery.clone(),
            },
            pk.auth_key,
        ))
    }

    /// Recover the DEK with the recovery key.
    pub fn recover(&self, recovery_key: &str) -> Result<SecretKey> {
        let rk = crypto::decode_recovery_key(recovery_key)?;
        let wrapped = self
            .wrapped_dek_recovery
            .as_ref()
            .ok_or_else(|| Error::Invalid("this vault has no recovery kit".into()))?;
        unwrap_dek_recovery(&rk, wrapped)
    }
}

/// Encrypt a secret field with the DEK, binding it to a record id (as AAD).
pub fn encrypt_field(dek: &[u8; KEY_LEN], record_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    crypto::seal(dek, plaintext, record_id.as_bytes())
}

pub fn decrypt_field(
    dek: &[u8; KEY_LEN],
    record_id: &str,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    crypto::open(dek, sealed, record_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn create_unlock_change_recover() {
        let kdf = KdfParams::insecure_for_tests();
        let nv = VaultMeta::create("correct horse", kdf).unwrap();
        assert!(matches!(nv.meta.unlock("wrong password"), Err(Error::WrongPassword)));
        let keys = nv.meta.unlock("correct horse").unwrap();
        assert_eq!(*keys.dek, *nv.keys.dek);

        let (meta2, _) = nv.meta.rewrap(&keys.dek, "new password!", kdf).unwrap();
        assert!(meta2.unlock("correct horse").is_err());
        assert_eq!(*meta2.unlock("new password!").unwrap().dek, *keys.dek);

        let recovered = meta2.recover(&nv.recovery_key).unwrap();
        assert_eq!(*recovered, *keys.dek);
    }

    #[test]
    fn short_password_rejected() {
        let kdf = KdfParams::insecure_for_tests();
        assert!(VaultMeta::create("short", kdf).is_err());
    }

    #[test]
    fn field_encryption_is_bound_to_record() {
        let dek = crypto::random_key();
        let ct = encrypt_field(&dek, "a", b"secret").unwrap();
        assert_eq!(&decrypt_field(&dek, "a", &ct).unwrap()[..], b"secret");
        assert!(decrypt_field(&dek, "b", &ct).is_err());
    }
}
