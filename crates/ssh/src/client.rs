//! SSH connection management: host-key pinning, interaction hooks, auth.

use std::collections::HashMap;
use std::sync::Arc;

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{agent::client::AgentClient, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::error::{Result, SshError};

/// A server host key, as presented during key exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKeyInfo {
    pub key_type: String,
    pub key_base64: String,
    pub fingerprint: String,
}

/// Prompts surfaced to the user during connection.
#[async_trait::async_trait]
pub trait Interaction: Send + Sync {
    async fn password(&self, prompt: &str) -> Result<String>;
    async fn kbd_prompt(&self, name: &str, instruction: &str, prompt: &str) -> Result<String>;
    async fn accept_host_key(&self, info: &HostKeyInfo, changed: bool) -> Result<bool>;
}

/// Non-interactive fallback: rejects host-key changes, no passwords.
pub struct HeadlessInteraction;

#[async_trait::async_trait]
impl Interaction for HeadlessInteraction {
    async fn password(&self, _prompt: &str) -> Result<String> {
        Err(SshError::Auth("no interactive prompt available".into()))
    }

    async fn kbd_prompt(&self, _name: &str, _instruction: &str, _prompt: &str) -> Result<String> {
        Err(SshError::Auth("no interactive prompt available".into()))
    }

    async fn accept_host_key(&self, _info: &HostKeyInfo, changed: bool) -> Result<bool> {
        // Trust on first use only; never silently accept a changed key.
        Ok(!changed)
    }
}

/// Persists known host keys.
#[async_trait::async_trait]
pub trait HostKeyStore: Send + Sync {
    async fn pinned(&self, host: &str, port: u16) -> Option<String>;
    async fn pin(&self, host: &str, port: u16, key_base64: String);
}

/// In-memory store (no persistence).
#[derive(Default)]
pub struct MemHostKeyStore {
    keys: Mutex<HashMap<(String, u16), String>>,
}

#[async_trait::async_trait]
impl HostKeyStore for MemHostKeyStore {
    async fn pinned(&self, host: &str, port: u16) -> Option<String> {
        self.keys.lock().await.get(&(host.to_string(), port)).cloned()
    }

    async fn pin(&self, host: &str, port: u16, key_base64: String) {
        self.keys.lock().await.insert((host.to_string(), port), key_base64);
    }
}

/// SHA-256 fingerprint, colon-separated lowercase hex (e.g. `e3:b0:c4:...`).
pub fn fingerprint(bytes: &[u8]) -> String {
    let sum = Sha256::digest(bytes);
    let hex: Vec<String> = sum.iter().map(|b| format!("{b:02x}")).collect();
    hex.join(":")
}

/// A live SSH session.
pub struct SshConnection {
    /// Shared so a clone can open new channels (SFTP) without holding the
    /// connection across awaits.
    pub handle: std::sync::Arc<Handle<VeraHandler>>,
}

impl SshConnection {
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    pub fn clone_handle(&self) -> std::sync::Arc<Handle<VeraHandler>> {
        self.handle.clone()
    }
}

/// How to authenticate.
pub enum AuthMethod {
    Password(String),
    PrivateKey { pem: String, passphrase: Option<String> },
    Agent,
}

#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub keepalive_secs: u64,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            keepalive_secs: 30,
        }
    }
}

impl VeraHandler {
    pub fn new(host: String, port: u16, interaction: Arc<dyn Interaction>, store: Arc<dyn HostKeyStore>) -> Self {
        Self { host, port, interaction, store }
    }
}

impl russh::client::Handler for VeraHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                check_key(&self.host, self.port, key, &*self.interaction, &*self.store).await
            }
            russh::keys::PublicKeyOrCertificate::Certificate(_) => {
                // ponytail: reject certificates — TOFU store keys on OpenSSH-form keys only.
                Err(reject("certificate host keys unsupported"))
            }
        }
    }
}

/// Client handler that performs host-key TOFU via [`HostKeyStore`] + [`Interaction`].
pub struct VeraHandler {
    host: String,
    port: u16,
    interaction: Arc<dyn Interaction>,
    store: Arc<dyn HostKeyStore>,
}

// ponytail: TOFU only — first-seen key auto-pinned, changed key requires user consent.
async fn check_key(
    host: &str,
    port: u16,
    key: &PublicKey,
    interaction: &dyn Interaction,
    store: &dyn HostKeyStore,
) -> Result<bool> {
    let key_base64 = key
        .to_openssh()
        .map_err(|e| SshError::Connect(format!("encode host key: {e}")))?;
    let key_type = key.algorithm().to_string();
    let raw = key
        .to_bytes()
        .map_err(|e| SshError::Connect(format!("encode host key: {e}")))?;
    let info = HostKeyInfo {
        key_type,
        key_base64: key_base64.clone(),
        fingerprint: fingerprint(&raw),
    };

    match store.pinned(host, port).await {
        None => {
            if interaction.accept_host_key(&info, false).await? {
                store.pin(host, port, key_base64).await;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Some(pinned) if pinned == key_base64 => Ok(true),
        Some(_) => interaction.accept_host_key(&info, true).await,
    }
}

fn reject(reason: &str) -> SshError {
    tracing::warn!("{reason}");
    SshError::HostKeyRejected
}

/// Connect and authenticate.
pub async fn connect(
    cfg: &ConnectConfig,
    auth: AuthMethod,
    interaction: Arc<dyn Interaction>,
    store: Arc<dyn HostKeyStore>,
) -> Result<SshConnection> {
    let config = russh::client::Config {
        keepalive_interval: Some(std::time::Duration::from_secs(cfg.keepalive_secs)),
        ..Default::default()
    };
    let config = Arc::new(config);
    let addr = (cfg.host.as_str(), cfg.port);
    let handler = VeraHandler::new(
        cfg.host.clone(),
        cfg.port,
        interaction.clone(),
        store.clone(),
    );

    let mut handle = russh::client::connect(config, addr, handler).await?;

    let user = cfg.username.clone();
    let ok = match auth {
        AuthMethod::Password(pw) => {
            match handle.authenticate_password(&user, pw).await? {
                AuthResult::Success => true,
                AuthResult::Failure { .. } => {
                    // One re-prompt on failure; headless interaction returns Err here.
                    let pw = interaction
                        .password("SSH password")
                        .await
                        .map_err(|_| SshError::Auth("authentication failed".into()))?;
                    matches!(
                        handle.authenticate_password(&user, pw).await?,
                        AuthResult::Success
                    )
                }
            }
        }
        AuthMethod::PrivateKey { pem, passphrase } => {
            let key = decode_private_key(&pem, passphrase)?;
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            matches!(
                handle.authenticate_publickey(&user, key).await?,
                AuthResult::Success
            )
        }
        AuthMethod::Agent => {
            // On Windows the OpenSSH agent listens on a named pipe; Pageant is the other option.
            const PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
            let mut agent = AgentClient::connect_named_pipe(PIPE)
                .await
                .map_err(|e| SshError::Auth(format!("ssh agent: {e}")))?;
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| SshError::Auth(format!("ssh agent: {e}")))?;
            let mut success = false;
            for identity in identities {
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                match handle
                    .authenticate_publickey_with(
                        &user,
                        identity.public_key().into_owned(),
                        hash,
                        &mut agent,
                    )
                    .await
                {
                    Ok(AuthResult::Success) => {
                        success = true;
                        break;
                    }
                    // Agent declined this key; try the next one.
                    Ok(AuthResult::Failure { .. }) => continue,
                    Err(e) => return Err(SshError::Auth(format!("ssh agent: {e}"))),
                }
            }
            success
        }
    };

    if !ok {
        return Err(SshError::Auth("authentication failed".into()));
    }
    Ok(SshConnection { handle: std::sync::Arc::new(handle) })
}

fn decode_private_key(pem: &str, passphrase: Option<String>) -> Result<PrivateKey> {
    let key = match passphrase {
        Some(p) => PrivateKey::from_openssh(pem)
            .and_then(|k| k.decrypt(p.as_bytes()))
            .map_err(|e| SshError::Invalid(format!("private key: {e}")))?,
        None => PrivateKey::from_openssh(pem)
            .map_err(|e| SshError::Invalid(format!("private key: {e}")))?,
    };
    Ok(key)
}

/// Drive keyboard-interactive auth to completion.
pub async fn authenticate_keyboard_interactive(
    handle: &mut Handle<VeraHandler>,
    username: &str,
    interaction: Arc<dyn Interaction>,
) -> Result<bool> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None)
        .await?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in &prompts {
                    answers.push(
                        interaction
                            .kbd_prompt(&name, &instructions, &prompt.prompt)
                            .await?,
                    );
                }
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_fingerprint_is_known_sha256() {
        assert_eq!(
            fingerprint(b""),
            "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55"
        );
    }

    #[tokio::test]
    async fn mem_store_round_trips() {
        let store = MemHostKeyStore::default();
        assert_eq!(store.pinned("h", 22).await, None);
        store.pin("h", 22, "abc".into()).await;
        assert_eq!(store.pinned("h", 22).await.as_deref(), Some("abc"));
        assert_eq!(store.pinned("other", 22).await, None);
    }

    #[test]
    fn connect_config_defaults() {
        let cfg = ConnectConfig::default();
        assert_eq!(cfg.port, 22);
        assert_eq!(cfg.keepalive_secs, 30);
    }

    #[tokio::test]
    async fn headless_rejects_changed_key_but_accepts_first_use() {
        let i = Arc::new(HeadlessInteraction);
        let info = HostKeyInfo {
            key_type: "ssh-ed25519".into(),
            key_base64: "AAA=".into(),
            fingerprint: "aa:bb".into(),
        };
        assert!(i.accept_host_key(&info, false).await.unwrap());
        assert!(!i.accept_host_key(&info, true).await.unwrap());
    }
}
