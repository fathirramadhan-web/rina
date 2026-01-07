//! RINA desktop (Tauri shell): IPC commands + SSH session plumbing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use rina_core::crypto::{KdfParams, SecretKey};
use rina_core::db::Db;
use rina_core::models::{
    new_id, now_ms, AuthKind, Credential, Group, Host as CoreHost, HostOptions, KnownHost, Snippet,
};
use rina_core::vault::{self, UnlockedKeys};
use rina_ssh::client::{AuthMethod, ConnectConfig, HostKeyInfo, HostKeyStore, Interaction};
use rina_ssh::shell::{open_shell, ShellEvent, ShellHandle, ShellOptions};

/// Minimal host JSON the frontend expects (see src/store.ts). Exactly 7 keys,
/// `group_id` spelled with an underscore.
#[derive(Serialize)]
struct HostJson {
    id: String,
    label: String,
    hostname: String,
    port: u16,
    username: String,
    group_id: Option<String>,
    tags: Vec<String>,
}

impl From<&CoreHost> for HostJson {
    fn from(h: &CoreHost) -> Self {
        Self {
            id: h.id.clone(),
            label: h.label.clone(),
            hostname: h.hostname.clone(),
            port: h.port,
            username: h.username.clone(),
            group_id: h.group_id.clone(),
            tags: h.tags.clone(),
        }
    }
}

/// Db is not Sync; serialize access so it can live in Tauri state.
#[derive(Clone)]
struct DbHandle(Arc<Mutex<Db>>);

impl DbHandle {
    fn with<T>(&self, f: impl FnOnce(&Db) -> rina_core::Result<T>) -> Result<T, String> {
        let db = self.0.lock().map_err(|_| "database lock poisoned".to_string())?;
        f(&db).map_err(|e| e.to_string())
    }
}

/// Unlocked vault keys (DEK + sync auth key). Empty while locked.
#[derive(Clone, Default)]
struct VaultHandle(Arc<Mutex<Option<UnlockedKeys>>>);

impl VaultHandle {
    fn require_dek(&self) -> Result<SecretKey, String> {
        let guard = self.0.lock().map_err(|_| "vault lock poisoned".to_string())?;
        guard
            .as_ref()
            .map(|k| k.dek.clone())
            .ok_or_else(|| "vault locked: unlock the vault first".to_string())
    }
}

/// Host-key TOFU store backed by the SQLite `known_hosts` table.
/// The trait speaks OpenSSH public-key lines ("<type> <base64>"); the table
/// stores the decoded key bytes.
struct SqliteHostKeyStore(DbHandle);

#[async_trait]
impl HostKeyStore for SqliteHostKeyStore {
    async fn pinned(&self, host: &str, port: u16) -> Option<String> {
        let db = self.0.clone();
        let host = host.to_string();
        tokio::task::spawn_blocking(move || {
            let kh: KnownHost = db
                .with(|d| Ok(d.get_known_host(&host, port).ok().flatten()))
                .ok()??;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&kh.key_blob);
            Some(format!("{} {}", kh.key_type, b64))
        })
        .await
        .ok()
        .flatten()
    }

    async fn pin(&self, host: &str, port: u16, key_base64: String) {
        let db = self.0.clone();
        let host = host.to_string();
        // key_base64 may be "ssh-ed25519 AAAA..." or a bare base64 blob.
        let (key_type, b64) = match key_base64.split_once(' ') {
            Some((kt, rest)) => (kt.to_string(), rest.to_string()),
            None => ("ssh-ed25519".into(), key_base64),
        };
        let blob = match base64::engine::general_purpose::STANDARD.decode(&b64) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("pin: decode host key: {e}");
                return;
            }
        };
        let _ = tokio::task::spawn_blocking(move || {
            db.with(|d| {
                d.upsert_known_host(&KnownHost {
                    id: Db::known_host_id(&host, port),
                    host,
                    port,
                    key_type,
                    key_blob: blob,
                    updated_at: now_ms(),
                    deleted: false,
                })
            })
        })
        .await;
    }
}

/// SSH prompts surfaced as native dialogs.
///
/// ponytail: tauri-plugin-dialog 2.x has only file + yes/no message dialogs —
/// no text-input prompt. `password`/`kbd_prompt` therefore fail with a clear
/// error; store a credential in the vault instead of prompting. Upgrade path:
/// swap in a text-input capable dialog (or a frontend prompt over IPC).
struct RinaInteraction {
    app: AppHandle,
}

const NO_TEXT_PROMPT: &str = "no interactive text prompt available: store a password \
     or key credential in the vault and unlock it before connecting";

#[async_trait]
impl Interaction for RinaInteraction {
    async fn password(&self, _prompt: &str) -> rina_ssh::Result<String> {
        Err(rina_ssh::SshError::Auth(NO_TEXT_PROMPT.into()))
    }

    async fn kbd_prompt(&self, _name: &str, _instruction: &str, _prompt: &str) -> rina_ssh::Result<String> {
        Err(rina_ssh::SshError::Auth(NO_TEXT_PROMPT.into()))
    }

    async fn accept_host_key(&self, info: &HostKeyInfo, changed: bool) -> rina_ssh::Result<bool> {
        // First use: trust is the affirmative default. Changed key: reject is
        // the affirmative default; silent accept would hide a MITM.
        let (title, message, kind, ok_label, cancel_label) = if changed {
            (
                "Host key CHANGED",
                format!(
                    "The SSH host key for this server has CHANGED since your last connection.\n\n\
                     Fingerprint (SHA-256):\n{}\nKey type: {}\n\n\
                     This can indicate a man-in-the-middle attack. Reject unless you know the \
                     server was reinstalled or its keys were regenerated.",
                    info.fingerprint,
                    info.key_type
                ),
                MessageDialogKind::Warning,
                "Reject (safe)",
                "Accept anyway",
            )
        } else {
            (
                "Trust this host?",
                format!(
                    "This is the first time you connect to this server.\n\n\
                     Fingerprint (SHA-256):\n{}\nKey type: {}\n\n\
                     Trust and remember this key?",
                    info.fingerprint,
                    info.key_type
                ),
                MessageDialogKind::Info,
                "Trust and remember",
                "Reject",
            )
        };

        let builder = self
            .app
            .dialog()
            .message(message)
            .title(title)
            .kind(kind)
            .buttons(MessageDialogButtons::OkCancelCustom(
                ok_label.to_string(),
                cancel_label.to_string(),
            ));

        // blocking_show must not run on the main thread; commands run on the
        // async runtime, so park it on a blocking thread.
        let ok_pressed = tokio::task::spawn_blocking(move || builder.blocking_show())
            .await
            .map_err(|e| rina_ssh::SshError::Connect(format!("host key dialog: {e}")))?;

        // OK button = Reject on a changed key, Trust on first use.
        Ok(if changed { !ok_pressed } else { ok_pressed })
    }
}

/// Resolve authentication: decrypt the stored credential with the DEK, or fall
/// back to the SSH agent only when no credential is set on the host.
fn resolve_auth(db: &Db, vault: &VaultHandle, host: &CoreHost) -> Result<AuthMethod, String> {
    if let Some(cid) = &host.credential_id {
        let dek = vault.require_dek()?;
        let c: Credential = db.get_credential(cid).map_err(|e| e.to_string())?;
        let secret = vault::decrypt_field(&dek, cid, &c.secret_enc)
            .map_err(|e| format!("decrypt credential: {e}"))?;
        let secret = String::from_utf8_lossy(&secret).into_owned();
        return Ok(match c.kind {
            AuthKind::Password => AuthMethod::Password(secret),
            AuthKind::PrivateKey => {
                let passphrase = match &c.passphrase_enc {
                    Some(pp) => {
                        let dec = vault::decrypt_field(&dek, cid, pp)
                            .map_err(|e| format!("decrypt passphrase: {e}"))?;
                        Some(String::from_utf8_lossy(&dec).into_owned())
                    }
                    None => None,
                };
                AuthMethod::PrivateKey { pem: secret, passphrase }
            }
            AuthKind::Agent => AuthMethod::Agent,
        });
    }
    // No credential pinned: use the local SSH agent.
    Ok(AuthMethod::Agent)
}

/// A live shell session. `conn` keeps the SSH connection alive.
struct Session {
    _conn: rina_ssh::SshConnection,
    shell: ShellHandle,
}

type SessionMap = Mutex<HashMap<String, Session>>;

// ---- vault commands ----

#[tauri::command]
async fn vault_exists(db: State<'_, DbHandle>) -> Result<bool, String> {
    db.with(|d| d.has_vault())
}

#[tauri::command]
async fn vault_unlock(
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    password: String,
) -> Result<bool, String> {
    let meta = db
        .with(|d| d.get_vault_meta())?
        .ok_or_else(|| "no vault exists yet".to_string())?;
    match meta.unlock(&password) {
        Ok(keys) => {
            *vault.0.lock().map_err(|_| "vault lock poisoned".to_string())? = Some(keys);
            Ok(true)
        }
        Err(rina_core::Error::WrongPassword) => Ok(false), // wrong password → false; caller keeps the modal open
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn vault_create(
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    password: String,
) -> Result<String, String> {
    if db.with(|d| d.has_vault())? {
        return Err("a vault already exists".to_string());
    }
    // Real Argon2id cost parameters: this is the master password, so pay it.
    let nv = vault::VaultMeta::create(&password, KdfParams::default()).map_err(|e| e.to_string())?;
    db.with(|d| d.set_vault_meta(&nv.meta))?;
    *vault.0.lock().map_err(|_| "vault lock poisoned".to_string())? = Some(nv.keys);
    Ok(nv.recovery_key)
}

#[tauri::command]
async fn vault_lock(vault: State<'_, VaultHandle>) -> Result<(), String> {
    // Drops the DEK and auth key; SecretKey zeroizes on drop.
    *vault.0.lock().map_err(|_| "vault lock poisoned".to_string())? = None;
    Ok(())
}

// ---- host / group / snippet / credential CRUD ----

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct HostInput {
    id: Option<String>,
    #[serde(alias = "group_id")]
    group_id: Option<String>,
    label: String,
    hostname: String,
    port: u16,
    username: String,
    #[serde(alias = "credential_id")]
    credential_id: Option<String>,
    #[serde(alias = "jump_host_id")]
    jump_host_id: Option<String>,
    tags: Vec<String>,
    #[serde(alias = "initial_command")]
    initial_command: Option<String>,
    #[serde(alias = "keepalive_seconds")]
    keepalive_seconds: u32,
    #[serde(alias = "auto_reconnect")]
    auto_reconnect: bool,
    // Inline credential material: when `secret` is non-empty, host_save creates
    // a credential first and pins it to the host. Otherwise credential_id wins.
    auth_kind: Option<AuthKind>,
    secret: Option<String>,
    passphrase: Option<String>,
}

#[tauri::command]
async fn host_save(
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    input: HostInput,
) -> Result<HostJson, String> {
    let id = match input.id.as_deref() {
        Some(existing) if !existing.is_empty() => existing.to_string(),
        _ => new_id(),
    };
    let mut credential_id = input.credential_id;
    if let Some(secret) = input.secret.as_deref().filter(|s| !s.is_empty()) {
        let dek = vault.require_dek()?;
        let cid = new_id();
        let kind = input.auth_kind.unwrap_or(AuthKind::Password);
        let secret_enc =
            vault::encrypt_field(&dek, &cid, secret.as_bytes()).map_err(|e| e.to_string())?;
        let passphrase_enc = match input.passphrase.as_deref() {
            Some(p) if !p.is_empty() => Some(
                vault::encrypt_field(&dek, &cid, p.as_bytes()).map_err(|e| e.to_string())?,
            ),
            _ => None,
        };
        let c = Credential {
            id: cid.clone(),
            label: input.label.clone(),
            kind,
            secret_enc,
            passphrase_enc,
            public_key: None,
            updated_at: now_ms(),
            deleted: false,
        };
        db.with(|d| d.upsert_credential(&c))?;
        credential_id = Some(cid);
    }
    let host = CoreHost {
        id: id.clone(),
        group_id: input.group_id,
        label: input.label,
        hostname: input.hostname,
        port: input.port,
        username: input.username,
        credential_id,
        jump_host_id: input.jump_host_id,
        tags: input.tags,
        options: HostOptions {
            initial_command: input.initial_command,
            keepalive_seconds: input.keepalive_seconds,
            auto_reconnect: input.auto_reconnect,
        },
        updated_at: now_ms(),
        deleted: false,
    };
    db.with(|d| d.upsert_host(&host))?;
    Ok(HostJson::from(&host))
}

#[tauri::command]
async fn host_delete(db: State<'_, DbHandle>, id: String) -> Result<(), String> {
    db.with(|d| d.delete_host(&id))
}

#[tauri::command]
async fn group_save(
    db: State<'_, DbHandle>,
    name: String,
    parent_id: Option<String>,
) -> Result<String, String> {
    let g = Group {
        id: new_id(),
        name,
        parent_id,
        icon: None,
        color: None,
        updated_at: now_ms(),
        deleted: false,
    };
    db.with(|d| d.upsert_group(&g))?;
    Ok(g.id)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct SnippetInput {
    id: Option<String>,
    name: String,
    body: String,
    placeholders: Vec<String>,
}

#[tauri::command]
async fn snippet_save(db: State<'_, DbHandle>, input: SnippetInput) -> Result<String, String> {
    let id = match input.id.as_deref() {
        Some(existing) if !existing.is_empty() => existing.to_string(),
        _ => new_id(),
    };
    let s = Snippet {
        id: id.clone(),
        name: input.name,
        body: input.body,
        placeholders: input.placeholders,
        updated_at: now_ms(),
        deleted: false,
    };
    db.with(|d| d.upsert_snippet(&s))?;
    Ok(id)
}

#[tauri::command]
async fn snippet_delete(db: State<'_, DbHandle>, id: String) -> Result<(), String> {
    let tombstone = Snippet {
        id: id.clone(),
        name: String::new(),
        body: String::new(),
        placeholders: Vec::new(),
        updated_at: now_ms(),
        deleted: true,
    };
    db.with(|d| d.upsert_snippet(&tombstone))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialInput {
    id: Option<String>,
    label: String,
    kind: AuthKind,
    secret: String,
    passphrase: Option<String>,
    #[serde(alias = "public_key")]
    public_key: Option<String>,
}

#[tauri::command]
async fn credential_save(
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    input: CredentialInput,
) -> Result<String, String> {
    let dek = vault.require_dek()?;
    let id = match input.id.as_deref() {
        Some(existing) if !existing.is_empty() => existing.to_string(),
        _ => new_id(),
    };
    // Encrypt with the DEK before it touches disk, binding to the id as AAD.
    let secret_enc =
        vault::encrypt_field(&dek, &id, input.secret.as_bytes()).map_err(|e| e.to_string())?;
    let passphrase_enc = match input.passphrase.as_deref() {
        Some(p) if !p.is_empty() => {
            Some(vault::encrypt_field(&dek, &id, p.as_bytes()).map_err(|e| e.to_string())?)
        }
        _ => None,
    };
    let c = Credential {
        id: id.clone(),
        label: input.label,
        kind: input.kind,
        secret_enc,
        passphrase_enc,
        public_key: input.public_key,
        updated_at: now_ms(),
        deleted: false,
    };
    db.with(|d| d.upsert_credential(&c))?;
    Ok(id)
}

// ---- sessions ----

#[tauri::command]
async fn list_hosts(db: State<'_, DbHandle>) -> Result<Vec<HostJson>, String> {
    Ok(db.with(|d| d.list_hosts())?.iter().map(HostJson::from).collect())
}

#[tauri::command]
async fn connect_host(
    app: AppHandle,
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    store: State<'_, Arc<dyn HostKeyStore>>,
    host_id: String,
) -> Result<String, String> {
    let host = db.with(|d| d.get_host(&host_id))?;
    let auth = {
        let guard = db.0.lock().map_err(|_| "db lock".to_string())?;
        resolve_auth(&guard, &vault, &host)?
    };
    let cfg = ConnectConfig {
        host: host.hostname.clone(),
        port: host.port,
        username: host.username.clone(),
        keepalive_secs: host.options.keepalive_seconds.max(1) as u64,
    };

    let interaction: Arc<dyn Interaction> = Arc::new(RinaInteraction { app: app.clone() });
    let conn = rina_ssh::client::connect(&cfg, auth, interaction, store.inner().clone())
        .await
        .map_err(|e| e.to_string())?;

    let sid = new_id();
    let sid_out = sid.clone();
    let app_out = app.clone();
    let app_closed = app.clone();
    let shell = open_shell(&conn, ShellOptions::default(), move |ev: ShellEvent| {
        match ev {
            ShellEvent::Data(data) => {
                let _ = app_out.emit("session-output", serde_json::json!({
                    "sessionId": sid_out, "data": data
                }));
            }
            ShellEvent::Closed { exit_status } => {
                let _ = app_closed.emit("session-closed", serde_json::json!({
                    "sessionId": sid_out, "status": exit_status
                }));
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    let sessions = app.state::<SessionMap>();
    sessions.lock().map_err(|_| "session lock")?.insert(sid.clone(), Session { _conn: conn, shell });
    Ok(sid)
}

#[tauri::command]
async fn disconnect(app: AppHandle, session_id: String) -> Result<(), String> {
    let sessions = app.state::<SessionMap>();
    let mut map = sessions.lock().map_err(|_| "session lock")?;
    if let Some(s) = map.remove(&session_id) {
        s.shell.close();
        drop(s);
    }
    Ok(())
}

#[tauri::command]
async fn session_write(app: AppHandle, session_id: String, data: String) -> Result<(), String> {
    let sessions = app.state::<SessionMap>();
    let map = sessions.lock().map_err(|_| "session lock")?;
    let s = map.get(&session_id).ok_or_else(|| format!("no session {session_id}"))?;
    s.shell.write(data.as_bytes());
    Ok(())
}

#[tauri::command]
async fn session_resize(app: AppHandle, session_id: String, cols: u32, rows: u32) -> Result<(), String> {
    let sessions = app.state::<SessionMap>();
    let map = sessions.lock().map_err(|_| "session lock")?;
    let s = map.get(&session_id).ok_or_else(|| format!("no session {session_id}"))?;
    s.shell.resize(cols, rows);
    Ok(())
}

#[tauri::command]
async fn export_backup(db: State<'_, DbHandle>) -> Result<String, String> {
    db.with(|d| d.export_json())
}

// ---- SFTP commands ----
//
// ponytail: each call opens a fresh SFTP subsystem channel (cheap on most
// servers) instead of caching one per session. Add a per-session SftpClient
// held behind its own mutex when transfer throughput matters.

async fn open_sftp(app: &AppHandle, session_id: &str) -> Result<rina_ssh::sftp::SftpClient, String> {
    let sessions = app.state::<SessionMap>();
    let conn = {
        let map = sessions.lock().map_err(|_| "session lock".to_string())?;
        map.get(session_id)
            .ok_or_else(|| format!("no session {session_id}"))?
            ._conn
            .handle
            .clone()
    };
    rina_ssh::sftp::SftpClient::open(&conn)
        .await
        .map_err(|e| e.to_string())
}

fn sftp_map(r: rina_ssh::Result<()>) -> Result<(), String> {
    r.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_list(app: AppHandle, session_id: String, path: String) -> Result<Vec<rina_ssh::sftp::DirEntry>, String> {
    let s = open_sftp(&app, &session_id).await?;
    s.read_dir(&path).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_mkdir(app: AppHandle, session_id: String, path: String) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    sftp_map(s.create_dir(&path).await)
}

#[tauri::command]
async fn sftp_delete(app: AppHandle, session_id: String, path: String) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    sftp_map(s.remove_file(&path).await)
}

#[tauri::command]
async fn sftp_rename(app: AppHandle, session_id: String, from: String, to: String) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    sftp_map(s.rename(&from, &to).await)
}

#[tauri::command]
async fn sftp_chmod(app: AppHandle, session_id: String, path: String, mode: String) -> Result<(), String> {
    // mode arrives as an octal string like "0644"
    let digits = mode.trim().trim_start_matches("0o").trim_start_matches('0');
    let mode_num = u32::from_str_radix(if digits.is_empty() { "0" } else { digits }, 8)
        .map_err(|_| format!("invalid mode {mode}"))?;
    let s = open_sftp(&app, &session_id).await?;
    sftp_map(s.set_permissions(&path, mode_num).await)
}

#[tauri::command]
async fn sftp_download(app: AppHandle, session_id: String, remote_path: String) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    let name = remote_path.rsplit('/').next().unwrap_or("download").to_string();
    let dir = app.path().download_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let dest = dir.join(name);
    let data = s.read_file(&remote_path).await.map_err(|e| e.to_string())?;
    tokio::fs::write(&dest, data).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_upload(app: AppHandle, session_id: String, remote_path: String, data: Vec<u8>) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    s.write_file(&remote_path, &data).await.map_err(|e| e.to_string())
}

pub fn run() {
    tracing_subscriber::fmt().try_init().ok();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db = Db::open(dir.join("rina.db"))?;
            let db_handle = DbHandle(Arc::new(Mutex::new(db)));
            let store: Arc<dyn HostKeyStore> = Arc::new(SqliteHostKeyStore(DbHandle(db_handle.0.clone())));
            app.manage(db_handle);
            app.manage(store);
            app.manage(VaultHandle::default());
            app.manage(SessionMap::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_hosts,
            connect_host,
            disconnect,
            session_write,
            session_resize,
            export_backup,
            vault_exists,
            vault_unlock,
            vault_create,
            vault_lock,
            host_save,
            host_delete,
            group_save,
            snippet_save,
            snippet_delete,
            credential_save,
            sftp_list,
            sftp_mkdir,
            sftp_delete,
            sftp_rename,
            sftp_chmod,
            sftp_download,
            sftp_upload,
        ])
        .run(tauri::generate_context!())
        .expect("tauri run");
}
