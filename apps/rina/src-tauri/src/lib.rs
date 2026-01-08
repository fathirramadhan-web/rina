//! RINA desktop (Tauri shell): IPC commands + SSH session plumbing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

use rina_core::crypto::{KdfParams, SecretKey};
use rina_core::db::Db;
use rina_core::models::{
    new_id, now_ms, AuthKind, Credential, Group, Host as CoreHost, HostOptions, KnownHost, Snippet,
};
use rina_core::vault::{self, UnlockedKeys};
use rina_ssh::client::{AuthMethod, ConnectConfig, HostKeyInfo, HostKeyStore, Interaction};
use rina_ssh::shell::{open_shell, ShellEvent, ShellHandle, ShellOptions};

mod sync;

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

/// Custom-dialog bridge replacing tauri-plugin-dialog. The backend emits a
/// `dialog-confirm` / `dialog-prompt` event carrying a unique token, then waits
/// on a oneshot channel; the frontend modal calls `dialog_resolve` with that
/// token to complete it.
///
/// ponytail: one shared waiter map keyed by token covers confirm + prompt, so
/// concurrent dialogs can't collide. Add per-dialog timeouts here if a modal can
/// ever be dismissed without answering.
#[derive(Clone, Default)]
struct DialogWaiters(Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<String>>>>);

struct DialogBridge {
    app: AppHandle,
    waiters: DialogWaiters,
}

/// Open a token→answer channel, emit the dialog event, await the answer.
/// The std-Mutex guard is dropped before awaiting (never held across `.await`).
async fn ask(
    bridge: &DialogBridge,
    event: &str,
    title: String,
    message: String,
    extra: serde_json::Value,
) -> rina_ssh::Result<String> {
    let token = new_id();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    bridge
        .waiters
        .0
        .lock()
        .map_err(|_| rina_ssh::SshError::Connect("dialog waiter lock poisoned".into()))?
        .insert(token.clone(), tx);

    let payload = serde_json::json!({
        "token": token,
        "title": title,
        "message": message,
    });
    // Merge `extra` (danger / kind) into the flat payload the frontend expects.
    let payload = match (payload, extra) {
        (serde_json::Value::Object(mut base), serde_json::Value::Object(rest)) => {
            for (k, v) in rest {
                base.insert(k, v);
            }
            serde_json::Value::Object(base)
        }
        (base, _) => base,
    };

    if bridge.app.emit(event, payload).is_err() {
        // Nobody is listening (window gone): fail the connect instead of hanging.
        bridge.waiters.0.lock().ok().map(|mut m| m.remove(&token));
        return Err(rina_ssh::SshError::Connect(format!(
            "failed to emit {event}: no dialog surface"
        )));
    }

    match rx.await {
        Ok(answer) => Ok(answer),
        Err(_) => {
            // dialog_resolve never arrived (sender dropped).
            Err(rina_ssh::SshError::Connect("dialog cancelled".into()))
        }
    }
}

#[async_trait]
impl Interaction for DialogBridge {
    async fn password(&self, prompt: &str) -> rina_ssh::Result<String> {
        let answer = ask(
            self,
            "dialog-prompt",
            "SSH authentication".into(),
            prompt.to_string(),
            serde_json::json!({ "kind": "password", "secret": true }),
        )
        .await?;
        Ok(answer)
    }

    async fn kbd_prompt(&self, _name: &str, _instruction: &str, prompt: &str) -> rina_ssh::Result<String> {
        ask(
            self,
            "dialog-prompt",
            "SSH authentication".into(),
            prompt.to_string(),
            serde_json::json!({ "kind": "otp", "secret": true }),
        )
        .await
    }

    async fn accept_host_key(&self, info: &HostKeyInfo, changed: bool) -> rina_ssh::Result<bool> {
        // First use: trust is the affirmative ask (danger=false). Changed key:
        // danger=true, and acceptance still requires an explicit OK, so reject
        // stays the safe default against a silent MITM.
        let (title, message, danger) = if changed {
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
                true,
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
                false,
            )
        };

        let answer = ask(
            self,
            "dialog-confirm",
            title.into(),
            message,
            serde_json::json!({ "danger": danger }),
        )
        .await?;
        Ok(answer == "yes")
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

/// Registry of running local port-forwards, keyed by (session_id, listen_port).
/// `forward_stop` aborts the accept-loop task and the registry drops the entry,
/// closing the listener socket.
type ForwardMap = Arc<Mutex<HashMap<(String, u16), tokio::task::JoinHandle<()>>>>;

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

    let interaction: Arc<dyn Interaction> = Arc::new(DialogBridge {
        app: app.clone(),
        waiters: app.state::<DialogWaiters>().inner().clone(),
    });
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

#[derive(Serialize)]
struct SnippetJson {
    id: String,
    name: String,
    body: String,
    placeholders: Vec<String>,
}

#[tauri::command]
async fn snippet_list(db: State<'_, DbHandle>) -> Result<Vec<SnippetJson>, String> {
    Ok(db
        .with(|d| d.list_snippets())?
        .into_iter()
        .map(|s| SnippetJson {
            id: s.id,
            name: s.name,
            body: s.body,
            placeholders: s.placeholders,
        })
        .collect())
}

/// Scan `{{ name }}` tokens in first-seen order, deduped.
fn scan_placeholders(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let name = after[..end].trim();
        if !name.is_empty() && !out.iter().any(|p| p == name) {
            out.push(name.to_string());
        }
        rest = &after[end + 2..];
    }
    out
}

/// Replace `{{ name }}` tokens that have a supplied value; unknown tokens stay
/// verbatim so the user can see what was left unfilled.
fn substitute_placeholders(body: &str, values: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let raw = &after[..end];
        match values.get(raw.trim()) {
            Some(v) => out.push_str(v),
            None => {
                out.push_str("{{");
                out.push_str(raw);
                out.push_str("}}");
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

#[tauri::command]
async fn snippet_placeholders(db: State<'_, DbHandle>, snippet_id: String) -> Result<Vec<String>, String> {
    let snippet = db
        .with(|d| d.list_snippets())?
        .into_iter()
        .find(|s| s.id == snippet_id)
        .ok_or_else(|| format!("no snippet {snippet_id}"))?;
    Ok(scan_placeholders(&snippet.body))
}

#[tauri::command]
async fn snippet_run(
    app: AppHandle,
    db: State<'_, DbHandle>,
    session_id: String,
    snippet_id: String,
    values: HashMap<String, String>,
) -> Result<String, String> {
    let snippet = db
        .with(|d| d.list_snippets())?
        .into_iter()
        .find(|s| s.id == snippet_id)
        .ok_or_else(|| format!("no snippet {snippet_id}"))?;
    let command = substitute_placeholders(&snippet.body, &values);

    let sessions = app.state::<SessionMap>();
    let map = sessions.lock().map_err(|_| "session lock")?;
    let s = map.get(&session_id).ok_or_else(|| format!("no session {session_id}"))?;
    if !s.shell.write(command.as_bytes()) {
        return Err("session shell closed".to_string());
    }
    Ok(command)
}

// ---- ssh_config import ----

#[tauri::command]
async fn ssh_config_import(
    app: AppHandle,
    db: State<'_, DbHandle>,
    path: String,
) -> Result<Vec<HostJson>, String> {
    let home = app.path().home_dir().ok();
    let expanded = match path.strip_prefix("~/") {
        Some(rest) => {
            let base = home
                .as_ref()
                .ok_or_else(|| "cannot resolve ~: home directory unavailable".to_string())?;
            base.join(rest)
        }
        None => std::path::PathBuf::from(&path),
    };
    let content = tokio::fs::read_to_string(&expanded)
        .await
        .map_err(|e| format!("read ssh config {}: {e}", expanded.display()))?;
    let parsed = rina_core::sshconfig::parse(&content, home.as_deref());
    let hosts = rina_core::sshconfig::into_hosts(&parsed);
    for h in &hosts {
        db.with(|d| d.upsert_host(h))?;
    }
    Ok(hosts.iter().map(HostJson::from).collect())
}

#[tauri::command]
async fn dialog_resolve(app: AppHandle, token: String, value: String) -> Result<(), String> {
    let waiters = app.state::<DialogWaiters>();
    let mut map = waiters.0.lock().map_err(|_| "dialog waiter lock poisoned".to_string())?;
    if let Some(tx) = map.remove(&token) {
        let _ = tx.send(value);
    }
    Ok(())
}

// ---- local port forwarding ----

#[tauri::command]
async fn forward_local(
    app: AppHandle,
    session_id: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
) -> Result<(), String> {
    let sessions = app.state::<SessionMap>();
    let handle = {
        let map = sessions.lock().map_err(|_| "session lock".to_string())?;
        map.get(&session_id)
            .ok_or_else(|| format!("no session {session_id}"))?
            ._conn
            .clone_handle()
    };

    // Bind before registering: a bind failure returns a clear error and leaves
    // no stale registry entry.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", listen_port))
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{listen_port}: {e}"))?;

    let forwards = app.state::<ForwardMap>().inner().clone();
    let key = (session_id, listen_port);
    let task = tokio::spawn(async move {
        loop {
            let (mut tcp, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("forward accept on {listen_port}: {e}");
                    break;
                }
            };
            let h = handle.clone();
            let host = target_host.clone();
            let port = target_port;
            tokio::spawn(async move {
                match h
                    .channel_open_direct_tcpip(host.clone(), port as u32, "127.0.0.1", 0)
                    .await
                {
                    Ok(channel) => {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                    }
                    Err(e) => tracing::warn!("direct-tcpip {host}:{port}: {e}"),
                }
            });
        }
    });

    let mut map = forwards.lock().map_err(|_| "forward lock poisoned".to_string())?;
    if let Some(old) = map.insert(key, task) {
        old.abort();
    }
    Ok(())
}

#[tauri::command]
async fn forward_stop(app: AppHandle, session_id: String, listen_port: u16) -> Result<(), String> {
    let forwards = app.state::<ForwardMap>();
    let mut map = forwards.lock().map_err(|_| "forward lock poisoned".to_string())?;
    if let Some(task) = map.remove(&(session_id, listen_port)) {
        task.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_scan_and_substitute() {
        let body = "echo {{host}} {{ user }} {{host}} {{}} {{unclosed";
        let found = scan_placeholders(body);
        assert_eq!(found, vec!["host", "user"]);
        let values = HashMap::from([("host".to_string(), "box".to_string())]);
        assert_eq!(
            substitute_placeholders(body, &values),
            "echo box {{ user }} box {{}} {{unclosed"
        );
    }
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
async fn sftp_delete_dir(app: AppHandle, session_id: String, path: String) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    sftp_map(s.remove_dir(&path).await)
}

#[tauri::command]
async fn sftp_upload(app: AppHandle, session_id: String, remote_path: String, data: Vec<u8>) -> Result<(), String> {
    let s = open_sftp(&app, &session_id).await?;
    s.write_file(&remote_path, &data).await.map_err(|e| e.to_string())
}

pub fn run() {
    tracing_subscriber::fmt().try_init().ok();
    tauri::Builder::default()
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
            app.manage(ForwardMap::default());
            app.manage(DialogWaiters::default());
            app.manage(sync::SyncHandle::default());
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
            snippet_list,
            snippet_placeholders,
            snippet_run,
            credential_save,
            ssh_config_import,
            dialog_resolve,
            forward_local,
            forward_stop,
            sftp_list,
            sftp_mkdir,
            sftp_delete,
            sftp_delete_dir,
            sftp_rename,
            sftp_chmod,
            sftp_download,
            sftp_upload,
            sync::sync_register,
            sync::sync_login,
            sync::sync_now,
            sync::sync_status,
            sync::sync_logout,
            sync::sync_devices,
            sync::sync_revoke_device,
            sync::sync_set_url,
        ])
        .run(tauri::generate_context!())
        .expect("tauri run");
}
