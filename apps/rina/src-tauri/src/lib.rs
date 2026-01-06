//! RINA desktop (Tauri shell): IPC commands + SSH session plumbing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use rina_core::db::Db;
use rina_core::models::{AuthKind, Host as CoreHost, KnownHost, now_ms, new_id};
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

// ponytail: env-var credentials + TOFU host keys — no real dialogs yet.
// Replace with tauri-plugin-dialog password/confirm prompts and vault-unlock
// state, and resolve auth from the decrypted credential instead of env vars.
struct RinaInteraction;

#[async_trait]
impl Interaction for RinaInteraction {
    async fn password(&self, _prompt: &str) -> rina_ssh::Result<String> {
        std::env::var("RINA_PASSWORD")
            .map_err(|_| rina_ssh::SshError::Auth("no RINA_PASSWORD set".into()))
    }

    async fn kbd_prompt(&self, _name: &str, _instruction: &str, _prompt: &str) -> rina_ssh::Result<String> {
        std::env::var("RINA_PASSWORD")
            .map_err(|_| rina_ssh::SshError::Auth("no RINA_PASSWORD set".into()))
    }

    async fn accept_host_key(&self, _info: &HostKeyInfo, changed: bool) -> rina_ssh::Result<bool> {
        // Trust on first use; never silently accept a changed key.
        Ok(!changed)
    }
}

/// Resolve how to authenticate to `host`: stored credential when usable,
/// otherwise env fallback.
fn resolve_auth(db: &Db, host: &CoreHost) -> Result<AuthMethod, String> {
    if let Some(cid) = &host.credential_id {
        if let Ok(c) = db.get_credential(cid) {
            let secret = String::from_utf8_lossy(&c.secret_enc).into_owned();
            return Ok(match c.kind {
                AuthKind::Password => AuthMethod::Password(secret),
                AuthKind::PrivateKey => AuthMethod::PrivateKey { pem: secret, passphrase: None },
                AuthKind::Agent => AuthMethod::Agent,
            });
        }
    }
    // ponytail: env fallback until vault unlock + secret decryption is wired.
    if let Ok(pem) = std::env::var("RINA_KEY_PEM") {
        return Ok(AuthMethod::PrivateKey {
            pem,
            passphrase: std::env::var("RINA_KEY_PASSPHRASE").ok(),
        });
    }
    if let Ok(pw) = std::env::var("RINA_PASSWORD") {
        return Ok(AuthMethod::Password(pw));
    }
    Ok(AuthMethod::Agent)
}

/// A live shell session. `conn` keeps the SSH connection alive.
struct Session {
    _conn: rina_ssh::SshConnection,
    shell: ShellHandle,
}

type SessionMap = Mutex<HashMap<String, Session>>;

#[tauri::command]
async fn list_hosts(db: State<'_, DbHandle>) -> Result<Vec<HostJson>, String> {
    Ok(db.with(|d| d.list_hosts())?.iter().map(HostJson::from).collect())
}

#[tauri::command]
async fn connect_host(
    app: AppHandle,
    db: State<'_, DbHandle>,
    store: State<'_, Arc<dyn HostKeyStore>>,
    host_id: String,
) -> Result<String, String> {
    let host = db.with(|d| d.get_host(&host_id))?;
    let auth = {
        let guard = db.0.lock().map_err(|_| "db lock".to_string())?;
        resolve_auth(&guard, &host)?
    };
    let cfg = ConnectConfig {
        host: host.hostname.clone(),
        port: host.port,
        username: host.username.clone(),
        keepalive_secs: host.options.keepalive_seconds.max(1) as u64,
    };

    let interaction: Arc<dyn Interaction> = Arc::new(RinaInteraction);
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
        ])
        .run(tauri::generate_context!())
        .expect("tauri run");
}
