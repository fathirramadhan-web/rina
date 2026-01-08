//! E2E-encrypted sync client: talks to the optional self-hosted sync server.
//!
//! Security invariant: every record blob is sealed with the local DEK before it
//! leaves the device, so the server only ever stores ciphertext. The DEK, the
//! master key, the master password and the plaintext are never transmitted. The
//! master password never leaves the device either — only an HKDF-derived
//! `auth_hash` proof is sent, and the server stores only its Argon2id PHC hash.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager, State};

use rina_core::crypto::{self, KdfParams, SecretKey, SALT_LEN};
use rina_core::db::Db;
use rina_core::models::{now_ms, Group, Host as CoreHost, KnownHost, Snippet};
use rina_core::vault::{self, password_keys};
use rina_sync::envelope::RecordCrypto;
use rina_sync::protocol::{self, PushItem};

use crate::{DbHandle, VaultHandle};

const DEFAULT_SYNC_URL: &str = "http://127.0.0.1:8080";
const META_SYNC_URL: &str = "sync_url";
const META_CURSOR: &str = "sync_cursor";
const META_LAST_SYNC: &str = "sync_last_sync";
/// `{kind}:{id}` -> local `updated_at` at last successful push. Lets us push
/// only rows that changed since the previous sync.
const META_PUSHED: &str = "sync_pushed_at";

const KINDS: &[&str] = &["host", "group", "snippet", "known_host"];

/// Tokens for the current device, held in memory only (never on disk).
struct Session {
    email: String,
    access_token: String,
    refresh_token: String,
    device_id: String,
}

/// Managed sync state. `client` is cheap to clone (Arc inside reqwest).
#[derive(Default)]
pub struct SyncHandle {
    session: Mutex<Option<Session>>,
    client: reqwest::Client,
}

#[derive(Clone, Serialize)]
pub struct SyncStatus {
    connected: bool,
    email: Option<String>,
    cursor: u64,
    last_sync: Option<i64>,
}

#[derive(Clone, Serialize)]
pub struct DeviceInfo {
    id: String,
    label: String,
    created_at: i64,
    revoked: bool,
}

#[derive(Clone, Serialize)]
pub struct SyncResult {
    pushed: u64,
    pulled: u64,
    cursor: u64,
}

#[derive(Deserialize)]
struct DeviceRow {
    id: String,
    created_at: i64,
    revoked: bool,
}

#[derive(Deserialize)]
struct AppliedItem {
    seq: i64,
}

/// Ensure the sync state is managed. Idempotent; keeps lib.rs setup untouched.
fn sync_state(app: &AppHandle) -> State<'_, SyncHandle> {
    app.manage(SyncHandle::default());
    app.state::<SyncHandle>()
}

fn base_url(db: &DbHandle) -> Result<String, String> {
    if let Some(url) = db.with(|d| d.get_meta(META_SYNC_URL))? {
        return Ok(url.trim_end_matches('/').to_string());
    }
    Ok(std::env::var("RINA_SYNC_URL")
        .unwrap_or_else(|_| DEFAULT_SYNC_URL.to_string())
        .trim_end_matches('/')
        .to_string())
}

fn set_session(app: &AppHandle, session: Option<Session>) -> Result<(), String> {
    let handle = sync_state(app);
    let mut guard = handle.session.lock().map_err(|_| "sync lock poisoned".to_string())?;
    *guard = session;
    Ok(())
}

fn get_tokens(app: &AppHandle) -> Result<Option<(String, String, String)>, String> {
    let handle = sync_state(app);
    let guard = handle.session.lock().map_err(|_| "sync lock poisoned".to_string())?;
    Ok(guard
        .as_ref()
        .map(|s| (s.access_token.clone(), s.refresh_token.clone(), s.device_id.clone())))
}

fn require_session(app: &AppHandle) -> Result<(String, String, String), String> {
    get_tokens(app)?.ok_or_else(|| "not signed in: connect a sync account first".to_string())
}

/// One round trip. On HTTP 401 refreshes the access token once and retries.
async fn request(
    app: &AppHandle,
    db: &DbHandle,
    method: reqwest::Method,
    path: &str,
    body: Option<&impl Serialize>,
) -> Result<reqwest::Response, String> {
    let base = base_url(db)?;
    let handle = sync_state(app);
    let client = handle.client.clone();
    let url = format!("{base}/api/v1{path}");

    let mut req = client.request(method.clone(), &url);
    let tokens = get_tokens(app)?;
    if let Some((access, _, _)) = &tokens {
        req = req.bearer_auth(access);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req.send().await.map_err(|e| format!("sync request failed: {e}"))?;
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(resp);
    }
    // 401: try one refresh, then retry the original request.
    let Some((_, refresh_token, _)) = tokens else {
        return Ok(resp);
    };
    if refresh(app, &client, &base, &refresh_token).await? {
        let Some((access, _, _)) = get_tokens(app)? else {
            return Ok(resp);
        };
        let mut retry = client.request(method, &url).bearer_auth(access);
        if let Some(b) = body {
            retry = retry.json(b);
        }
        return retry.send().await.map_err(|e| format!("sync retry failed: {e}"));
    }
    Ok(resp)
}

/// POST /account/refresh. On success stores the new token pair. `false` means
/// the refresh token was rejected and the caller must re-login.
async fn refresh(
    app: &AppHandle,
    client: &reqwest::Client,
    base: &str,
    refresh_token: &str,
) -> Result<bool, String> {
    let body = serde_json::json!({ "refresh_token": refresh_token });
    let resp = client
        .post(format!("{base}/api/v1/account/refresh"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("token refresh failed: {e}"))?;
    if !resp.status().is_success() {
        return Ok(false);
    }
    let tokens: protocol::TokenResponse = resp.json().await.map_err(|e| e.to_string())?;
    let handle = sync_state(app);
    let mut guard = handle.session.lock().map_err(|_| "sync lock poisoned".to_string())?;
    if let Some(s) = guard.as_mut() {
        s.access_token = tokens.access_token;
        s.refresh_token = tokens.refresh_token;
        s.device_id = tokens.device_id;
    }
    Ok(true)
}

async fn ensure_ok(resp: reqwest::Response, what: &str) -> Result<reqwest::Response, String> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(format!("{what} failed ({status}): {body}"))
}

/// Derive the password proof (`auth_hash`) the server expects, plus the KEK.
fn derive_proof(
    password: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<(String, SecretKey), String> {
    let pk = password_keys(password, salt, kdf).map_err(|e| e.to_string())?;
    let auth_hash = crypto::b64_encode(pk.auth_key.as_ref());
    Ok((auth_hash, pk.kek))
}

fn local_salt_and_kdf(db: &DbHandle) -> (Vec<u8>, KdfParams) {
    // Prefer the local vault's salt/params so the derived proof matches what was
    // registered from this device; fall back to defaults for fresh logins.
    if let Ok(Some(meta)) = db.with(|d| d.get_vault_meta()) {
        return (meta.kdf_salt, meta.kdf);
    }
    (Vec::new(), KdfParams::default())
}

// ---- commands ----

#[tauri::command]
pub async fn sync_register(
    app: AppHandle,
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
    email: String,
    password: String,
) -> Result<String, String> {
    let kdf = KdfParams::default();
    let salt = crypto::random_bytes::<SALT_LEN>().to_vec();
    let (auth_hash, kek) = derive_proof(&password, &salt, &kdf)?;
    let dek = vault.require_dek()?;
    let wrapped_dek = vault::wrap_dek(&kek, &dek).map_err(|e| e.to_string())?;
    // Fresh random recovery key wraps the DEK so the account can be recovered
    // if the master password is lost. Shown once, never stored.
    let recovery = crypto::random_key();
    let wrapped_dek_recovery =
        vault::wrap_dek_recovery(&recovery, &dek).map_err(|e| e.to_string())?;

    let req = protocol::RegisterRequest {
        email: email.clone(),
        auth_hash,
        kdf_salt: salt,
        kdf,
        wrapped_dek,
        wrapped_dek_recovery: Some(wrapped_dek_recovery),
    };
    let base = base_url(&db)?;
    let resp = sync_state(&app)
        .client
        .post(format!("{base}/api/v1/account/register"))
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("register failed: {e}"))?;
    let resp = ensure_ok(resp, "register").await?;
    let tokens: protocol::TokenResponse = resp.json().await.map_err(|e| e.to_string())?;

    set_session(
        &app,
        Some(Session {
            email,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            device_id: tokens.device_id,
        }),
    )?;
    Ok(crypto::encode_recovery_key(&recovery))
}

#[tauri::command]
pub async fn sync_login(
    app: AppHandle,
    db: State<'_, DbHandle>,
    email: String,
    password: String,
) -> Result<String, String> {
    let (salt, kdf) = local_salt_and_kdf(&db);
    let salt = if salt.is_empty() {
        crypto::random_bytes::<SALT_LEN>().to_vec()
    } else {
        salt
    };
    let (auth_hash, _kek) = derive_proof(&password, &salt, &kdf)?;
    let req = protocol::LoginRequest {
        email: email.clone(),
        auth_hash,
    };
    let base = base_url(&db)?;
    let resp = sync_state(&app)
        .client
        .post(format!("{base}/api/v1/account/login"))
        .json(&req)
        .send()
        .await
        .map_err(|e| format!("login failed: {e}"))?;
    let resp = ensure_ok(resp, "login").await?;
    let tokens: protocol::TokenResponse = resp.json().await.map_err(|e| e.to_string())?;
    let device_id = tokens.device_id.clone();
    set_session(
        &app,
        Some(Session {
            email,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            device_id: device_id.clone(),
        }),
    )?;
    Ok(device_id)
}

#[tauri::command]
pub async fn sync_status(
    app: AppHandle,
    db: State<'_, DbHandle>,
) -> Result<SyncStatus, String> {
    let email = sync_state(&app)
        .session
        .lock()
        .map_err(|_| "sync lock poisoned".to_string())?
        .as_ref()
        .map(|s| s.email.clone());
    let cursor = db
        .with(|d| d.get_meta(META_CURSOR))?
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let last_sync = db
        .with(|d| d.get_meta(META_LAST_SYNC))?
        .and_then(|v| v.parse::<i64>().ok());
    Ok(SyncStatus {
        connected: email.is_some(),
        email,
        cursor,
        last_sync,
    })
}

#[tauri::command]
pub async fn sync_logout(app: AppHandle) -> Result<(), String> {
    set_session(&app, None)?;
    Ok(())
}

#[tauri::command]
pub async fn sync_set_url(
    db: State<'_, DbHandle>,
    url: String,
) -> Result<(), String> {
    db.with(|d| d.set_meta(META_SYNC_URL, &url))?;
    Ok(())
}

#[tauri::command]
pub async fn sync_devices(
    app: AppHandle,
    db: State<'_, DbHandle>,
) -> Result<Vec<DeviceInfo>, String> {
    let current = require_session(&app)?.2;
    let resp = request(&app, &db, reqwest::Method::GET, "/devices", None::<&()>).await?;
    let resp = ensure_ok(resp, "list devices").await?;
    let rows: Vec<DeviceRow> = resp.json().await.map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|d| DeviceInfo {
            label: if d.id == current {
                "This device".to_string()
            } else {
                // The server stores no human label; show a short, stable id.
                format!("Device {}", &d.id[..8.min(d.id.len())])
            },
            id: d.id,
            created_at: d.created_at,
            revoked: d.revoked,
        })
        .collect())
}

#[tauri::command]
pub async fn sync_revoke_device(
    app: AppHandle,
    db: State<'_, DbHandle>,
    device_id: String,
) -> Result<(), String> {
    require_session(&app)?;
    let path = format!("/devices/{device_id}");
    let resp = request(&app, &db, reqwest::Method::DELETE, &path, None::<&()>).await?;
    ensure_ok(resp, "revoke device").await?;
    Ok(())
}

/// Seal one local entity into a `PushItem`.
fn seal_item(rc: &RecordCrypto, kind: &str, value: &Value) -> Result<PushItem, String> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "entity missing id".to_string())?
        .to_string();
    let updated_at = value
        .get("updated_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let deleted = value
        .get("deleted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let blob = rc.seal(value).map_err(|e| e.to_string())?;
    Ok(PushItem {
        id,
        kind: kind.to_string(),
        blob,
        updated_at,
        deleted,
    })
}

/// Apply one pulled record with last-write-wins against the local row.
fn apply_record(
    db: &Db,
    dek: &SecretKey,
    rec: &protocol::SyncRecord,
) -> std::result::Result<bool, String> {
    let rc = RecordCrypto::new(**dek);
    // Skip when the local copy is newer or equal (canonical LWW policy).
    if let Some(local_at) = db
        .get_entity_updated_at(&rec.kind, &rec.id)
        .map_err(|e| e.to_string())?
    {
        if matches!(
            protocol::decide(local_at, rec),
            protocol::MergeDecision::KeepLocal
        ) {
            return Ok(false);
        }
    }
    match rec.kind.as_str() {
        "host" => {
            let h: CoreHost = rc.open(&rec.blob).map_err(|e| e.to_string())?;
            db.upsert_host(&h).map_err(|e| e.to_string())?;
        }
        "group" => {
            let g: Group = rc.open(&rec.blob).map_err(|e| e.to_string())?;
            db.upsert_group(&g).map_err(|e| e.to_string())?;
        }
        "snippet" => {
            let s: Snippet = rc.open(&rec.blob).map_err(|e| e.to_string())?;
            db.upsert_snippet(&s).map_err(|e| e.to_string())?;
        }
        "known_host" => {
            let k: KnownHost = rc.open(&rec.blob).map_err(|e| e.to_string())?;
            db.upsert_known_host(&k).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown sync kind: {other}")),
    }
    Ok(true)
}

#[tauri::command]
pub async fn sync_now(
    app: AppHandle,
    db: State<'_, DbHandle>,
    vault: State<'_, VaultHandle>,
) -> Result<SyncResult, String> {
    require_session(&app)?;
    let dek = vault.require_dek()?;
    let rc = RecordCrypto::new(*dek);

    // ---- push ----
    let pushed_map: Value = db
        .with(|d| d.get_meta(META_PUSHED))?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut new_pushed = pushed_map.clone();
    let mut items: Vec<PushItem> = Vec::new();
    for kind in KINDS {
        let rows = db.with(|d| d.list_entity_json(kind))?;
        for value in rows {
            let id = value.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let updated_at = value.get("updated_at").and_then(Value::as_i64).unwrap_or(0);
            let key = format!("{kind}:{id}");
            let synced_at = pushed_map.get(&key).and_then(Value::as_i64).unwrap_or(-1);
            if synced_at == updated_at {
                continue; // unchanged since last successful push
            }
            items.push(seal_item(&rc, kind, &value)?);
            new_pushed[key] = Value::from(updated_at);
        }
    }

    let mut max_seq: i64 = 0;
    let mut pushed = 0u64;
    if !items.is_empty() {
        let resp = request(&app, &db, reqwest::Method::POST, "/sync/push", Some(&items)).await?;
        let resp = ensure_ok(resp, "push").await?;
        let applied: Vec<AppliedItem> = resp.json().await.map_err(|e| e.to_string())?;
        max_seq = applied.iter().map(|a| a.seq).max().unwrap_or(0);
        pushed = items.len() as u64;
        db.with(|d| d.set_meta(META_PUSHED, &serde_json::to_string(&new_pushed).unwrap_or_default()))?;
    }

    // ---- pull ----
    let mut cursor = db
        .with(|d| d.get_meta(META_CURSOR))?
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(-1);
    let mut pulled = 0u64;
    loop {
        let path = format!("/sync/pull?cursor={cursor}");
        let resp = request(&app, &db, reqwest::Method::GET, &path, None::<&()>).await?;
        let resp = ensure_ok(resp, "pull").await?;
        let page: protocol::PullResponse = resp.json().await.map_err(|e| e.to_string())?;
        let next = page.cursor as i64;
        for rec in &page.records {
            if db
                .with(|d| {
                    apply_record(d, &dek, rec).map_err(|e| rina_core::Error::Other(e))
                })?
            {
                pulled += 1;
            }
            cursor = cursor.max(rec.seq as i64);
        }
        cursor = cursor.max(next);
        if page.records.is_empty() || next <= cursor {
            break;
        }
    }

    let final_cursor = cursor.max(max_seq).max(0) as u64;
    db.with(|d| d.set_meta(META_CURSOR, &final_cursor.to_string()))?;
    db.with(|d| d.set_meta(META_LAST_SYNC, &now_ms().to_string()))?;
    Ok(SyncResult {
        pushed,
        pulled,
        cursor: final_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record sealed under the DEK must not open under any other key.
    #[test]
    fn record_blob_is_bound_to_the_dek() {
        let dek = crypto::random_key();
        let rc = RecordCrypto::new(*dek);
        let host = CoreHost {
            id: "h1".into(),
            group_id: None,
            label: "web".into(),
            hostname: "x".into(),
            port: 22,
            username: "root".into(),
            credential_id: None,
            jump_host_id: None,
            tags: Vec::new(),
            options: Default::default(),
            updated_at: 0,
            deleted: false,
        };
        let blob = rc.seal(&host).unwrap();
        let opened: CoreHost = rc.open(&blob).unwrap();
        assert_eq!(opened.label, "web");

        let other = RecordCrypto::new(*crypto::random_key());
        assert!(other.open::<CoreHost>(&blob).is_err());
    }

    /// Pull keeps the local row when it is newer or equal (last-write-wins).
    #[test]
    fn pull_skips_when_local_is_newer() {
        let dek = crypto::random_key();
        let rc = RecordCrypto::new(*dek);
        let remote = Snippet {
            id: "s1".into(),
            name: "remote".into(),
            body: String::new(),
            placeholders: Vec::new(),
            updated_at: 100,
            deleted: false,
        };
        let blob = rc.seal(&remote).unwrap();
        let rec = protocol::SyncRecord {
            id: "s1".into(),
            kind: "snippet".into(),
            blob,
            updated_at: 100,
            deleted: false,
            seq: 1,
        };
        let db = Db::open_in_memory().unwrap();
        db.upsert_snippet(&Snippet {
            id: "s1".into(),
            name: "local-newer".into(),
            body: String::new(),
            placeholders: Vec::new(),
            updated_at: 200,
            deleted: false,
        })
        .unwrap();
        assert!(!apply_record(&db, &dek, &rec).unwrap());
        assert_eq!(db.list_snippets().unwrap()[0].name, "local-newer");
    }
}
