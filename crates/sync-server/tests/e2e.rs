//! Live end-to-end test of the zero-knowledge sync protocol.
//!
//! Needs a reachable PostgreSQL and a running `rina-sync-server`. Bring them up:
//!
//! ```bash
//! docker run -d --name rina-pg -e POSTGRES_PASSWORD=pg -p 55432:5432 postgres:17
//! DATABASE_URL=postgres://postgres:pg@localhost:55432/postgres \
//!   JWT_SECRET=00000000000000000000000000000000 \
//!   BIND_ADDR=127.0.0.1:18080 cargo run -p rina-sync-server
//! ```
//!
//! Then:
//! ```bash
//! SYNC_URL=http://127.0.0.1:18080/api/v1 \
//!   cargo test -p rina-sync-server --test e2e -- --nocapture --include-ignored
//! ```
//!
//! Without a server the test is ignored, never silently skipped.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rina_core::crypto::{self, KdfParams};
use rina_sync::envelope::RecordCrypto;
use rina_sync::protocol::{LoginRequest, PushItem, RegisterRequest, TokenResponse};
use serde_json::json;

fn base_url() -> String {
    std::env::var("SYNC_URL").unwrap_or_else(|_| "http://127.0.0.1:18080/api/v1".into())
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("http client")
}

/// Derive the client-side auth_hash exactly like the app: Argon2id over the
/// master password -> HKDF subkey "auth" -> base64 of 32 bytes.
fn auth_hash(password: &str, salt: &[u8], kdf: &KdfParams) -> String {
    let master = crypto::derive_master_key(password, salt, kdf).expect("argon2");
    let auth = crypto::derive_subkey(master.as_ref(), "auth");
    B64.encode(auth.as_ref())
}

fn unique_email() -> String {
    format!("e2e-{}@rina.test", uuid_like())
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos}-{}", std::process::id())
}

fn post_json(url: &str, token: Option<&str>, body: &serde_json::Value) -> reqwest::blocking::Response {
    let mut rb = client().post(url).json(body);
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    rb.send().expect("request")
}

fn get(url: &str, token: &str) -> reqwest::blocking::Response {
    client()
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("request")
}

fn assert_status(resp: &reqwest::blocking::Response, want: u16, ctx: &str) {
    let got = resp.status().as_u16();
    assert_eq!(got, want, "{ctx}: expected {want}, got {got}");
}

#[test]
#[ignore = "needs DATABASE_URL + a running sync server (no Docker/Postgres on this host)"]
fn live_end_to_end() {
    let base = base_url();
    let kdf = KdfParams::insecure_for_tests(); // fast; server only checks bounds
    let salt = crypto::random_bytes::<16>();
    let password = "correct horse battery staple";
    let auth = auth_hash(password, &salt, &kdf);
    let _recovery = auth_hash(&format!("{password}-recovery"), &salt, &kdf);
    let email = unique_email();

    // Opaque ciphertext blobs the server should never be able to read.
    let dek = crypto::random_key();
    let wrapped_dek = crypto::seal(crypto::random_key().as_ref(), dek.as_ref(), b"wrap").unwrap();
    let wrapped_recovery =
        crypto::seal(crypto::random_key().as_ref(), dek.as_ref(), b"wrap-recovery").unwrap();

    // ---- register ----
    let reg = RegisterRequest {
        email: email.clone(),
        auth_hash: auth.clone(),
        kdf_salt: salt.to_vec(),
        kdf,
        wrapped_dek: wrapped_dek.clone(),
        wrapped_dek_recovery: Some(wrapped_recovery.clone()),
    };
    let resp = post_json(&format!("{base}/account/register"), None, &serde_json::to_value(&reg).unwrap());
    assert_status(&resp, 200, "register");
    let tok_a: TokenResponse = resp.json().expect("register TokenResponse");
    assert!(!tok_a.access_token.is_empty() && !tok_a.refresh_token.is_empty());
    assert!(!tok_a.device_id.is_empty(), "register must return device_id");

    // Duplicate registration is a conflict.
    let resp = post_json(&format!("{base}/account/register"), None, &serde_json::to_value(&reg).unwrap());
    assert_status(&resp, 409, "duplicate register");

    // ---- wrong auth_hash login fails ----
    let bad = LoginRequest {
        email: email.clone(),
        auth_hash: B64.encode([0xAAu8; 32]),
    };
    let resp = post_json(&format!("{base}/account/login"), None, &serde_json::to_value(&bad).unwrap());
    assert_status(&resp, 401, "wrong auth_hash login");

    // ---- login (second device) ----
    let good = LoginRequest { email: email.clone(), auth_hash: auth.clone() };
    let resp = post_json(&format!("{base}/account/login"), None, &serde_json::to_value(&good).unwrap());
    assert_status(&resp, 200, "login");
    let tok_b: TokenResponse = resp.json().expect("login TokenResponse");
    assert_ne!(tok_a.device_id, tok_b.device_id, "each login = new device");

    // ---- push 3 sealed records ----
    let rc = RecordCrypto::new(*dek);
    let payloads = vec![
        json!({"label": "prod-db", "user": "admin", "password": "s3cr3t-sup3r-l0ng-v4lue"}),
        json!({"label": "staging", "user": "deploy", "password": "another-secret"}),
        json!({"label": "router", "user": "root", "password": "third-secret"}),
    ];
    let mut pushed: Vec<PushItem> = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let sealed = rc.seal(p).expect("seal");
        // The blob must NOT contain plaintext bytes.
        assert!(
            !sealed.windows(8).any(|w| w == b"s3cr3t-s"),
            "sealed blob leaked plaintext"
        );
        pushed.push(PushItem {
            id: format!("rec-{i}"),
            kind: "host".into(),
            blob: sealed,
            updated_at: 1_000 + i as i64,
            deleted: false,
        });
    }
    let resp = post_json(
        &format!("{base}/sync/push"),
        Some(&tok_a.access_token),
        &serde_json::to_value(&pushed).unwrap(),
    );
    assert_status(&resp, 200, "push");

    // ---- pull from cursor 0, blobs round-trip byte-for-byte ----
    let resp = get(&format!("{base}/sync/pull?cursor=0"), &tok_b.access_token);
    assert_status(&resp, 200, "pull");
    let pulled: rina_sync::protocol::PullResponse = resp.json().expect("pull body");
    assert_eq!(pulled.records.len(), 3, "expected 3 records");
    for p in &pushed {
        let got = pulled
            .records
            .iter()
            .find(|r| r.id == p.id)
            .unwrap_or_else(|| panic!("record {} missing from pull", p.id));
        assert_eq!(got.blob, p.blob, "blob must round-trip byte-for-byte: {}", p.id);
        assert_eq!(got.kind, p.kind);
        assert_eq!(got.updated_at, p.updated_at);
    }
    // Client decrypts what the server stored.
    for r in &pulled.records {
        let v: serde_json::Value = rc.open(&r.blob).expect("open pulled record");
        assert!(v.get("password").is_some());
    }
    let cursor = pulled.cursor;
    assert!(cursor > 0);

    // ---- LWW: older push loses, newer push wins ----
    let target = "rec-0";
    let older = PushItem {
        id: target.into(),
        kind: "host".into(),
        blob: rc.seal(&json!({"label": "OLD-SHOULD-LOSE"})).unwrap(),
        updated_at: 10,
        deleted: false,
    };
    let resp = post_json(
        &format!("{base}/sync/push"),
        Some(&tok_a.access_token),
        &serde_json::to_value(vec![older]).unwrap(),
    );
    assert_status(&resp, 200, "push older");

    let resp = get(&format!("{base}/sync/pull?cursor=0"), &tok_b.access_token);
    let after_old: rina_sync::protocol::PullResponse = resp.json().unwrap();
    let rec = after_old.records.iter().find(|r| r.id == target).unwrap();
    assert_eq!(rec.blob, pushed[0].blob, "older push must NOT overwrite");

    let newer = PushItem {
        id: target.into(),
        kind: "host".into(),
        blob: rc.seal(&json!({"label": "NEW-SHOULD-WIN"})).unwrap(),
        updated_at: 9_000,
        deleted: false,
    };
    let newer_blob = newer.blob.clone();
    let resp = post_json(
        &format!("{base}/sync/push"),
        Some(&tok_a.access_token),
        &serde_json::to_value(vec![newer]).unwrap(),
    );
    assert_status(&resp, 200, "push newer");

    let resp = get(&format!("{base}/sync/pull?cursor=0"), &tok_b.access_token);
    let after_new: rina_sync::protocol::PullResponse = resp.json().unwrap();
    let rec = after_new.records.iter().find(|r| r.id == target).unwrap();
    assert_eq!(rec.blob, newer_blob, "newer push must win");
    assert_eq!(rec.updated_at, 9_000);
    let v: serde_json::Value = rc.open(&rec.blob).unwrap();
    assert_eq!(v["label"], "NEW-SHOULD-WIN");

    // ---- devices: list then revoke the other device ----
    let resp = get(&format!("{base}/devices"), &tok_a.access_token);
    assert_status(&resp, 200, "list devices");
    let devices: Vec<serde_json::Value> = resp.json().unwrap();
    assert!(devices.iter().any(|d| d["id"] == tok_a.device_id.as_str()));
    assert!(devices.iter().any(|d| d["id"] == tok_b.device_id.as_str()));

    let resp = client()
        .delete(format!("{base}/devices/{}", tok_b.device_id))
        .bearer_auth(&tok_a.access_token)
        .send()
        .expect("delete device");
    assert_status(&resp, 204, "revoke device");

    // Revoked device's access token must now be rejected.
    let resp = get(&format!("{base}/sync/pull?cursor=0"), &tok_b.access_token);
    assert_status(&resp, 401, "revoked device pull");

    // Its refresh token must also fail.
    let resp = post_json(
        &format!("{base}/account/refresh"),
        None,
        &json!({ "refresh_token": tok_b.refresh_token }),
    );
    assert_status(&resp, 401, "revoked device refresh");

    // The still-valid device keeps working.
    let resp = get(&format!("{base}/sync/pull?cursor=0"), &tok_a.access_token);
    assert_status(&resp, 200, "valid device pull after revoke");

    // Cannot revoke yourself.
    let resp = client()
        .delete(format!("{base}/devices/{}", tok_a.device_id))
        .bearer_auth(&tok_a.access_token)
        .send()
        .expect("delete self");
    assert_status(&resp, 400, "cannot revoke current device");

    // ---- re-login with wrong password on an existing account ----
    let wrong = LoginRequest { email: email.clone(), auth_hash: B64.encode([0x11u8; 32]) };
    let resp = post_json(&format!("{base}/account/login"), None, &serde_json::to_value(&wrong).unwrap());
    assert_status(&resp, 401, "wrong password login");
}
