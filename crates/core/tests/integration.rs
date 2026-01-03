//! Integration tests: SQLite store round-trips and vault persistence.

use rina_core::db::Db;
use rina_core::models::{new_id, now_ms, AuthKind, Credential, Host, Snippet};
use rina_core::vault::VaultMeta;
use rina_core::crypto::KdfParams;

#[test]
fn host_crud_and_soft_delete() {
    let db = Db::open_in_memory().unwrap();
    let id = new_id();
    let host = Host {
        id: id.clone(),
        label: "web".into(),
        hostname: "10.0.0.5".into(),
        port: 2222,
        username: "deploy".into(),
        updated_at: now_ms(),
        ..Default::default()
    };
    db.upsert_host(&host).unwrap();
    let got = db.get_host(&id).unwrap();
    assert_eq!(got.hostname, "10.0.0.5");
    assert_eq!(got.port, 2222);

    // update label
    let mut updated = got.clone();
    updated.label = "prod".into();
    db.upsert_host(&updated).unwrap();
    assert_eq!(db.list_hosts().unwrap().len(), 1);
    assert_eq!(db.list_hosts().unwrap()[0].label, "prod");

    // soft delete hides it
    db.delete_host(&id).unwrap();
    assert!(db.list_hosts().unwrap().is_empty());
    assert!(db.get_host(&id).is_err());
}

#[test]
fn credential_and_snippet_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let cred = Credential {
        id: new_id(),
        label: "my key".into(),
        kind: AuthKind::PrivateKey,
        secret_enc: vec![1, 2, 3],
        passphrase_enc: None,
        public_key: Some("AAAAC3".into()),
        updated_at: now_ms(),
        deleted: false,
    };
    db.upsert_credential(&cred).unwrap();
    let got = db.get_credential(&cred.id).unwrap();
    assert_eq!(got.kind, AuthKind::PrivateKey);
    assert_eq!(got.secret_enc, vec![1, 2, 3]);

    let snip = Snippet {
        id: new_id(),
        name: "df -h".into(),
        body: "df -h {{path}}".into(),
        placeholders: vec!["path".into()],
        updated_at: now_ms(),
        deleted: false,
    };
    db.upsert_snippet(&snip).unwrap();
    assert_eq!(db.list_snippets().unwrap()[0].placeholders, vec!["path"]);
}

#[test]
fn vault_meta_persists() {
    let db = Db::open_in_memory().unwrap();
    assert!(!db.has_vault().unwrap());
    let nv = VaultMeta::create("correct horse", KdfParams::insecure_for_tests()).unwrap();
    db.set_vault_meta(&nv.meta).unwrap();
    assert!(db.has_vault().unwrap());
    let loaded = db.get_vault_meta().unwrap().unwrap();
    assert_eq!(loaded, nv.meta);
    // wrong password rejected, right one unlocks to same DEK
    assert!(loaded.unlock("wrong").is_err());
    assert_eq!(*loaded.unlock("correct horse").unwrap().dek, *nv.keys.dek);
}

#[test]
fn known_host_tofu_id_is_deterministic() {
    let db = Db::open_in_memory().unwrap();
    assert_eq!(Db::known_host_id("h", 22), Db::known_host_id("h", 22));
    assert_ne!(Db::known_host_id("h", 22), Db::known_host_id("h", 2222));
    assert!(db.get_known_host("h", 22).unwrap().is_none());
}

#[test]
fn export_json_contains_hosts() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_host(&Host {
        id: new_id(),
        label: "db".into(),
        hostname: "db.local".into(),
        ..Default::default()
    })
    .unwrap();
    let json = db.export_json().unwrap();
    assert!(json.contains("db.local"));
}
