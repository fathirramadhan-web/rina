//! SQLite-backed store. Offline-first: every operation hits the local DB; sync
//! runs in the background. Secrets are stored encrypted (see [`crate::vault`]).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::models::{
    now_ms, AuthKind, Credential, Group, Host, KnownHost, Snippet,
};
use crate::vault::VaultMeta;

/// Opens and owns the SQLite connection.
pub struct Db {
    conn: Connection,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id TEXT,
    icon TEXT,
    color TEXT,
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    group_id TEXT,
    label TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    credential_id TEXT,
    jump_host_id TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    options TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    secret_enc BLOB NOT NULL,
    passphrase_enc BLOB,
    public_key TEXT,
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS snippets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    body TEXT NOT NULL,
    placeholders TEXT NOT NULL DEFAULT '[]',
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS known_hosts (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    key_type TEXT NOT NULL,
    key_blob BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sync_meta (
    entity TEXT PRIMARY KEY,
    last_synced_at INTEGER NOT NULL DEFAULT 0,
    cursor INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts(group_id);
"#;

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ---- vault meta persistence ----

    pub fn set_vault_meta(&self, meta: &VaultMeta) -> Result<()> {
        let json = serde_json::to_string(meta)?;
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES('vault', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![json],
        )?;
        Ok(())
    }

    pub fn get_vault_meta(&self) -> Result<Option<VaultMeta>> {
        let json: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='vault'", [], |r| r.get(0))
            .optional()?;
        json.map(|j| serde_json::from_str(&j).map_err(Into::into)).transpose()
    }

    pub fn has_vault(&self) -> Result<bool> {
        Ok(self.get_vault_meta()?.is_some())
    }

    // ---- generic meta (sync URL, tokens, cursor) ----

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Local `updated_at` for a synced entity (tombstones included), so pull can
    /// do last-write-wins. `kind` is a fixed whitelist, so the interpolated
    /// table name is safe.
    pub fn get_entity_updated_at(&self, kind: &str, id: &str) -> Result<Option<i64>> {
        let table = match kind {
            "host" => "hosts",
            "group" => "groups",
            "snippet" => "snippets",
            "known_host" => "known_hosts",
            other => return Err(Error::Invalid(format!("unknown sync kind: {other}"))),
        };
        let sql = format!("SELECT updated_at FROM {table} WHERE id=?1");
        self.conn
            .query_row(&sql, params![id], |r| r.get(0))
            .optional()
            .map_err(Into::into)
    }

    /// All local rows for a synced entity kind, tombstones included, as JSON.
    /// Lets the sync client seal pushes and compute last-write-wins without
    /// per-kind query methods. `kind` is a fixed whitelist, so the interpolated
    /// table name is safe.
    pub fn list_entity_json(&self, kind: &str) -> Result<Vec<serde_json::Value>> {
        let out = match kind {
            "host" => {
                let mut s = self.conn.prepare("SELECT * FROM hosts")?;
                let rows: Vec<Host> = s
                    .query_map([], host_from_row)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                to_json_values(rows)?
            }
            "group" => {
                let mut s = self.conn.prepare("SELECT * FROM groups")?;
                let rows: Vec<Group> = s
                    .query_map([], group_from_row)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                to_json_values(rows)?
            }
            "snippet" => {
                let mut s = self.conn.prepare("SELECT * FROM snippets")?;
                let rows: Vec<Snippet> = s
                    .query_map([], snippet_from_row)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                to_json_values(rows)?
            }
            "known_host" => {
                let mut s = self.conn.prepare("SELECT * FROM known_hosts")?;
                let rows: Vec<KnownHost> = s
                    .query_map([], known_host_from_row)?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                to_json_values(rows)?
            }
            other => return Err(Error::Invalid(format!("unknown sync kind: {other}"))),
        };
        Ok(out)
    }

    // ---- groups ----

    pub fn upsert_group(&self, g: &Group) -> Result<()> {
        self.conn.execute(
            "INSERT INTO groups(id,name,parent_id,icon,color,updated_at,deleted)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, parent_id=excluded.parent_id,
               icon=excluded.icon, color=excluded.color, updated_at=excluded.updated_at,
               deleted=excluded.deleted",
            params![g.id, g.name, g.parent_id, g.icon, g.color, g.updated_at, g.deleted as i64],
        )?;
        Ok(())
    }

    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let mut stmt = self.conn.prepare("SELECT * FROM groups WHERE deleted=0 ORDER BY name")?;
        let rows = stmt.query_map([], |r| group_from_row(r))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ---- hosts ----

    pub fn upsert_host(&self, h: &Host) -> Result<()> {
        let tags = serde_json::to_string(&h.tags)?;
        let options = serde_json::to_string(&h.options)?;
        self.conn.execute(
            "INSERT INTO hosts(id,group_id,label,hostname,port,username,credential_id,jump_host_id,tags,options,updated_at,deleted)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(id) DO UPDATE SET group_id=excluded.group_id, label=excluded.label,
               hostname=excluded.hostname, port=excluded.port, username=excluded.username,
               credential_id=excluded.credential_id, jump_host_id=excluded.jump_host_id,
               tags=excluded.tags, options=excluded.options, updated_at=excluded.updated_at,
               deleted=excluded.deleted",
            params![
                h.id, h.group_id, h.label, h.hostname, h.port as i64, h.username,
                h.credential_id, h.jump_host_id, tags, options, h.updated_at, h.deleted as i64
            ],
        )?;
        Ok(())
    }

    pub fn list_hosts(&self) -> Result<Vec<Host>> {
        let mut stmt = self.conn.prepare("SELECT * FROM hosts WHERE deleted=0 ORDER BY label")?;
        let rows = stmt.query_map([], |r| host_from_row(r))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_host(&self, id: &str) -> Result<Host> {
        self.conn
            .query_row("SELECT * FROM hosts WHERE id=?1 AND deleted=0", params![id], |r| host_from_row(r))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound(format!("host {id}")),
                other => other.into(),
            })
    }

    pub fn delete_host(&self, id: &str) -> Result<()> {
        // Soft delete (tombstone) so sync can propagate.
        self.conn.execute(
            "UPDATE hosts SET deleted=1, updated_at=?2 WHERE id=?1",
            params![id, now_ms()],
        )?;
        Ok(())
    }

    // ---- credentials ----

    pub fn upsert_credential(&self, c: &Credential) -> Result<()> {
        self.conn.execute(
            "INSERT INTO credentials(id,label,kind,secret_enc,passphrase_enc,public_key,updated_at,deleted)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET label=excluded.label, kind=excluded.kind,
               secret_enc=excluded.secret_enc, passphrase_enc=excluded.passphrase_enc,
               public_key=excluded.public_key, updated_at=excluded.updated_at, deleted=excluded.deleted",
            params![
                c.id, c.label, kind_str(c.kind), c.secret_enc, c.passphrase_enc,
                c.public_key, c.updated_at, c.deleted as i64
            ],
        )?;
        Ok(())
    }

    pub fn list_credentials(&self) -> Result<Vec<Credential>> {
        let mut stmt =
            self.conn.prepare("SELECT * FROM credentials WHERE deleted=0 ORDER BY label")?;
        let rows = stmt.query_map([], |r| credential_from_row(r))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_credential(&self, id: &str) -> Result<Credential> {
        self.conn
            .query_row("SELECT * FROM credentials WHERE id=?1 AND deleted=0", params![id], |r| {
                credential_from_row(r)
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound(format!("credential {id}")),
                other => other.into(),
            })
    }

    // ---- snippets ----

    pub fn upsert_snippet(&self, s: &Snippet) -> Result<()> {
        let ph = serde_json::to_string(&s.placeholders)?;
        self.conn.execute(
            "INSERT INTO snippets(id,name,body,placeholders,updated_at,deleted)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, body=excluded.body,
               placeholders=excluded.placeholders, updated_at=excluded.updated_at, deleted=excluded.deleted",
            params![s.id, s.name, s.body, ph, s.updated_at, s.deleted as i64],
        )?;
        Ok(())
    }

    pub fn list_snippets(&self) -> Result<Vec<Snippet>> {
        let mut stmt = self.conn.prepare("SELECT * FROM snippets WHERE deleted=0 ORDER BY name")?;
        let rows = stmt.query_map([], |r| snippet_from_row(r))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ---- known hosts (TOFU) ----

    pub fn known_host_id(host: &str, port: u16) -> String {
        format!("kh:{host}:{port}")
    }

    pub fn get_known_host(&self, host: &str, port: u16) -> Result<Option<KnownHost>> {
        let id = Self::known_host_id(host, port);
        self.conn
            .query_row("SELECT * FROM known_hosts WHERE id=?1", params![id], |r| {
                known_host_from_row(r)
            })
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_known_host(&self, k: &KnownHost) -> Result<()> {
        self.conn.execute(
            "INSERT INTO known_hosts(id,host,port,key_type,key_blob,updated_at,deleted)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET key_type=excluded.key_type, key_blob=excluded.key_blob,
               updated_at=excluded.updated_at, deleted=excluded.deleted",
            params![k.id, k.host, k.port as i64, k.key_type, k.key_blob, k.updated_at, k.deleted as i64],
        )?;
        Ok(())
    }

    // ---- backup / export ----

    pub fn export_json(&self) -> Result<String> {
        #[derive(serde::Serialize)]
        struct Backup<'a> {
            groups: &'a [Group],
            hosts: &'a [Host],
            snippets: &'a [Snippet],
        }
        let groups = self.list_groups()?;
        let hosts = self.list_hosts()?;
        let snippets = self.list_snippets()?;
        Ok(serde_json::to_string_pretty(&Backup { groups: &groups, hosts: &hosts, snippets: &snippets })?)
    }
}

fn to_json_values<T: Serialize>(rows: Vec<T>) -> Result<Vec<serde_json::Value>> {
    rows.iter()
        .map(|e| serde_json::to_value(e).map_err(Into::into))
        .collect::<Result<Vec<serde_json::Value>>>()
}

fn kind_str(k: AuthKind) -> &'static str {
    match k {
        AuthKind::Password => "password",
        AuthKind::PrivateKey => "private_key",
        AuthKind::Agent => "agent",
    }
}

fn kind_from(s: &str) -> Result<AuthKind> {
    match s {
        "password" => Ok(AuthKind::Password),
        "private_key" => Ok(AuthKind::PrivateKey),
        "agent" => Ok(AuthKind::Agent),
        other => Err(Error::Invalid(format!("unknown auth kind: {other}"))),
    }
}

fn group_from_row(r: &Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        id: r.get("id")?,
        name: r.get("name")?,
        parent_id: r.get("parent_id")?,
        icon: r.get("icon")?,
        color: r.get("color")?,
        updated_at: r.get("updated_at")?,
        deleted: r.get::<_, i64>("deleted")? != 0,
    })
}

fn host_from_row(r: &Row<'_>) -> rusqlite::Result<Host> {
    let tags_s: String = r.get("tags")?;
    let opts_s: String = r.get("options")?;
    Ok(Host {
        id: r.get("id")?,
        group_id: r.get("group_id")?,
        label: r.get("label")?,
        hostname: r.get("hostname")?,
        port: r.get::<_, i64>("port")? as u16,
        username: r.get("username")?,
        credential_id: r.get("credential_id")?,
        jump_host_id: r.get("jump_host_id")?,
        tags: serde_json::from_str(&tags_s).unwrap_or_default(),
        options: serde_json::from_str(&opts_s).unwrap_or_default(),
        updated_at: r.get("updated_at")?,
        deleted: r.get::<_, i64>("deleted")? != 0,
    })
}

fn credential_from_row(r: &Row<'_>) -> rusqlite::Result<Credential> {
    let kind_s: String = r.get("kind")?;
    Ok(Credential {
        id: r.get("id")?,
        label: r.get("label")?,
        kind: kind_from(&kind_s).unwrap_or(AuthKind::Password),
        secret_enc: r.get("secret_enc")?,
        passphrase_enc: r.get("passphrase_enc")?,
        public_key: r.get("public_key")?,
        updated_at: r.get("updated_at")?,
        deleted: r.get::<_, i64>("deleted")? != 0,
    })
}

fn snippet_from_row(r: &Row<'_>) -> rusqlite::Result<Snippet> {
    let ph: String = r.get("placeholders")?;
    Ok(Snippet {
        id: r.get("id")?,
        name: r.get("name")?,
        body: r.get("body")?,
        placeholders: serde_json::from_str(&ph).unwrap_or_default(),
        updated_at: r.get("updated_at")?,
        deleted: r.get::<_, i64>("deleted")? != 0,
    })
}

fn known_host_from_row(r: &Row<'_>) -> rusqlite::Result<KnownHost> {
    Ok(KnownHost {
        id: r.get("id")?,
        host: r.get("host")?,
        port: r.get::<_, i64>("port")? as u16,
        key_type: r.get("key_type")?,
        key_blob: r.get("key_blob")?,
        updated_at: r.get("updated_at")?,
        deleted: r.get::<_, i64>("deleted")? != 0,
    })
}

