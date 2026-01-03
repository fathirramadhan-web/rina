# RINA

**R**emote **I**nteractive **N**etwork **A**ccess

A cross-platform desktop SSH client with SFTP and optional end-to-end encrypted
sync to a server you host yourself. Built with **Rust** (Tauri 2, russh, rusqlite,
Axum) and **React + TypeScript** (xterm.js).

## Features

- SSH terminal — password, private key (with passphrase), ssh-agent,
  keyboard-interactive (2FA/OTP), ProxyJump, TOFU host-key verification,
  keepalive, auto-reconnect.
- Workspace — tabs, split panes, session restore.
- Hosts & snippets — nested groups, tags, search, command palette, import
  `~/.ssh/config`, JSON backup, snippets with `{{placeholders}}`.
- SFTP — dual-pane browser, upload/download with resume, remote edit, chmod.
- Vault — Argon2id master password, XChaCha20-Poly1305, recovery key, OS keychain.
- Sync (optional) — zero-knowledge E2E encrypted sync with a self-hosted server.

## Repository layout

```
crates/core      data model, SQLite, vault & crypto, ssh_config import
crates/ssh       russh connection/auth, PTY shells, SFTP
crates/sync      sync protocol types, record encryption
apps/rina        Tauri app (src-tauri = Rust, src = React UI)
```

## Development

Prerequisites: Rust (stable), Node.js ≥ 20, Tauri 2 system dependencies.

```
cargo build --workspace
cargo test --workspace
cd apps/rina && npm install && npm run tauri dev
```

## License

All rights reserved. License to be chosen.
