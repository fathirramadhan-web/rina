import { invoke } from "@tauri-apps/api/core";
import { useApp, type Host, type AuthKind, type DirEntry } from "./store";

// Every IPC call funnels through here so an unimplemented backend command
// surfaces as a toast instead of an unhandled rejection.
async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T | null> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    useApp.getState().toast(`${cmd}: ${String(e)}`, "error");
    return null;
  }
}

export async function listHosts(): Promise<Host[]> {
  try {
    return await invoke<Host[]>("list_hosts");
  } catch (e) {
    useApp.getState().toast(`list_hosts: ${String(e)}`, "error");
    return [];
  }
}

export async function connectHost(hostId: string): Promise<string> {
  // returns a session id
  return invoke<string>("connect_host", { hostId });
}

export async function disconnect(sessionId: string): Promise<void> {
  return invoke("disconnect", { sessionId });
}

export async function write(sessionId: string, data: string): Promise<void> {
  return invoke("session_write", { sessionId, data });
}

export async function resize(sessionId: string, cols: number, rows: number): Promise<void> {
  return invoke("session_resize", { sessionId, cols, rows });
}

export async function exportBackup(): Promise<string> {
  return invoke<string>("export_backup");
}

// ---------- Host & vault management ----------

export interface HostSavePayload {
  id: string | null;
  label: string;
  hostname: string;
  port: number;
  username: string;
  groupId: string | null;
  tags: string[];
  authKind: AuthKind;
  secret: string;      // password, or PEM private key
  passphrase: string;  // private-key passphrase (may be empty)
}

export function hostSave(p: HostSavePayload): Promise<Host | null> {
  return call<Host>("host_save", { ...p });
}

export function hostDelete(hostId: string): Promise<boolean> {
  return call("host_delete", { hostId }).then((r) => r !== null);
}

export function groupSave(id: string | null, name: string, parentId: string | null): Promise<string | null> {
  return call<string>("group_save", { id, name, parentId });
}

export function snippetSave(id: string | null, name: string, body: string): Promise<boolean> {
  return call("snippet_save", { id, name, body }).then((r) => r !== null);
}

export function snippetDelete(snippetId: string): Promise<boolean> {
  return call("snippet_delete", { snippetId }).then((r) => r !== null);
}

export async function vaultExists(): Promise<boolean> {
  const r = await call<boolean>("vault_exists");
  return r === true;
}

export function vaultUnlock(password: string): Promise<boolean> {
  return call<boolean>("vault_unlock", { password }).then((r) => {
    if (r === true) useApp.getState().setVaultLocked(false);
    return r === true;
  });
}

// Returns the one-time recovery key, or null on failure.
export function vaultCreate(password: string): Promise<string | null> {
  return call<string>("vault_create", { password }).then((r) => {
    if (r == null) return null;
    useApp.getState().setVaultLocked(false);
    return r;
  });
}

export function vaultLock(): Promise<void> {
  useApp.getState().setVaultLocked(true);
  return call("vault_lock").then(() => undefined);
}

// ---------- SFTP ----------

function sid(sessionId: string): boolean {
  if (!sessionId) {
    useApp.getState().toast("No connected session for SFTP", "error");
    return false;
  }
  return true;
}

export function sftpList(sessionId: string, path: string): Promise<DirEntry[]> {
  if (!sid(sessionId)) return Promise.resolve([]);
  return call<DirEntry[]>("sftp_list", { sessionId, path }).then((r) => r ?? []);
}

export function sftpDownload(sessionId: string, remotePath: string): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return call("sftp_download", { sessionId, remotePath }).then(() => true).catch(() => false);
}

export function sftpUpload(sessionId: string, remotePath: string, file: Blob): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return file
    .arrayBuffer()
    .then((buf) => Array.from(new Uint8Array(buf)))
    .then((data) => call("sftp_upload", { sessionId, remotePath, data }))
    .then((r) => r !== null)
    .catch(() => false);
}

export function sftpMkdir(sessionId: string, path: string): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return call("sftp_mkdir", { sessionId, path }).then((r) => r !== null);
}

export function sftpDelete(sessionId: string, path: string): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return call("sftp_delete", { sessionId, path }).then((r) => r !== null);
}

export function sftpRename(sessionId: string, from: string, to: string): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return call("sftp_rename", { sessionId, from, to }).then((r) => r !== null);
}

export function sftpChmod(sessionId: string, path: string, mode: string): Promise<boolean> {
  if (!sid(sessionId)) return Promise.resolve(false);
  return call("sftp_chmod", { sessionId, path, mode }).then((r) => r !== null);
}
