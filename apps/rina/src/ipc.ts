import { invoke } from "@tauri-apps/api/core";
import type { Host } from "./store";

export async function listHosts(): Promise<Host[]> {
  return invoke<Host[]>("list_hosts");
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
