import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useApp, type Tab } from "./store";
import { TermView } from "./TermView";
import { Dialogs, Toasts, SftpPanel, Icon as UIIcon } from "./ui";
import * as ipc from "./ipc";

// SVG icon set — no icon-font dependency, no decorative text.
const Icon = {
  Terminal: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M4 17l6-6-6-6M12 19h8" />
    </svg>
  ),
  Plus: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 5v14M5 12h14" />
    </svg>
  ),
  Close: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  ),
  Menu: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M3 12h18M3 6h18M3 18h18" />
    </svg>
  ),
  Search: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" />
    </svg>
  ),
};

// Terminal callbacks registered per session id; TermView subscribes through these.
type OutputSink = (data: string) => void;
type ClosedSink = (status: number | null) => void;
const outputs = new Map<string, OutputSink>();
const closed = new Map<string, ClosedSink>();

function newId() {
  return globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
}

export default function App() {
  const hosts = useApp((s) => s.hosts);
  const tabs = useApp((s) => s.tabs);
  const activeTab = useApp((s) => s.activeTab);
  const sidebarOpen = useApp((s) => s.sidebarOpen);
  const sftpOpen = useApp((s) => s.sftp.open);
  const vaultLocked = useApp((s) => s.vaultLocked);
  const hasVault = useApp((s) => s.hasVault);
  const setDialog = useApp((s) => s.setDialog);
  const toast = useApp((s) => s.toast);
  const toggleSftp = useApp((s) => s.toggleSftp);
  const { setHosts, addTab, removeTab, setActiveTab, toggleSidebar } = useApp();
  const [filter, setFilter] = useState("");
  const [sessions, setSessions] = useState<Record<string, string>>({}); // tabId -> sessionId

  // Load hosts from the Rust backend on mount.
  useEffect(() => {
    ipc.listHosts().then(setHosts).catch(() => setHosts([]));
  }, [setHosts]);

  // Vault unlock prompt on startup when a vault exists.
  const vaultChecked = useRef(false);
  useEffect(() => {
    if (vaultChecked.current) return;
    vaultChecked.current = true;
    ipc.vaultExists().then((exists) => {
      useApp.getState().setHasVault(exists);
      if (exists) useApp.getState().setDialog({ kind: "vault-unlock" });
    });
  }, []);

  // Stream terminal output into the active TermView via Tauri events.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<{ sessionId: string; data: number[] }>("session-output", (e) => {
      const sink = outputs.get(e.payload.sessionId);
      if (sink) sink(new TextDecoder().decode(new Uint8Array(e.payload.data)));
    }).then((u) => (unlisten = u));
    listen<{ sessionId: string; status: number | null }>("session-closed", (e) => {
      const sink = closed.get(e.payload.sessionId);
      if (sink) sink(e.payload.status);
    });
    return () => unlisten?.();
  }, []);

  const openHost = useCallback(
    async (hostId: string, label: string) => {
      const tabId = newId();
      addTab({ id: tabId, hostId, title: label, connected: false });
      try {
        const sessionId = await ipc.connectHost(hostId);
        setSessions((s) => ({ ...s, [tabId]: sessionId }));
        useApp.getState().patchTab(tabId, { connected: true });
      } catch {
        useApp.getState().patchTab(tabId, { connected: false });
      }
    },
    [addTab]
  );

  const closeTab = useCallback(
    (id: string) => {
      const sid = sessions[id];
      if (sid) {
        ipc.disconnect(sid).catch(() => {});
        outputs.delete(sid);
        closed.delete(sid);
      }
      removeTab(id);
    },
    [sessions, removeTab]
  );

  const visible = useMemo(
    () => hosts.filter((h) => (h.label + h.hostname + h.username).toLowerCase().includes(filter.toLowerCase())),
    [hosts, filter]
  );

  return (
    <div className="app">
      <aside className={`sidebar${sidebarOpen ? "" : " collapsed"}`}>
        <div className="sidebar-head">
          <span className="logo"><Icon.Terminal /></span>
          <span className="brand">RINA</span>
          <span style={{ flex: 1 }} />
          <button
            className="icon-btn"
            title={hasVault ? (vaultLocked ? "Vault locked" : "Vault unlocked — click to lock") : "Create vault"}
            onClick={() => {
              if (!hasVault) setDialog({ kind: "vault-create", recoveryKey: "" });
              else if (vaultLocked) setDialog({ kind: "vault-unlock" });
              else ipc.vaultLock();
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="5" y="11" width="14" height="10" rx="2" />
              <path d="M8 11V7a4 4 0 018 0v4" />
              {hasVault && !vaultLocked && <path d="M12 15v2" />}
            </svg>
          </button>
          <button className="icon-btn" title="New host"
                  onClick={() => setDialog({ kind: "host", host: null })}>
            <Icon.Plus />
          </button>
        </div>
        {sidebarOpen && (
          <>
            <div style={{ position: "relative" }}>
              <span style={{ position: "absolute", left: 18, top: 17, color: "#8b949e" }}><Icon.Search /></span>
              <input
                className="sidebar-search"
                style={{ paddingLeft: 30, width: "calc(100% - 16px)" }}
                placeholder="Search hosts"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </div>
            <ul className="host-list">
              {visible.map((h) => (
                <li key={h.id} className="host-item" onDoubleClick={() => openHost(h.id, h.label)}>
                  <span className="dot" />
                  <span className="host-label">{h.label}</span>
                  <span className="host-meta">{h.username}@{h.hostname}</span>
                  <button className="host-act" title="Edit host"
                          onClick={(e) => { e.stopPropagation(); setDialog({ kind: "host", host: h }); }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17 3l4 4L8 20l-5 1 1-5z" />
                    </svg>
                  </button>
                  <button className="host-act danger" title="Delete host"
                          onClick={(e) => { e.stopPropagation(); setDialog({
                            kind: "confirm", title: "Delete host",
                            message: `Delete host "${h.label}"? This cannot be undone.`,
                            onOk: () => { ipc.hostDelete(h.id).then((ok) => {
                              if (ok) { useApp.getState().setHosts(useApp.getState().hosts.filter((x) => x.id !== h.id)); toast("Host deleted", "success"); }
                            }); },
                          }); }}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" />
                    </svg>
                  </button>
                </li>
              ))}
              {visible.length === 0 && (
                <li style={{ padding: 12, color: "#8b949e", fontSize: 12 }}>No hosts saved yet.</li>
              )}
            </ul>
          </>
        )}
      </aside>

      <div className="main">
        <div className="tabbar">
          <button className="icon-btn" title="Toggle sidebar" onClick={toggleSidebar}><Icon.Menu /></button>
          {tabs.map((t) => (
            <div
              key={t.id}
              className={`tab${t.id === activeTab ? " active" : ""}`}
              onClick={() => setActiveTab(t.id)}
            >
              <span className="dot" style={{ background: t.connected ? "#3fb950" : "#484f58" }} />
              <span className="tab-title">{t.title}</span>
              <button className="tab-close" onClick={(e) => { e.stopPropagation(); closeTab(t.id); }}>
                <Icon.Close />
              </button>
            </div>
          ))}
          <button
            className={`tab-new${sftpOpen ? " on" : ""}`}
            title={sftpOpen ? "Close SFTP browser" : "Open SFTP browser"}
            onClick={toggleSftp}
          >
            <UIIcon.Folder />
          </button>
          <button
            className="tab-new"
            title="New tab"
            onClick={() => addTab({ id: newId(), hostId: null, title: "shell", connected: false })}
          >
            <Icon.Plus />
          </button>
        </div>

        <div className="workspace">
          <div className="terminals">
            {tabs.length === 0 ? (
              <div className="empty">
                <span style={{ color: "#8b949e" }}><Icon.Terminal /></span>
                <span className="empty-title">No open sessions</span>
                <span className="empty-sub">Double-click a host in the sidebar to connect.</span>
              </div>
            ) : (
              tabs.map((t) => (
                <div key={t.id} className={`term-pane${t.id === activeTab ? " active" : ""}`}>
                  <TermView
                    onData={(d) => {
                      const sid = sessions[t.id];
                      if (sid) ipc.write(sid, d).catch(() => {});
                    }}
                    onResize={(cols, rows) => {
                      const sid = sessions[t.id];
                      if (sid) ipc.resize(sid, cols, rows).catch(() => {});
                    }}
                    onOutput={(cb) => outputs.set(t.id, cb)}
                    onClosed={(cb) => closed.set(t.id, cb)}
                  />
                </div>
              ))
            )}
          </div>
          {sftpOpen && (
            <div className="sftp-pane">
              <SftpPanel sessionId={activeTab ? sessions[activeTab] ?? null : null} />
            </div>
          )}
        </div>
      </div>
      <Dialogs />
      <Toasts />
    </div>
  );
}

// Keep a stable type import so TS doesn't elide the Tab type in emitted code.
export type { Tab };
