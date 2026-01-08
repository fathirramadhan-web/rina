import { create } from "zustand";

export type AuthKind = "password" | "private_key" | "agent";

export interface Host {
  id: string;
  label: string;
  hostname: string;
  port: number;
  username: string;
  group_id: string | null;
  tags: string[];
  // Optional auth fields — set when host_save returns them.
  auth_kind?: AuthKind;
  has_secret?: boolean;
}

export interface Tab {
  id: string;
  hostId: string | null;
  title: string;
  connected: boolean;
}

export interface DirEntry {
  name: string;
  is_dir: boolean;
  is_symlink: boolean;
  size: number;
}

export interface Snippet {
  id: string;
  name: string;
  body: string;
  placeholders: string[];
}

export interface Forward {
  listenPort: number;
  targetHost: string;
  targetPort: number;
}

// Which modal is open. Only one at a time.
export type Dialog =
  | { kind: "host"; host: Host | null }
  | { kind: "confirm"; title: string; message: string; onOk: () => void }
  | { kind: "vault-unlock" }
  | { kind: "vault-create"; recoveryKey: string }
  | { kind: "ssh-import" };

export interface Toast {
  id: number;
  message: string;
  kind: "info" | "error" | "success";
}

export interface SftpState {
  open: boolean;
  path: string;
  entries: DirEntry[];
  loading: boolean;
  selected: string | null;
}

interface AppState {
  hosts: Host[];
  tabs: Tab[];
  activeTab: string | null;
  sidebarOpen: boolean;
  dialog: Dialog | null;
  toasts: Toast[];
  vaultLocked: boolean;
  hasVault: boolean;
  sftp: SftpState;
  snippets: Snippet[];
  snippetPanelOpen: boolean;
  forwards: Record<string, Forward[]>; // sessionId -> forwards
  setSnippets: (s: Snippet[]) => void;
  toggleSnippetPanel: () => void;
  addForward: (sessionId: string, f: Forward) => void;
  removeForward: (sessionId: string, listenPort: number) => void;
  setHosts: (h: Host[]) => void;
  addTab: (t: Tab) => void;
  removeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  patchTab: (id: string, p: Partial<Tab>) => void;
  toggleSidebar: () => void;
  setDialog: (d: Dialog | null) => void;
  toast: (message: string, kind?: Toast["kind"]) => void;
  dismissToast: (id: number) => void;
  setVaultLocked: (v: boolean) => void;
  setHasVault: (v: boolean) => void;
  setSftp: (p: Partial<SftpState>) => void;
  toggleSftp: () => void;
}

let toastSeq = 0;

export const useApp = create<AppState>((set) => ({
  hosts: [],
  tabs: [],
  activeTab: null,
  sidebarOpen: true,
  dialog: null,
  toasts: [],
  vaultLocked: false,
  hasVault: false,
  sftp: { open: false, path: "/", entries: [], loading: false, selected: null },
  snippets: [],
  snippetPanelOpen: false,
  forwards: {},
  setSnippets: (snippets) => set({ snippets }),
  toggleSnippetPanel: () => set((s) => ({ snippetPanelOpen: !s.snippetPanelOpen })),
  addForward: (sessionId, f) => set((s) => ({
    forwards: { ...s.forwards, [sessionId]: [...(s.forwards[sessionId] ?? []).filter((x) => x.listenPort !== f.listenPort), f] },
  })),
  removeForward: (sessionId, listenPort) => set((s) => ({
    forwards: { ...s.forwards, [sessionId]: (s.forwards[sessionId] ?? []).filter((x) => x.listenPort !== listenPort) },
  })),
  setHosts: (hosts) => set({ hosts }),
  addTab: (t) => set((s) => ({ tabs: [...s.tabs, t], activeTab: t.id })),
  removeTab: (id) =>
    set((s) => {
      const tabs = s.tabs.filter((t) => t.id !== id);
      return { tabs, activeTab: s.activeTab === id ? tabs[tabs.length - 1]?.id ?? null : s.activeTab };
    }),
  setActiveTab: (activeTab) => set({ activeTab }),
  patchTab: (id, p) =>
    set((s) => ({ tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...p } : t)) })),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  setDialog: (dialog) => set({ dialog }),
  toast: (message, kind = "info") => {
    const id = ++toastSeq;
    set((s) => ({ toasts: [...s.toasts, { id, message, kind }] }));
    setTimeout(() => useApp.getState().dismissToast(id), kind === "error" ? 6000 : 3500);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  setVaultLocked: (vaultLocked) => set({ vaultLocked }),
  setHasVault: (hasVault) => set({ hasVault }),
  setSftp: (p) => set((s) => ({ sftp: { ...s.sftp, ...p } })),
  toggleSftp: () => set((s) => ({ sftp: { ...s.sftp, open: !s.sftp.open } })),
}));

