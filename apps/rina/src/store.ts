import { create } from "zustand";

export interface Host {
  id: string;
  label: string;
  hostname: string;
  port: number;
  username: string;
  group_id: string | null;
  tags: string[];
}

export interface Tab {
  id: string;
  hostId: string | null;
  title: string;
  connected: boolean;
}

interface AppState {
  hosts: Host[];
  tabs: Tab[];
  activeTab: string | null;
  sidebarOpen: boolean;
  setHosts: (h: Host[]) => void;
  addTab: (t: Tab) => void;
  removeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  patchTab: (id: string, p: Partial<Tab>) => void;
  toggleSidebar: () => void;
}

export const useApp = create<AppState>((set) => ({
  hosts: [],
  tabs: [],
  activeTab: null,
  sidebarOpen: true,
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
}));
