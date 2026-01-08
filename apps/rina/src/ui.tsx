import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useApp, type Host, type AuthKind, type DirEntry, type Snippet, type Forward } from "./store";
import * as ipc from "./ipc";

// ---- inline SVG icons (no icon font, no emoji) ----
const S = (p: { d: string | string[]; size?: number }) => (
  <svg width={p.size ?? 16} height={p.size ?? 16} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {(Array.isArray(p.d) ? p.d : [p.d]).map((d, i) => <path key={i} d={d} />)}
  </svg>
);
export const Icon = {
  Plus: () => <S d="M12 5v14M5 12h14" />,
  Close: (p: { size?: number }) => <S size={p.size} d="M18 6L6 18M6 6l12 12" />,
  Edit: () => <S d="M17 3l4 4L8 20l-5 1 1-5z" />,
  Trash: () => <S d={["M3 6h18", "M8 6V4h8v2", "M6 6l1 14h10l1-14"]} />,
  Folder: () => <S d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />,
  Back: () => <S d={["M19 12H5", "M12 19l-7-7 7-7"]} />,
  File: () => <S d={["M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z", "M14 3v5h5"]} />,
  Link: () => <S d={["M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1.5 1.5", "M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1.5-1.5"]} />,
  Down: () => <S d={["M12 3v12", "M7 11l5 5 5-5", "M4 21h16"]} />,
  Up: () => <S d={["M12 21V9", "M7 13l5-5 5 5", "M4 3h16"]} />,
  Rename: () => <S d={["M4 7V4h16v3", "M9 20h6", "M12 4v16"]} />,
  Lock: () => <S d={["M5 11h14v10H5z", "M8 11V7a4 4 0 018 0v4"]} />,
  Check: () => <S d="M4 12l5 5L20 6" />,
  Refresh: () => <S d={["M21 12a9 9 0 11-3-6.7", "M21 3v6h-6"]} />,
  Bolt: () => <S d="M13 2L4 14h7l-1 8 9-12h-7z" />,
  Upload: () => <S d={["M12 16V4", "M7 9l5-5 5 5", "M4 17v3h16v-3"]} />,
  Globe: () => <S d={["M12 3a9 9 0 100 18 9 9 0 000-18z", "M3 12h18", "M12 3c3 3 3 15 0 18", "M12 3c-3 3-3 15 0 18"]} />,
  ChevronDown: () => <S d={["M6 9l6 6 6-6"]} />,
};

// ---- generic modal shell ----
export function Modal(props: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  footer?: React.ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") props.onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props.onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) props.onClose(); }}>
      <div className={`modal${props.wide ? " wide" : ""}`} role="dialog" aria-label={props.title}>
        <div className="modal-head">
          <span className="modal-title">{props.title}</span>
          <button className="icon-btn" onClick={props.onClose} aria-label="Close"><Icon.Close /></button>
        </div>
        <div className="modal-body">{props.children}</div>
        {props.footer && <div className="modal-foot">{props.footer}</div>}
      </div>
    </div>
  );
}

// ---- confirm dialog ----
function ConfirmDialog() {
  const dialog = useApp((s) => s.dialog);
  const setDialog = useApp((s) => s.setDialog);
  if (!dialog || dialog.kind !== "confirm") return null;
  const close = () => setDialog(null);
  return (
    <Modal title={dialog.title} onClose={close}
      footer={
        <>
          <button className="btn" onClick={close}>Cancel</button>
          <button className="btn danger" onClick={() => { close(); dialog.onOk(); }}>Delete</button>
        </>
      }>
      <p className="confirm-msg">{dialog.message}</p>
    </Modal>
  );
}

// ---- host create/edit dialog ----
function HostDialog() {
  const dialog = useApp((s) => s.dialog);
  const setDialog = useApp((s) => s.setDialog);
  const toast = useApp((s) => s.toast);
  const [form, setForm] = useState(() => {
    const h = dialog?.kind === "host" ? dialog.host : null;
    return {
      id: h?.id ?? null,
      label: h?.label ?? "",
      hostname: h?.hostname ?? "",
      port: String(h?.port ?? 22),
      username: h?.username ?? "root",
      groupId: h?.group_id ?? "",
      tags: (h?.tags ?? []).join(", "),
      authKind: (h?.auth_kind ?? "password") as AuthKind,
      secret: "",
      passphrase: "",
    };
  });
  if (!dialog || dialog.kind !== "host") return null;
  const edit = form.id != null;
  const set = <K extends keyof typeof form>(k: K, v: string) => setForm((f) => ({ ...f, [k]: v }));
  const close = () => setDialog(null);

  const submit = async () => {
    if (!form.label.trim() || !form.hostname.trim()) { toast("Label and hostname are required", "error"); return; }
    const port = Number(form.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) { toast("Port must be 1-65535", "error"); return; }
    const saved = await ipc.hostSave({
      id: form.id,
      label: form.label.trim(),
      hostname: form.hostname.trim(),
      port,
      username: form.username.trim(),
      groupId: form.groupId.trim() || null,
      tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
      authKind: form.authKind,
      secret: form.secret,
      passphrase: form.passphrase,
    });
    if (saved === null) return; // toast already shown
    const hosts = await ipc.listHosts();
    useApp.getState().setHosts(hosts);
    toast(edit ? "Host updated" : "Host created", "success");
    close();
  };

  return (
    <Modal title={edit ? "Edit host" : "New host"} onClose={close}
      footer={
        <>
          <button className="btn" onClick={close}>Cancel</button>
          <button className="btn primary" onClick={submit}><Icon.Check /> Save</button>
        </>
      }>
      <div className="form-grid">
        <label>Label<input value={form.label} onChange={(e) => set("label", e.target.value)} placeholder="web-1" autoFocus /></label>
        <label>Hostname<input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} placeholder="203.0.113.10" /></label>
        <label>Port<input value={form.port} onChange={(e) => set("port", e.target.value)} inputMode="numeric" /></label>
        <label>Username<input value={form.username} onChange={(e) => set("username", e.target.value)} /></label>
        <label>Group<input value={form.groupId} onChange={(e) => set("groupId", e.target.value)} placeholder="prod (optional)" /></label>
        <label>Tags<input value={form.tags} onChange={(e) => set("tags", e.target.value)} placeholder="web, staging" /></label>
        <label>Auth
          <select value={form.authKind} onChange={(e) => set("authKind", e.target.value)}>
            <option value="password">Password</option>
            <option value="private_key">Private key</option>
            <option value="agent">Agent</option>
          </select>
        </label>
        {form.authKind === "password" && (
          <label className="span2">Password
            <input type="password" value={form.secret} onChange={(e) => set("secret", e.target.value)}
                   placeholder={edit ? "(unchanged)" : "password"} />
          </label>
        )}
        {form.authKind === "private_key" && (
          <>
            <label className="span2">Private key (PEM)
              <textarea rows={5} value={form.secret} onChange={(e) => set("secret", e.target.value)}
                        placeholder={edit ? "(unchanged)" : "-----BEGIN OPENSSH PRIVATE KEY-----"} />
            </label>
            <label className="span2">Key passphrase
              <input type="password" value={form.passphrase} onChange={(e) => set("passphrase", e.target.value)}
                     placeholder="(optional)" />
            </label>
          </>
        )}
        {form.authKind === "agent" && (
          <p className="form-hint span2">Uses the local SSH agent. No secret stored.</p>
        )}
      </div>
    </Modal>
  );
}

// ---- vault unlock / create ----
function VaultDialog() {
  const dialog = useApp((s) => s.dialog);
  const setDialog = useApp((s) => s.setDialog);
  const toast = useApp((s) => s.toast);
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const create = dialog?.kind === "vault-create";
  const recovery = create ? (dialog as { recoveryKey: string }).recoveryKey : "";
  if (!dialog || (dialog.kind !== "vault-create" && dialog.kind !== "vault-unlock")) return null;
  const close = () => setDialog(null);

  const submit = async () => {
    if (!pw) { toast("Enter a passphrase", "error"); return; }
    setBusy(true);
    if (create) {
      const key = await ipc.vaultCreate(pw);
      setBusy(false);
      if (key === null) return;
      setDialog({ kind: "vault-create", recoveryKey: key });
    } else {
      const ok = await ipc.vaultUnlock(pw);
      setBusy(false);
      if (ok) { toast("Vault unlocked", "success"); close(); }
    }
  };

  // Once a recovery key exists, show only that screen.
  if (create && recovery) {
    return (
      <Modal title="Vault created" onClose={close} wide
        footer={<button className="btn primary" onClick={close}><Icon.Check /> Done</button>}>
        <p className="confirm-msg">Store this recovery key now. It is shown only once and cannot be recovered.</p>
        <div className="recovery">
          <code>{recovery}</code>
          <button className="btn" onClick={() => {
            navigator.clipboard?.writeText(recovery);
            setCopied(true);
          }}>{copied ? "Copied" : "Copy"}</button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={create ? "Create vault" : "Vault locked"} onClose={create ? close : () => {}} wide
      footer={
        <>
          {create && <button className="btn" onClick={close}>Cancel</button>}
          <button className="btn primary" onClick={submit} disabled={busy}>
            {create ? "Create" : "Unlock"}
          </button>
        </>
      }>
      <p className="confirm-msg">
        {create
          ? "Choose a passphrase to encrypt stored secrets on this device."
          : "Enter the vault passphrase to use saved credentials."}
      </p>
      <div className="form-grid">
        <label className="span2">Passphrase
          <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus
                 onKeyDown={(e) => { if (e.key === "Enter") submit(); }} />
        </label>
      </div>
    </Modal>
  );
}

export function Dialogs() {
  return (
    <>
      <ConfirmDialog />
      <HostDialog />
      <VaultDialog />
      <BackendDialog />
      <SshImportDialog />
    </>
  );
}

// ---- custom replacement for native Tauri dialogs ----
// Backend emits dialog-confirm { token, title, message, danger } and
// dialog-prompt { token, title, message, kind }. Frontend renders a Modal and
// invokes dialog_resolve with the answer; each event has its own token so
// concurrent prompts don't collide.
type BackendPrompt =
  | { token: string; title: string; message: string; danger: boolean; kind: "confirm"; placeholder?: undefined; secret?: undefined }
  | { token: string; title: string; message: string; danger: false; kind: "prompt"; placeholder?: string; secret?: boolean }
  | null;

function BackendDialog() {
  const [queue, setQueue] = useState<NonNullable<BackendPrompt>[]>([]);
  const [value, setValue] = useState("");
  const waiters = useRef(new Map<string, (answer: string) => void>());

  useEffect(() => {
    // Each event registers a promise keyed by token; answering resolves it,
    // which sends dialog_resolve only for that token.
    const enqueue = (p: NonNullable<BackendPrompt>) => {
      const done = new Promise<string>((resolve) => { waiters.current.set(p.token, resolve); });
      done
        .then((answer) => { ipc.dialogResolve(p.token, answer).catch(() => {}); })
        .finally(() => { waiters.current.delete(p.token); });
      setQueue((q) => [...q, p]);
    };
    let unConfirm: (() => void) | undefined, unPrompt: (() => void) | undefined;
    listen<{ token: string; title: string; message: string; danger?: boolean }>(
      "dialog-confirm",
      (e) => enqueue({ ...e.payload, danger: e.payload.danger === true, kind: "confirm" }),
    ).then((u) => (unConfirm = u));
    listen<{ token: string; title: string; message: string; kind: string }>(
      "dialog-prompt",
      (e) => enqueue({ ...e.payload, danger: false, kind: "prompt" }),
    ).then((u) => (unPrompt = u));
    return () => { unConfirm?.(); unPrompt?.(); };
  }, []);

  const prompt = queue[0] ?? null;
  if (!prompt) return null;
  const answer = (v: string) => {
    waiters.current.get(prompt.token)?.(v);
    setQueue((q) => q.slice(1));
    setValue("");
  };

  return (
    <Modal title={prompt.title} onClose={() => answer("")}
      footer={
        <>
          <button className="btn" onClick={() => answer("")}>Cancel</button>
          {prompt.kind === "confirm" ? (
            <button className={prompt.danger ? "btn danger" : "btn primary"} onClick={() => answer("yes")}>OK</button>
          ) : (
            <button className="btn primary" onClick={() => answer(value)}><Icon.Check /> OK</button>
          )}
        </>
      }>
      <p className="confirm-msg">{prompt.message}</p>
      {prompt.kind === "prompt" && (
        <div className="form-grid" style={{ marginTop: 12 }}>
          <label className="span2">
            <input
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") answer(value); }}
              placeholder={prompt.placeholder ?? ""}
            />
          </label>
        </div>
      )}
    </Modal>
  );
}

// ---- SSH config import (sidebar footer button) ----
function SshImportDialog() {
  const dialog = useApp((s) => s.dialog);
  const setDialog = useApp((s) => s.setDialog);
  const toast = useApp((s) => s.toast);
  const [path, setPath] = useState("~/.ssh/config");
  if (!dialog || dialog.kind !== "ssh-import") return null;
  const close = () => setDialog(null);

  const submit = async () => {
    const p = path.trim();
    if (!p) { toast("Enter a config path", "error"); return; }
    const hosts = await ipc.sshConfigImport(p);
    if (hosts.length === 0) { toast("No hosts found", "info"); close(); return; }
    const existing = useApp.getState().hosts;
    const byId = new Map(existing.map((h) => [h.id, h]));
    for (const h of hosts) byId.set(h.id, h);
    useApp.getState().setHosts([...byId.values()]);
    toast(`Imported ${hosts.length} host${hosts.length === 1 ? "" : "s"}`, "success");
    close();
  };

  return (
    <Modal title="Import SSH config" onClose={close}
      footer={
        <>
          <button className="btn" onClick={close}>Cancel</button>
          <button className="btn primary" onClick={submit}><Icon.Check /> Import</button>
        </>
      }>
      <div className="form-grid">
        <label className="span2">Config path
          <input value={path} autoFocus onChange={(e) => setPath(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
                 placeholder="~/.ssh/config" />
        </label>
      </div>
    </Modal>
  );
}

// ---- toast stack ----
export function Toasts() {
  const toasts = useApp((s) => s.toasts);
  const dismiss = useApp((s) => s.dismissToast);
  return (
    <div className="toast-stack" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          <span className="toast-msg">{t.message}</span>
          <button className="toast-close" onClick={() => dismiss(t.id)} aria-label="Dismiss"><Icon.Close size={12} /></button>
        </div>
      ))}
    </div>
  );
}

// ---- SFTP browser panel ----
function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

const joinPath = (base: string, name: string) => (base.endsWith("/") ? base + name : base + "/" + name);
const parentPath = (p: string) => { const i = p.replace(/\/+$/, "").lastIndexOf("/"); return i <= 0 ? "/" : p.slice(0, i); };

export function SftpPanel({ sessionId }: { sessionId: string | null }) {
  const sftp = useApp((s) => s.sftp);
  const setSftp = useApp((s) => s.setSftp);
  const toast = useApp((s) => s.toast);
  const setDialog = useApp((s) => s.setDialog);
  const [prompt, setPrompt] = useState<{ mode: "mkdir" | "rename" | "chmod"; path: string; value: string } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const crumbs = useMemo(
    () => sftp.path.split("/").filter(Boolean).map((seg, i, all) => ({ name: seg, path: "/" + all.slice(0, i + 1).join("/") })),
    [sftp.path],
  );

  const list = (path: string) => {
    setSftp({ loading: true, path });
    ipc.sftpList(sessionId ?? "", path).then((entries) => {
      const sorted = [...entries].sort((a, b) =>
        a.is_dir === b.is_dir ? a.name.localeCompare(b.name) : a.is_dir ? -1 : 1);
      setSftp({ entries: sorted, loading: false, selected: null });
    });
  };
  const refresh = () => list(sftp.path);

  // Load on first open / session change.
  const loadedKey = useRef<string | null>(null);
  useEffect(() => {
    if (!sftp.open || !sessionId) return;
    if (loadedKey.current === sessionId) return;
    loadedKey.current = sessionId;
    list(sftp.path);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sftp.open, sessionId]);

  useEffect(() => {
    if (sftp.open && !sessionId) toast("Connect to a host to browse files", "error");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sftp.open, sessionId]);

  const selPath = sftp.selected ? joinPath(sftp.path, sftp.selected) : null;

  const runPrompt = async () => {
    if (!prompt) return;
    const { mode, path, value } = prompt;
    setPrompt(null);
    if (!value.trim()) return;
    if (mode === "mkdir") await ipc.sftpMkdir(sessionId ?? "", joinPath(sftp.path, value.trim()));
    else if (mode === "rename") await ipc.sftpRename(sessionId ?? "", path, joinPath(sftp.path, value.trim()));
    else if (mode === "chmod") await ipc.sftpChmod(sessionId ?? "", path, value.trim());
    refresh();
  };

  const onUpload = async (files: FileList | null) => {
    if (!files || !files.length) return;
    // Electron/Tauri webview exposes File.path for picked files.
    for (const f of Array.from(files)) {
      await ipc.sftpUpload(sessionId ?? "", joinPath(sftp.path, f.name), f);
    }
    refresh();
  };

  return (
    <div className="sftp">
      <div className="sftp-bar">
        <button className="icon-btn" title="Up" onClick={() => list(parentPath(sftp.path))} disabled={!sessionId}><Icon.Back /></button>
        <div className="crumbs">
          <button className="crumb" onClick={() => list("/")}>/</button>
          {crumbs.map((c, i) => (
            <span key={c.path} className="crumb-wrap">
              <button className="crumb" onClick={() => list(c.path)}>{c.name}</button>
              {i < crumbs.length - 1 && <span className="crumb-sep">/</span>}
            </span>
          ))}
        </div>
        <button className="icon-btn" title="Refresh" onClick={refresh} disabled={!sessionId}><Icon.Refresh /></button>
        <span className="sftp-sep" />
        <button className="icon-btn" title="New folder" onClick={() => setPrompt({ mode: "mkdir", path: "", value: "" })} disabled={!sessionId}><Icon.Plus /></button>
        <button className="icon-btn" title="Upload" onClick={() => fileRef.current?.click()} disabled={!sessionId}><Icon.Up /></button>
        <button className="icon-btn" title="Download" onClick={() => { if (selPath) ipc.sftpDownload(sessionId ?? "", selPath).then(refresh); }} disabled={!selPath}><Icon.Down /></button>
        <button className="icon-btn" title="Rename"
                onClick={() => selPath && setPrompt({ mode: "rename", path: selPath, value: sftp.selected ?? "" })} disabled={!selPath}><Icon.Rename /></button>
        <button className="icon-btn" title="Permissions"
                onClick={() => selPath && setPrompt({ mode: "chmod", path: selPath, value: "0644" })} disabled={!selPath}><Icon.Lock /></button>
        <button className="icon-btn danger" title="Delete"
                onClick={() => selPath && setDialog({
                  kind: "confirm", title: "Delete remote item",
                  message: `Delete "${sftp.selected}"? This cannot be undone.`,
                  onOk: () => {
                // sftpDeleteDir handles folders, sftpDelete handles files.
                const isDir = (sftp.entries.find((e) => e.name === sftp.selected)?.is_dir) ?? false;
                const del = isDir ? ipc.sftpDeleteDir : ipc.sftpDelete;
                del(sessionId ?? "", selPath!).then(refresh);
              },
                })} disabled={!selPath}><Icon.Trash /></button>
        <input ref={fileRef} type="file" multiple hidden onChange={(e) => { onUpload(e.target.files); e.target.value = ""; }} />
      </div>

      <div className="sftp-head">
        <span>Name</span><span>Type</span><span className="num">Size</span>
      </div>
      <div className="sftp-list">
        {!sessionId ? (
          <div className="sftp-empty">No connected session.</div>
        ) : sftp.loading ? (
          <div className="sftp-empty">Loading…</div>
        ) : sftp.entries.length === 0 ? (
          <div className="sftp-empty">Empty directory.</div>
        ) : (
          sftp.entries.map((e) => <Row key={e.name} e={e} path={sftp.path}
            selected={sftp.selected === e.name}
            onSelect={() => setSftp({ selected: e.name })}
            onOpen={() => e.is_dir && list(joinPath(sftp.path, e.name))} />)
        )}
      </div>

      {prompt && (
        <Modal title={prompt.mode === "mkdir" ? "New folder" : prompt.mode === "rename" ? "Rename" : "Change permissions"}
               onClose={() => setPrompt(null)}
               footer={
                 <>
                   <button className="btn" onClick={() => setPrompt(null)}>Cancel</button>
                   <button className="btn primary" onClick={runPrompt}><Icon.Check /> Apply</button>
                 </>
               }>
          <div className="form-grid">
            <label className="span2">
              {prompt.mode === "mkdir" ? "Folder name" : prompt.mode === "rename" ? "New name" : "Mode (octal)"}
              <input value={prompt.value} autoFocus
                     onChange={(e) => setPrompt({ ...prompt, value: e.target.value })}
                     onKeyDown={(e) => { if (e.key === "Enter") runPrompt(); }} />
            </label>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ---- snippet runner / command palette (Ctrl+K) ----
export function SnippetPanel({ sessionId }: { sessionId: string | null }) {
  const open = useApp((s) => s.snippetPanelOpen);
  const toggle = useApp((s) => s.toggleSnippetPanel);
  const snippets = useApp((s) => s.snippets);
  const setSnippets = useApp((s) => s.setSnippets);
  const toast = useApp((s) => s.toast);
  const setDialog = useApp((s) => s.setDialog);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Snippet | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newBody, setNewBody] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        toggle();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);

  useEffect(() => {
    if (open) ipc.snippetList().then(setSnippets);
  }, [open, setSnippets]);

  const pick = async (s: Snippet) => {
    setSelected(s);
    // Backend scans placeholders from body; fall back to the stored field.
    const ph = (await ipc.snippetPlaceholders(s.id)) ?? s.placeholders ?? [];
    setValues(Object.fromEntries(ph.map((p) => [p, ""])));
  };

  const run = async () => {
    if (!selected || !sessionId) return;
    const ok = await ipc.snippetRun(sessionId, selected.id, values);
    if (ok) { toast("Snippet sent", "success"); toggle(); }
  };

  const create = async () => {
    if (!newName.trim() || !newBody.trim()) { toast("Name and body required", "error"); return; }
    const ok = await ipc.snippetSave(null, newName.trim(), newBody);
    if (!ok) return;
    ipc.snippetList().then(setSnippets);
    setCreating(false);
    setNewName("");
    setNewBody("");
    toast("Snippet created", "success");
  };

  if (!open) return null;
  const visible = snippets.filter((s) => s.name.toLowerCase().includes(filter.toLowerCase()));

  return (
    <Modal title="Run snippet" onClose={toggle} wide
      footer={
        <>
          {!creating && <button className="btn" onClick={() => setCreating(true)}><Icon.Plus /> New</button>}
          {selected && !creating && (
            <button className="btn primary" onClick={run} disabled={!sessionId}><Icon.Bolt /> Run</button>
          )}
          {creating && (
            <>
              <button className="btn" onClick={() => setCreating(false)}>Cancel</button>
              <button className="btn primary" onClick={create}><Icon.Check /> Save</button>
            </>
          )}
        </>
      }>
      {creating ? (
        <div className="form-grid">
          <label className="span2">Name<input value={newName} autoFocus onChange={(e) => setNewName(e.target.value)} placeholder="deploy status" /></label>
          <label className="span2">Body (use {"{{name}}"} for placeholders)
            <textarea rows={5} value={newBody} onChange={(e) => setNewBody(e.target.value)} placeholder="kubectl get pods -n {{namespace}}" />
          </label>
        </div>
      ) : selected ? (
        <>
          <button className="link-btn" onClick={() => setSelected(null)}>← All snippets</button>
          <p className="confirm-msg" style={{ marginTop: 8 }}>{selected.name}</p>
          {Object.keys(values).length === 0 ? (
            <p className="form-hint">No placeholders.</p>
          ) : (
            <div className="form-grid" style={{ marginTop: 12 }}>
              {Object.keys(values).map((p) => (
                <label key={p}>{p}
                  <input value={values[p] ?? ""} onChange={(e) => setValues((v) => ({ ...v, [p]: e.target.value }))} autoFocus={p === Object.keys(values)[0]} />
                </label>
              ))}
            </div>
          )}
        </>
      ) : (
        <>
          <input className="sidebar-search" style={{ width: "100%" }} placeholder="Filter snippets" value={filter} onChange={(e) => setFilter(e.target.value)} autoFocus />
          <div className="palette-list">
            {visible.length === 0 ? (
              <div className="sftp-empty">
                No snippets yet.
                <div><button className="btn" onClick={() => setCreating(true)}><Icon.Plus /> Create snippet</button></div>
              </div>
            ) : visible.map((s) => (
              <div key={s.id} className="palette-row">
                <button className="palette-pick" onClick={() => pick(s)}>
                  <Icon.Bolt /> <span>{s.name}</span>
                </button>
                <button className="icon-btn danger" title="Delete snippet" onClick={() => {
                  setDialog({
                    kind: "confirm", title: "Delete snippet",
                    message: `Delete snippet "${s.name}"?`,
                    onOk: () => { ipc.snippetDelete(s.id).then(() => ipc.snippetList().then(setSnippets)); },
                  });
                }}><Icon.Trash /></button>
              </div>
            ))}
          </div>
        </>
      )}
    </Modal>
  );
}

// ---- port forwarding ----
export function ForwardDialog({ sessionId, onClose }: { sessionId: string | null; onClose: () => void }) {
  const forwards = useApp((s) => s.forwards);
  const addForward = useApp((s) => s.addForward);
  const removeForward = useApp((s) => s.removeForward);
  const toast = useApp((s) => s.toast);
  const [form, setForm] = useState({ listenPort: "8080", targetHost: "127.0.0.1", targetPort: "80" });
  const active = sessionId ? (forwards[sessionId] ?? []) : [];

  const add = async () => {
    const lp = Number(form.listenPort), tp = Number(form.targetPort);
    if (!sessionId) { toast("No active session", "error"); return; }
    if (![lp, tp].every((n) => Number.isInteger(n) && n >= 1 && n <= 65535)) { toast("Ports must be 1-65535", "error"); return; }
    const ok = await ipc.forwardLocal(sessionId, lp, form.targetHost.trim(), tp);
    if (!ok) return;
    addForward(sessionId, { listenPort: lp, targetHost: form.targetHost.trim(), targetPort: tp });
    toast("Forward added", "success");
  };

  const stop = async (f: Forward) => {
    if (!sessionId) return;
    const ok = await ipc.forwardStop(sessionId, f.listenPort);
    if (ok) removeForward(sessionId, f.listenPort);
  };

  return (
    <Modal title="Port forwarding" onClose={onClose}
      footer={<button className="btn" onClick={onClose}>Close</button>}>
      <h4 className="section-label">Add local forward</h4>
      <div className="form-grid">
        <label>Listen port<input value={form.listenPort} inputMode="numeric" onChange={(e) => setForm({ ...form, listenPort: e.target.value })} /></label>
        <label>Target host<input value={form.targetHost} onChange={(e) => setForm({ ...form, targetHost: e.target.value })} /></label>
        <label>Target port<input value={form.targetPort} inputMode="numeric" onChange={(e) => setForm({ ...form, targetPort: e.target.value })} /></label>
      </div>
      <div style={{ marginTop: 12, textAlign: "right" }}>
        <button className="btn primary" onClick={add}><Icon.Plus /> Add</button>
      </div>
      <h4 className="section-label" style={{ marginTop: 18 }}>Active forwards</h4>
      {!sessionId ? <p className="form-hint">No active session.</p> : active.length === 0 ? (
        <p className="form-hint">No forwards for this session.</p>
      ) : (
        <div className="palette-list">
          {active.map((f) => (
            <div key={f.listenPort} className="palette-row">
              <span className="palette-pick">:{f.listenPort} → {f.targetHost}:{f.targetPort}</span>
              <button className="icon-btn danger" title="Stop forward" onClick={() => stop(f)}><Icon.Close size={14} /></button>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

function Row({ e, path, selected, onSelect, onOpen }: {
  e: DirEntry; path: string; selected: boolean; onSelect: () => void; onOpen: () => void;
}) {
  const full = joinPath(path, e.name);
  return (
    <div className={`sftp-row${selected ? " sel" : ""}`} onClick={onSelect} onDoubleClick={onOpen}>
      <span className="sftp-name" title={full}>
        <span className="sftp-kind">{e.is_symlink ? <Icon.Link /> : e.is_dir ? <Icon.Folder /> : <Icon.File />}</span>
        {e.name}
      </span>
      <span className="sftp-type">{e.is_symlink ? "link" : e.is_dir ? "dir" : "file"}</span>
      <span className="sftp-size num">{e.is_dir ? "" : fmtSize(e.size)}</span>
    </div>
  );
}
