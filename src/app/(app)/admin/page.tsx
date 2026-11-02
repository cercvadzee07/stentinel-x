"use client";

import { Copy, KeyRound, Lock, Plus, RefreshCw, ScrollText, Unlock, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Forbidden, useSession } from "@/components/session";
import { Button, Empty, ErrorState, Field, Input, Modal, PageHeader, Panel, Select, Skeleton, Tabs, Tag, useConfirm, useToast } from "@/components/ui";
import { ApiError, api, cx, fmtDateTime, relTime } from "@/lib/client";
import { ROLES, ROLE_LABEL, type Role } from "@/lib/rbac";

interface UserRow { id: string; email: string; name: string; role: Role; disabled: boolean; lastLoginAt: number | null; createdAt: number; locked: boolean }
interface KeyRow { id: string; name: string; prefix: string; createdBy: string | null; createdAt: number; lastUsedAt: number | null; revokedAt: number | null }
interface AuditRow { id: number; actor: string; action: string; target: string | null; meta: Record<string, unknown> | null; ip: string | null; at: number }

const issuesOf = (e: unknown) => Object.fromEntries((((e as ApiError).data as { issues?: { path: string; message: string }[] })?.issues ?? []).map((i) => [i.path, i.message]));

export default function AdminPage() {
  const { can } = useSession();
  const [tab, setTab] = useState<"users" | "keys" | "audit">("users");
  if (!can("users:manage")) return <Forbidden perm="users:manage" />;
  return (
    <div>
      <PageHeader title="System Administration" subtitle="Users and roles, ingestion API keys, and the audit trail for your organization."
        actions={<Tabs value={tab} onChange={setTab} items={[
          { value: "users", label: <span className="flex items-center gap-1.5"><Users className="h-3.5 w-3.5" />Users</span> },
          { value: "keys", label: <span className="flex items-center gap-1.5"><KeyRound className="h-3.5 w-3.5" />API keys</span> },
          { value: "audit", label: <span className="flex items-center gap-1.5"><ScrollText className="h-3.5 w-3.5" />Audit log</span> },
        ]} />} />
      {tab === "users" && <UsersTab />}
      {tab === "keys" && <KeysTab />}
      {tab === "audit" && <AuditTab />}
    </div>
  );
}

// ── users ──────────────────────────────────────────────────────────────
function UsersTab() {
  const { user: me } = useSession();
  const toast = useToast();
  const confirm = useConfirm();
  const [users, setUsers] = useState<UserRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [resetFor, setResetFor] = useState<UserRow | null>(null);
  const load = useCallback(() => api<UserRow[]>("/api/admin/users").then(setUsers).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const patch = async (u: UserRow, p: Record<string, unknown>, msg: string) => {
    try { await api(`/api/admin/users/${u.id}`, { method: "PATCH", json: p }); toast({ tone: "success", title: msg }); load(); }
    catch (e) { toast({ tone: "error", title: "Update failed", body: (e as Error).message }); load(); }
  };
  const toggleDisabled = async (u: UserRow) => {
    if (!u.disabled && !(await confirm({ title: `Disable ${u.name}?`, body: "They are signed out everywhere and cannot sign in until re-enabled.", confirmLabel: "Disable account", danger: true }))) return;
    patch(u, { disabled: !u.disabled }, u.disabled ? `${u.name} re-enabled` : `${u.name} disabled and signed out`);
  };

  return (
    <>
      {err && <ErrorState message={err} onRetry={load} />}
      <Panel bodyClass="p-0" title={users ? `${users.length} users` : "Users"} actions={<Button size="sm" variant="primary" onClick={() => setCreating(true)}><Plus className="h-3.5 w-3.5" />Invite user</Button>}>
        {!users ? <div className="space-y-2 p-4">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div> : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-[12.5px]">
              <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">
                {["User", "Role", "Status", "Last sign-in", "Created", ""].map((h, i) => <th key={i} className="px-3 py-2 font-medium">{h}</th>)}
              </tr></thead>
              <tbody>
                {users.map((u) => {
                  const self = u.id === me.id;
                  return (
                    <tr key={u.id} className={cx("border-b border-line/40", u.disabled && "opacity-50")}>
                      <td className="px-3 py-2"><div className="text-ink">{u.name}{self && <span className="ml-1.5 text-[10.5px] text-emerald">(you)</span>}</div><div className="font-mono text-[11px] text-ink-3">{u.email}</div></td>
                      <td className="px-3">
                        <Select value={u.role} disabled={self} title={self ? "You cannot change your own role" : undefined} aria-label={`Role of ${u.name}`}
                          onChange={(e) => patch(u, { role: e.target.value }, `${u.name} is now ${ROLE_LABEL[e.target.value as Role]} (sessions revoked)`)}>
                          {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                        </Select>
                      </td>
                      <td className="px-3">{u.disabled ? <Tag>disabled</Tag> : u.locked ? <Tag className="text-sev-high">locked out</Tag> : <Tag className="text-emerald">active</Tag>}</td>
                      <td className="px-3 text-ink-2" title={u.lastLoginAt ? fmtDateTime(u.lastLoginAt) : ""}>{u.lastLoginAt ? relTime(u.lastLoginAt) : "never"}</td>
                      <td className="px-3 text-ink-3">{fmtDateTime(u.createdAt)}</td>
                      <td className="px-3 whitespace-nowrap text-right">
                        {u.locked && <Button size="sm" variant="ghost" onClick={() => patch(u, { unlock: true }, `${u.name} unlocked`)}><Unlock className="h-3.5 w-3.5" />Unlock</Button>}
                        <Button size="sm" variant="ghost" onClick={() => setResetFor(u)}><RefreshCw className="h-3.5 w-3.5" />Reset password</Button>
                        {!self && <Button size="sm" variant={u.disabled ? "outline" : "ghost"} onClick={() => toggleDisabled(u)}><Lock className="h-3.5 w-3.5" />{u.disabled ? "Enable" : "Disable"}</Button>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <p className="mt-2 text-[11.5px] text-ink-3">Role changes, disabling and password resets revoke the user’s active sessions immediately. An organization always keeps at least one active administrator.</p>
      {creating && <CreateUser onClose={() => setCreating(false)} onDone={() => { setCreating(false); load(); }} />}
      {resetFor && <ResetPassword user={resetFor} onClose={() => setResetFor(null)} />}
    </>
  );
}

function CreateUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ name: "", email: "", role: "ANALYST" as Role, password: "" });
  const [issues, setIssues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true); setIssues({});
    try { await api("/api/admin/users", { method: "POST", json: f }); toast({ tone: "success", title: `${f.name} added as ${ROLE_LABEL[f.role]}` }); onDone(); }
    catch (e) { setIssues(issuesOf(e)); if (!Object.keys(issuesOf(e)).length) toast({ tone: "error", title: "Could not create user", body: (e as Error).message }); }
    finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title="Invite user" width={480}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={submit}>Create user</Button></>}>
      <div className="space-y-3">
        <Field label="Name" error={issues.name}><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoFocus /></Field>
        <Field label="Email" error={issues.email}><Input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
        <Field label="Role"><Select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</Select></Field>
        <Field label="Initial password" error={issues.password} hint="Share it out of band; the user should change it from Settings."><Input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
      </div>
    </Modal>
  );
}

function ResetPassword({ user, onClose }: { user: UserRow; onClose: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [issue, setIssue] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true); setIssue(null);
    try { await api(`/api/admin/users/${user.id}`, { method: "PATCH", json: { password } }); toast({ tone: "success", title: `Password reset for ${user.name}; their sessions were revoked` }); onClose(); }
    catch (e) { setIssue(issuesOf(e).password ?? (e as Error).message); }
    finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title={`Reset password · ${user.name}`} width={440}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={submit} disabled={!password}>Set password</Button></>}>
      <Field label="New password" error={issue} hint="At least 10 characters with letters and digits."><Input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus /></Field>
    </Modal>
  );
}

// ── API keys ───────────────────────────────────────────────────────────
function KeysTab() {
  const toast = useToast();
  const confirm = useConfirm();
  const [keys, setKeys] = useState<KeyRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<{ key: string; name: string } | null>(null);
  const load = useCallback(() => api<KeyRow[]>("/api/admin/keys").then(setKeys).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    try { const k = await api<{ key: string }>("/api/admin/keys", { method: "POST", json: { name } }); setCreated({ key: k.key, name }); setName(""); load(); }
    catch (e) { toast({ tone: "error", title: "Could not create key", body: (e as Error).message }); }
  };
  const revoke = async (k: KeyRow) => {
    if (!(await confirm({ title: `Revoke “${k.name}”?`, body: "Senders using this key are rejected immediately. This cannot be undone.", confirmLabel: "Revoke key", danger: true }))) return;
    await api(`/api/admin/keys/${k.id}`, { method: "DELETE" });
    toast({ tone: "success", title: "Key revoked" });
    load();
  };
  const origin = typeof window === "undefined" ? "" : window.location.origin;

  return (
    <>
      {err && <ErrorState message={err} onRetry={load} />}
      <Panel className="mb-3" title="Create ingestion key" subtitle="For sensors, log shippers and scripts posting to /api/ingest">
        <div className="flex flex-wrap gap-2">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. suricata-dmz-01" className="w-72" aria-label="Key name" />
          <Button variant="primary" disabled={name.trim().length < 2} onClick={create}><Plus className="h-3.5 w-3.5" />Create key</Button>
        </div>
      </Panel>
      <Panel bodyClass="p-0" title="Keys">
        {!keys ? <div className="space-y-2 p-4"><Skeleton className="h-10" /><Skeleton className="h-10" /></div> : keys.length === 0 ? <Empty icon={<KeyRound className="h-5 w-5" />} title="No API keys" body="Create one to ingest events from external senders." /> : (
          <table className="w-full text-[12.5px]">
            <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Name", "Key", "Created", "Last used", "Status", ""].map((h, i) => <th key={i} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{keys.map((k) => (
              <tr key={k.id} className={cx("border-b border-line/40", k.revokedAt != null && "opacity-50")}>
                <td className="px-3 py-2 text-ink">{k.name}</td>
                <td className="px-3 font-mono text-[11.5px] text-ink-3">sx_{k.prefix}_••••••••</td>
                <td className="px-3 text-ink-2">{fmtDateTime(k.createdAt)}<span className="text-ink-3"> · {k.createdBy}</span></td>
                <td className="px-3 text-ink-2">{k.lastUsedAt ? relTime(k.lastUsedAt) : "never"}</td>
                <td className="px-3">{k.revokedAt ? <Tag>revoked</Tag> : <Tag className="text-emerald">active</Tag>}</td>
                <td className="px-3 text-right">{!k.revokedAt && <Button size="sm" variant="danger" onClick={() => revoke(k)}>Revoke</Button>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Panel>
      <Modal open={!!created} onClose={() => setCreated(null)} title={`API key created · ${created?.name}`} width={600}
        footer={<Button variant="primary" onClick={() => setCreated(null)}>I have stored the key</Button>}>
        <p className="text-[13px] text-sev-medium">Copy it now — it is shown only once. SENTINEL X stores only a SHA-256 hash.</p>
        <div className="mt-3 flex gap-2">
          <code className="flex-1 break-all rounded-lg border border-line bg-void p-2.5 font-mono text-[12px] text-emerald">{created?.key}</code>
          <Button onClick={() => { navigator.clipboard?.writeText(created?.key ?? ""); toast({ tone: "success", title: "Copied to clipboard" }); }} aria-label="Copy key"><Copy className="h-3.5 w-3.5" /></Button>
        </div>
        <div className="mt-4 text-[11px] uppercase tracking-wider text-ink-3">Example</div>
        <pre className="mt-1 overflow-x-auto rounded-lg border border-line bg-void p-2.5 font-mono text-[11px] leading-relaxed text-ink-2">{`curl -X POST ${origin}/api/ingest \\
  -H "Authorization: Bearer <your key>" \\
  -H "Content-Type: application/json" \\
  -d '{"format":"syslog","payload":"<38>1 2026-11-02T12:00:00Z web-01 sshd 42 - - Failed password for root from 192.0.2.7 port 4242 ssh2"}'`}</pre>
      </Modal>
    </>
  );
}

// ── audit ──────────────────────────────────────────────────────────────
const actionTone = (a: string) => (/lockout|failed|delete|revoke|disable|reset/.test(a) ? "text-sev-high" : /login|create/.test(a) ? "text-emerald" : "text-cyan");

function AuditTab() {
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [q, setQ] = useState("");
  const [more, setMore] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(async (before?: number) => {
    try {
      const p = new URLSearchParams({ limit: "100", ...(q ? { q } : {}), ...(before ? { before: String(before) } : {}) });
      const r = await api<AuditRow[]>(`/api/admin/audit?${p}`);
      setRows((cur) => (before && cur ? [...cur, ...r] : r));
      setMore(r.length === 100);
      setErr(null);
    } catch (e) { setErr((e as Error).message); }
  }, [q]);
  useEffect(() => { const t = setTimeout(() => load(), 250); return () => clearTimeout(t); }, [load]);
  return (
    <>
      <Panel bodyClass="p-3" className="mb-3"><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by action, actor or target (e.g. auth.login_failed, rule., admin@)" className="w-full" aria-label="Filter audit log" /></Panel>
      {err && <ErrorState message={err} onRetry={() => load()} />}
      <Panel bodyClass="p-0" title="Audit trail" subtitle="Written server-side for every security-relevant action; no API can edit or delete entries">
        {!rows ? <div className="space-y-2 p-4">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div> : rows.length === 0 ? <Empty title="No matching audit entries" /> : (
          <div className="max-h-[calc(100vh-330px)] overflow-auto scrollbar-thin">
            <table className="w-full text-[12px]">
              <thead className="sticky top-0 bg-panel/95"><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Time", "Actor", "Action", "Target", "Details", "IP"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
              <tbody>{rows.map((r) => (
                <tr key={r.id} className="border-b border-line/40">
                  <td className="px-3 py-1.5 font-mono text-ink-3 whitespace-nowrap">{fmtDateTime(r.at)}</td>
                  <td className="px-3 text-ink-2 whitespace-nowrap">{r.actor}</td>
                  <td className={cx("px-3 font-mono whitespace-nowrap", actionTone(r.action))}>{r.action}</td>
                  <td className="px-3 font-mono text-ink-2">{r.target ?? "—"}</td>
                  <td className="max-w-[340px] truncate px-3 font-mono text-[11px] text-ink-3" title={r.meta ? JSON.stringify(r.meta) : ""}>{r.meta ? JSON.stringify(r.meta) : ""}</td>
                  <td className="px-3 font-mono text-ink-3">{r.ip ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table>
            {more && <div className="p-3 text-center"><Button size="sm" onClick={() => load(rows[rows.length - 1]?.id)}>Load older entries</Button></div>}
          </div>
        )}
      </Panel>
    </>
  );
}
