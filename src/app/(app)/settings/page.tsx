"use client";

import { Database, KeyRound, ShieldCheck, User, Zap } from "lucide-react";
import { useState } from "react";
import { useLive } from "@/components/live";
import { deniedHint, useSession } from "@/components/session";
import { Button, ErrorState, Field, Input, KV, PageHeader, Panel, useToast } from "@/components/ui";
import { ApiError, api, cx, fmtCompact } from "@/lib/client";
import { PERMISSIONS, ROLE_LABEL, can as roleCan, type Permission } from "@/lib/rbac";

export default function SettingsPage() {
  const { user, db, can } = useSession();
  const { metrics } = useLive();
  const sim = metrics?.simulator;
  const toast = useToast();
  const control = can("simulator:control");

  const setSim = async (json: Record<string, unknown>, msg: string) => {
    try { await api("/api/simulator", { method: "POST", json }); toast({ tone: "success", title: msg }); }
    catch (e) { toast({ tone: "error", title: "Simulator update failed", body: (e as Error).message }); }
  };

  return (
    <div className="max-w-5xl">
      <PageHeader title="Settings" subtitle="Your profile and credentials, plus tenant-level simulator configuration." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title={<span className="flex items-center gap-1.5"><User className="h-3.5 w-3.5" />Profile</span>}>
          <KV k="name" v={user.name} mono={false} />
          <KV k="email" v={user.email} />
          <KV k="role" v={ROLE_LABEL[user.role]} mono={false} />
          <KV k="organization" v={`${user.orgName} (${user.orgSlug})`} mono={false} />
          <KV k="tenant mode" v={user.demo ? "Demo — simulated infrastructure" : "Live"} mono={false} />
          <p className="mt-3 text-[11.5px] text-ink-3">Name, email and role are managed by your organization’s administrators.</p>
        </Panel>

        <PasswordPanel />

        <Panel title={<span className="flex items-center gap-1.5"><Zap className="h-3.5 w-3.5" />Event simulator</span>} subtitle="Per-organization; persisted across restarts">
          {!sim ? <div className="text-[12px] text-ink-3">Waiting for live metrics…</div> : (
            <div className="space-y-3">
              {!control && <p className="rounded-md border border-line bg-base/60 px-2.5 py-1.5 text-[11.5px] text-ink-3">{deniedHint("simulator:control")} to change these settings.</p>}
              <div className="flex items-center justify-between text-[13px]">
                <span className="text-ink-2">Background generation</span>
                <Button size="sm" variant={sim.running ? "outline" : "primary"} disabled={!control} onClick={() => setSim({ action: sim.running ? "stop" : "start" }, sim.running ? "Simulator paused" : "Simulator started")}>{sim.running ? "Pause" : "Start"}</Button>
              </div>
              <label className="block text-[12px] text-ink-3">Rate: <span className="text-ink tnum">{sim.rate} events/s</span>
                <input type="range" min={5} max={300} step={5} defaultValue={sim.rate} disabled={!control} className="mt-1 w-full accent-emerald"
                  onMouseUp={(e) => setSim({ action: "config", rate: Number((e.target as HTMLInputElement).value) }, "Rate updated")}
                  onKeyUp={(e) => setSim({ action: "config", rate: Number((e.target as HTMLInputElement).value) }, "Rate updated")} />
              </label>
              <label className="flex items-center justify-between text-[13px] text-ink-2">
                <span>Launch random attack scenarios automatically</span>
                <input type="checkbox" className="accent-emerald" disabled={!control} checked={sim.autoScenarios} onChange={(e) => setSim({ action: "config", autoScenarios: e.target.checked }, e.target.checked ? "Auto scenarios on" : "Auto scenarios off")} />
              </label>
              <div className="text-[11.5px] text-ink-3">{fmtCompact(sim.generated)} simulated events generated since boot. Simulated data is always labelled SIM.</div>
            </div>
          )}
        </Panel>

        <Panel title={<span className="flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5" />Your permissions</span>} subtitle={ROLE_LABEL[user.role]}>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px]">
            {(Object.keys(PERMISSIONS) as Permission[]).map((p) => {
              const ok = roleCan(user.role, p);
              return <li key={p} className={cx("flex items-center gap-1.5 font-mono", ok ? "text-ink-2" : "text-ink-3/50 line-through")}><span className={cx("h-1.5 w-1.5 rounded-full", ok ? "bg-emerald" : "bg-line-strong")} />{p}</li>;
            })}
          </ul>
          <div className="mt-4 flex items-center gap-1.5 text-[11.5px] text-ink-3"><Database className="h-3.5 w-3.5" />Storage: {db === "pglite" ? "PGlite — embedded PostgreSQL (set DATABASE_URL for a PostgreSQL server)" : "PostgreSQL server"}</div>
        </Panel>
      </div>
    </div>
  );
}

function PasswordPanel() {
  const toast = useToast();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const mismatch = f.confirm.length > 0 && f.next !== f.confirm;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await api("/api/auth/password", { method: "POST", json: { current: f.current, next: f.next } });
      toast({ tone: "success", title: "Password changed", body: "All other sessions were signed out" });
      setF({ current: "", next: "", confirm: "" });
    } catch (x) {
      const issue = (((x as ApiError).data as { issues?: { path: string; message: string }[] })?.issues ?? [])[0]?.message;
      setErr(issue ?? (x as Error).message);
    } finally { setBusy(false); }
  };
  return (
    <Panel title={<span className="flex items-center gap-1.5"><KeyRound className="h-3.5 w-3.5" />Change password</span>} subtitle="Signs out your other sessions">
      <form onSubmit={submit} className="space-y-3">
        <Field label="Current password"><Input type="password" autoComplete="current-password" required value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} /></Field>
        <Field label="New password" hint="At least 10 characters with letters and digits."><Input type="password" autoComplete="new-password" required value={f.next} onChange={(e) => setF({ ...f, next: e.target.value })} /></Field>
        <Field label="Confirm new password" error={mismatch ? "Passwords do not match" : null}><Input type="password" autoComplete="new-password" required value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></Field>
        {err && <ErrorState message={err} />}
        <Button type="submit" variant="primary" loading={busy} disabled={!f.current || !f.next || mismatch}>Update password</Button>
      </form>
    </Panel>
  );
}
