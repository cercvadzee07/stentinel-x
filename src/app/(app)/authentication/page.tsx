"use client";

import { Globe2, KeyRound, Lock, Search, ShieldAlert, Siren, Terminal, UserX, Users } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { EventDrawer, EventTable } from "@/components/events";
import { deniedHint, useSession } from "@/components/session";
import { CreateIncident, useAnalysts } from "@/components/triage";
import { Button, Drawer, Empty, ErrorState, PageHeader, Panel, Select, SevBadge, Skeleton, Stat, StatusBadge, Tag, useConfirm, useToast } from "@/components/ui";
import { api, cx, fmtCompact, fmtDateTime, fmtNum, fmtTime, relTime } from "@/lib/client";
import { TIME_RANGES } from "@/lib/query";
import type { Alert, AlertStatus, SecurityEvent, Severity } from "@/lib/types";

interface Stats {
  totals: { success: number; failure: number; lockouts: number; ssh: { success: number; failure: number }; rdp: { success: number; failure: number }; other: { success: number; failure: number } };
  series: { t: number; success: number; failure: number }[];
  topFailedUsers: { key: string; value: number }[];
  topFailedSources: { key: string; value: number; external: boolean; country: string | null }[];
  topTargets: { key: string; value: number }[];
  repeated: { user: string; source: string; failures: number; external: boolean }[];
  compromise: { source: string; user: string | null; target: string | null; failures: number; successAt: number; country: string | null }[];
  locations: { source: string; country: string; success: number; failure: number; users: string[]; last: number }[];
  lockouts: { at: number; user: string | null; host: string | null; eventId: string; id: string }[];
  sessions: { user: string; host: string; source: string; since: number; method: string }[];
  tookMs: number;
}
interface Investigation {
  kind: "user" | "source"; value: string; query: string;
  summary: { events: number; failures: number; successes: number; lockouts: number; sources: string[]; users: string[]; targets: string[]; first: number | null; last: number | null };
  findings: { severity: Severity; text: string }[];
  timeline: SecurityEvent[];
  alerts: { id: string; title: string; severity: Severity; status: AlertStatus; ruleName: string; lastSeen: number; incidentId: string | null }[];
}

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><AuthMonitoring /></Suspense>;
}

function AuthMonitoring() {
  const params = useSearchParams();
  const router = useRouter();
  const [range, setRange] = useState("30m");
  const [s, setS] = useState<Stats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const inv = params.get("user") ? { kind: "user" as const, value: params.get("user")! } : params.get("source") ? { kind: "source" as const, value: params.get("source")! } : null;

  const load = useCallback(() => {
    const ms = TIME_RANGES.find((r) => r.value === range)?.ms || 24 * 3_600_000;
    return api<Stats>(`/api/authmon?from=${Date.now() - ms}`).then((x) => { setS(x); setErr(null); }).catch((e) => setErr(e.message));
  }, [range]);
  useEffect(() => { load(); const t = setInterval(load, 10_000); return () => clearInterval(t); }, [load]);
  const investigate = (kind: "user" | "source", value: string) => router.replace(`/authentication?${kind}=${encodeURIComponent(value)}`, { scroll: false });

  const Who = ({ kind, value, className }: { kind: "user" | "source"; value: string; className?: string }) => (
    <button onClick={() => investigate(kind, value)} className={cx("font-mono hover:text-emerald hover:underline", className)} title={`Investigate ${kind} ${value}`}>{value}</button>
  );

  return (
    <div className="space-y-4">
      <PageHeader title="Authentication Monitoring" subtitle="Logons across Windows, SSH and RDP — brute force, spraying, lockouts and compromise signals"
        actions={<Select value={range} onChange={(e) => setRange(e.target.value)} aria-label="Time range">{TIME_RANGES.filter((r) => r.value !== "all").map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}</Select>} />
      {err && <ErrorState message={err} onRetry={load} />}
      {!s ? <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-20" />)}</div> : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            <Stat label="Successful logins" value={s.totals.success} format={fmtCompact} accent="emerald" icon={<KeyRound className="h-3.5 w-3.5" />} />
            <Stat label="Failed logins" value={s.totals.failure} format={fmtCompact} accent="high" icon={<UserX className="h-3.5 w-3.5" />} hint={`${((s.totals.failure / Math.max(1, s.totals.failure + s.totals.success)) * 100).toFixed(1)} % failure rate`} />
            <Stat label="SSH" value={s.totals.ssh.failure} format={fmtCompact} accent="medium" icon={<Terminal className="h-3.5 w-3.5" />} hint={`${fmtNum(s.totals.ssh.success)} ok · ${fmtNum(s.totals.ssh.failure)} failed`} />
            <Stat label="RDP" value={s.totals.rdp.failure} format={fmtCompact} accent="medium" hint={`${fmtNum(s.totals.rdp.success)} ok · ${fmtNum(s.totals.rdp.failure)} failed`} />
            <Stat label="Account lockouts" value={s.totals.lockouts} accent={s.totals.lockouts ? "critical" : "slate"} icon={<Lock className="h-3.5 w-3.5" />} />
            <Stat label="Active sessions" value={s.sessions.length} accent="cyan" icon={<Users className="h-3.5 w-3.5" />} hint="inferred from logons, last 30 min" />
          </div>

          {s.compromise.length > 0 && (
            <Panel title={<span className="flex items-center gap-1.5 text-red-300"><ShieldAlert className="h-3.5 w-3.5" />Success after repeated failures — possible compromise</span>} tone="critical" bodyClass="p-2">
              <ul className="space-y-1">{s.compromise.map((c) => (
                <li key={c.source + c.successAt} className="flex flex-wrap items-center gap-2 rounded-lg px-2 py-1.5 text-[12.5px] hover:bg-raised/60">
                  <SevBadge s="critical" glow />
                  <Who kind="source" value={c.source} className="text-ink" /><span className="text-ink-3">{c.country ? `(${c.country}, demo GeoIP)` : ""}</span>
                  <span className="text-ink-2">logged in as <Who kind="user" value={c.user ?? "?"} className="text-ink" /> on {c.target} after {c.failures} failures</span>
                  <span className="ml-auto text-[11px] text-ink-3">{relTime(c.successAt)}</span>
                  <Button size="sm" variant="danger" onClick={() => investigate("source", c.source)}>Investigate</Button>
                </li>
              ))}</ul>
            </Panel>
          )}

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Logon outcomes over time" className="xl:col-span-2">
              <ResponsiveContainer width="100%" height={210}>
                <AreaChart data={s.series} margin={{ top: 6, right: 4, bottom: 0, left: -12 }}>
                  <CartesianGrid stroke="#1d252e" strokeDasharray="2 4" vertical={false} />
                  <XAxis dataKey="t" tickFormatter={(t) => fmtTime(t).slice(0, 5)} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} minTickGap={40} />
                  <YAxis stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} width={40} />
                  <Tooltip labelFormatter={(l) => fmtTime(Number(l))} contentStyle={{ background: "#0e1217", border: "1px solid #2a3540", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="success" stroke="#10f0a0" fill="#10f0a0" fillOpacity={0.15} isAnimationActive={false} />
                  <Area type="monotone" dataKey="failure" stroke="#ef4444" fill="#ef4444" fillOpacity={0.25} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </Panel>
            <Panel title="Repeated failed attempts" subtitle="Same account from the same source, ≥ 5 failures" bodyClass="p-2">
              {s.repeated.length ? <table className="w-full text-[12px]"><tbody>{s.repeated.map((r) => (
                <tr key={r.user + r.source} className="border-b border-line/40">
                  <td className="py-1 pl-2"><Who kind="user" value={r.user} className="text-ink" /></td>
                  <td><Who kind="source" value={r.source} className={r.external ? "text-red-300" : "text-ink-2"} /></td>
                  <td className="pr-2 text-right font-mono tnum text-sev-high">{r.failures}</td>
                </tr>
              ))}</tbody></table> : <Empty title="No repeated failures" />}
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Top failing accounts" bodyClass="p-2">{s.topFailedUsers.length ? <RankList items={s.topFailedUsers} onPick={(k) => investigate("user", k)} color="#f97316" /> : <Empty title="No failures" />}</Panel>
            <Panel title="Top failing sources" bodyClass="p-2">{s.topFailedSources.length ? <RankList items={s.topFailedSources.map((x) => ({ ...x, note: x.country ?? (x.external ? "external" : undefined) }))} onPick={(k) => investigate("source", k)} color="#ef4444" /> : <Empty title="No failures" />}</Panel>
            <Panel title="Most targeted hosts" bodyClass="p-2">{s.topTargets.length ? <RankList items={s.topTargets} color="#22d3ee" /> : <Empty title="No failures" />}</Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title={<span className="flex items-center gap-1.5"><Globe2 className="h-3.5 w-3.5" />Unusual login locations</span>} subtitle="Logons from outside the private address space · demo GeoIP" bodyClass="p-0">
              {s.locations.length ? <table className="w-full text-[12px]"><thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Source", "Location", "Success", "Failed", "Accounts", "Last"].map((h) => <th key={h} className="px-3 py-1.5 font-medium">{h}</th>)}</tr></thead>
                <tbody>{s.locations.map((l) => (
                  <tr key={l.source} className={cx("border-b border-line/40", l.success > 0 && "bg-sev-critical/[0.06]")}>
                    <td className="px-3 py-1.5"><Who kind="source" value={l.source} className="text-ink" /></td><td className="px-3 text-ink-2">{l.country}</td>
                    <td className={cx("px-3 font-mono tnum", l.success ? "font-semibold text-red-300" : "text-ink-3")}>{l.success}</td><td className="px-3 font-mono tnum text-sev-high">{fmtNum(l.failure)}</td>
                    <td className="max-w-[180px] truncate px-3 font-mono text-[11px] text-ink-3">{l.users.join(", ")}</td><td className="px-3 text-ink-3">{relTime(l.last)}</td>
                  </tr>
                ))}</tbody></table> : <Empty title="No external logon activity" />}
            </Panel>
            <div className="grid gap-4">
              <Panel title={<span className="flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" />Account lockouts</span>} subtitle="Windows EventID 4740" bodyClass="p-2">
                {s.lockouts.length ? <ul className="space-y-1">{s.lockouts.slice(0, 8).map((l) => (
                  <li key={l.id} className="flex items-center gap-2 px-2 py-1 text-[12px]"><Lock className="h-3.5 w-3.5 text-sev-high" /><Who kind="user" value={l.user ?? "?"} className="text-ink" /><span className="text-ink-3">on {l.host}</span><span className="ml-auto text-[11px] text-ink-3">{fmtDateTime(l.at)}</span></li>
                ))}</ul> : <Empty title="No lockouts in this window" body="The “Account lockout storm” scenario ends in a 4740 event." />}
              </Panel>
              <Panel title="Active sessions (inferred)" subtitle="Latest successful logon per account and host in the last 30 min — the feed has no logoff events" bodyClass="p-0">
                <div className="max-h-[220px] overflow-y-auto scrollbar-thin">
                  {s.sessions.length ? <table className="w-full text-[12px]"><tbody>{s.sessions.map((x) => (
                    <tr key={x.user + x.host} className="border-b border-line/40"><td className="px-3 py-1"><Who kind="user" value={x.user} className="text-ink" /></td><td className="px-3 text-ink-2">{x.host}</td><td className="px-3 font-mono text-[11px] text-ink-3">{x.source}</td><td className="px-3"><Tag>{x.method}</Tag></td><td className="px-3 text-right text-ink-3">{relTime(x.since)}</td></tr>
                  ))}</tbody></table> : <Empty title="No recent logons" />}
                </div>
              </Panel>
            </div>
          </div>
        </>
      )}
      <InvestigationDrawer target={inv} onClose={() => router.replace("/authentication", { scroll: false })} />
    </div>
  );
}

function RankList({ items, onPick, color }: { items: { key: string; value: number; note?: string }[]; onPick?: (k: string) => void; color: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-1">{items.slice(0, 8).map((it) => (
      <li key={it.key}>
        <button disabled={!onPick} onClick={() => onPick?.(it.key)} className="relative flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-[12px] enabled:hover:bg-raised">
          <span className="absolute inset-y-0 left-0 rounded-md opacity-15" style={{ width: `${(it.value / max) * 100}%`, background: color }} />
          <span className="relative flex-1 truncate font-mono text-ink-2">{it.key}{it.note && <span className="ml-1.5 font-sans text-[10.5px] text-ink-3">{it.note}</span>}</span>
          <span className="relative font-mono tnum text-ink">{fmtNum(it.value)}</span>
        </button>
      </li>
    ))}</ul>
  );
}

function InvestigationDrawer({ target, onClose }: { target: { kind: "user" | "source"; value: string } | null; onClose: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const { can } = useSession();
  const analysts = useAnalysts();
  const router = useRouter();
  const [d, setD] = useState<Investigation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [event, setEvent] = useState<string | null>(null);
  const [incidentFor, setIncidentFor] = useState<string[] | null>(null);
  const key = target ? `${target.kind}=${target.value}` : null;

  const load = useCallback(() => {
    if (!target) return;
    api<Investigation>(`/api/authmon/investigate?${target.kind}=${encodeURIComponent(target.value)}`).then(setD).catch((e) => setErr(e.message));
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setD(null); setErr(null); load(); }, [load]);

  const openAlerts = d?.alerts.filter((a) => a.status !== "resolved" && a.status !== "false_positive") ?? [];
  const markBenign = async () => {
    if (!(await confirm({ title: "Mark related alerts as false positive?", body: `${openAlerts.length} open alert(s) for ${d?.value} will be closed as false positive with a comment.`, confirmLabel: "Mark false positive" }))) return;
    await api("/api/alerts/bulk", { method: "POST", json: { ids: openAlerts.map((a) => a.id), patch: { status: "false_positive", comment: `Closed from failed-login investigation of ${d?.kind} ${d?.value}: benign.` } } });
    toast({ tone: "success", title: `${openAlerts.length} alert(s) closed as false positive` });
    load();
  };

  return (
    <>
      <Drawer open={!!target} onClose={onClose} width={860}
        title={target ? <span className="flex items-center gap-2"><Search className="h-4 w-4 text-emerald" />Failed-login investigation · <span className="font-mono">{target.value}</span></span> : ""}
        subtitle={target && `${target.kind === "user" ? "Account" : "Source address"} · authentication events in the hot window`}
        actions={d && <Link href={`/log-explorer?q=${encodeURIComponent(d.query)}`} onClick={onClose}><Button size="sm"><Search className="h-3.5 w-3.5" />Log Explorer</Button></Link>}>
        {err && <div className="p-5"><ErrorState message={err} /></div>}
        {!d && !err && <div className="space-y-2 p-5">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div>}
        {d && (
          <div className="space-y-5 p-5">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {[["Events", d.summary.events], ["Failures", d.summary.failures], ["Successes", d.summary.successes], ["Lockouts", d.summary.lockouts], [d.kind === "user" ? "Sources" : "Accounts", d.kind === "user" ? d.summary.sources.length : d.summary.users.length]].map(([k, v]) => (
                <div key={k as string} className="rounded-lg border border-line bg-base/60 p-2.5"><div className="text-[10px] uppercase tracking-wider text-ink-3">{k}</div><div className="mt-0.5 font-mono text-lg tnum">{fmtNum(v as number)}</div></div>
              ))}
            </div>
            <div>
              <div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Assessment</div>
              <ul className="space-y-1">{d.findings.map((f, i) => <li key={i} className="flex items-start gap-2 text-[13px]"><SevBadge s={f.severity} /><span className="text-ink-2">{f.text}</span></li>)}</ul>
            </div>
            <div className="grid gap-3 sm:grid-cols-3 text-[12px]">
              {([["Sources", d.summary.sources, "source"], ["Accounts", d.summary.users, "user"], ["Targets", d.summary.targets, null]] as const).map(([label, list, kind]) => (
                <div key={label}><div className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-3">{label} ({list.length})</div>
                  <div className="flex flex-wrap gap-1">{list.slice(0, 12).map((v) => kind ? <button key={v} onClick={() => router.replace(`/authentication?${kind}=${encodeURIComponent(v)}`, { scroll: false })}><Tag className="font-mono hover:text-emerald">{v}</Tag></button> : <Tag key={v} className="font-mono">{v}</Tag>)}</div></div>
              ))}
            </div>
            <div>
              <div className="mb-1.5 flex items-center justify-between"><span className="text-[11px] uppercase tracking-wider text-ink-3">Related alerts ({d.alerts.length})</span>
                <div className="flex gap-2">
                  <Button size="sm" variant="ghost" disabled={!openAlerts.length || !can("alerts:write")} title={can("alerts:write") ? undefined : deniedHint("alerts:write")} onClick={markBenign}>Mark benign</Button>
                  <Button size="sm" variant="primary" disabled={!openAlerts.length || !can("incidents:write")} title={can("incidents:write") ? undefined : deniedHint("incidents:write")} onClick={() => setIncidentFor(openAlerts.map((a) => a.id))}><Siren className="h-3.5 w-3.5" />Escalate to incident</Button>
                </div>
              </div>
              {d.alerts.length ? <ul className="space-y-1">{d.alerts.map((a) => (
                <li key={a.id}><Link href={`/alerts?id=${a.id}`} className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-[12.5px] hover:border-line-strong">
                  <SevBadge s={a.severity} /><span className="flex-1 truncate">{a.title}</span>{a.incidentId && <Tag className="text-sev-high">{a.incidentId}</Tag>}<StatusBadge s={a.status} /><span className="text-[11px] text-ink-3">{relTime(a.lastSeen)}</span>
                </Link></li>
              ))}</ul> : <div className="text-[12px] text-ink-3">No correlation alerts reference this {d.kind}.</div>}
            </div>
            <div className="-mx-5">
              <div className="px-5 pb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Timeline (newest first)</div>
              {d.timeline.length ? <EventTable events={d.timeline} onOpen={(e) => setEvent(e.id)} cols={["time", "type", "src", "dst", "user", "action", "vendor"]} dense /> : <Empty title="No events" />}
            </div>
          </div>
        )}
      </Drawer>
      <EventDrawer id={event} onClose={() => setEvent(null)} onOpen={(e) => setEvent(e.id)} />
      <CreateIncident ids={incidentFor} onClose={() => setIncidentFor(null)} analysts={analysts}
        alerts={(d?.alerts ?? []) as unknown as Alert[]} onCreated={(id) => { setIncidentFor(null); router.push(`/incidents?id=${id}`); }} />
    </>
  );
}
