"use client";

import { AlertTriangle, CheckCircle2, Clock, Globe2, Play, Plus, Radar, ShieldCheck, Square, Trash2, XCircle } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { deniedHint, useSession } from "@/components/session";
import { Button, Drawer, Empty, ErrorState, Field, Input, KV, Modal, PageHeader, Panel, Select, SevBadge, SimBadge, Skeleton, Tag, useConfirm, useToast } from "@/components/ui";
import { ApiError, api, cx, fmtDateTime, fmtNum, relTime } from "@/lib/client";
import type { Severity } from "@/lib/types";

type ScanType = "host_discovery" | "tcp" | "udp" | "service" | "network_discovery" | "vuln_basic";
const TYPES: { v: ScanType; label: string; desc: string; ports: boolean }[] = [
  { v: "host_discovery", label: "Host discovery", desc: "Which hosts are up (ping/ARP, no port probing)", ports: false },
  { v: "network_discovery", label: "Network discovery", desc: "Live hosts plus their top 20 TCP services", ports: false },
  { v: "tcp", label: "TCP port scan", desc: "TCP connect scan of the selected ports", ports: true },
  { v: "udp", label: "UDP port scan", desc: "UDP probes (max 100 ports; slow by nature)", ports: true },
  { v: "service", label: "Service detection", desc: "TCP connect + service/version banners", ports: true },
  { v: "vuln_basic", label: "Basic vulnerability assessment", desc: "Service detection + non-intrusive version/exposure checks", ports: true },
];
const TYPE_LABEL = Object.fromEntries(TYPES.map((t) => [t.v, t.label])) as Record<ScanType, string>;
const INTENSITY = ["", "Gentle", "Polite", "Normal", "Fast"];

interface Engines { nmap: { available: boolean; version: string | null; reason: string }; simulated: { available: boolean; reason: string }; limits: { maxPrefix: number; maxHosts: number; allowPublic: boolean } }
interface AllowEntry { id: string; cidr: string; label: string; createdBy: string | null; createdAt: number }
interface PortResult { port: number; proto: string; state: string; service: string | null; product: string | null; version: string | null }
interface HostResult { ip: string; hostname: string | null; state: "up" | "down"; os: string | null; ports: PortResult[] }
interface FindingRow { checkId: string; title: string; severity: Severity; cve: string | null; port: number; proto: string; ip: string; hostname: string | null; evidence: string }
interface Job {
  id: string; name: string; target: string; network: string; ports: string; portCount: number; hosts: number; type: ScanType; intensity: number; timeoutSec: number;
  engine: "nmap" | "simulated"; simulated: boolean; schedule: { kind: string; at?: number; everyHours?: number }; status: string; progress: number; error: string | null;
  createdBy: string; createdAt: number; startedAt: number | null; finishedAt: number | null; nextRunAt: number | null; allowlistMatch: string; args: string[] | null; parentId: string | null;
  results: { hosts: HostResult[]; up: number; down: number; openPorts: number } | null; findings: FindingRow[];
}
interface Validation { ok: boolean; errors?: string[]; network?: string; hosts?: number; ports?: number; probes?: number; allowlist?: string; portSpec?: string }

const STATUS: Record<string, string> = { scheduled: "text-violet", queued: "text-cyan", running: "text-emerald", completed: "text-ink-2", failed: "text-sev-critical", cancelled: "text-ink-3" };

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><ScanCenter /></Suspense>;
}

function ScanCenter() {
  const params = useSearchParams();
  const router = useRouter();
  const { can } = useSession();
  const [engines, setEngines] = useState<Engines | null>(null);
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const openId = params.get("scan");

  const loadJobs = useCallback(() => api<Job[]>("/api/scans").then((j) => { setJobs(j); setErr(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { api<Engines>("/api/scans/engines").then(setEngines).catch(() => {}); }, []);
  const active = jobs?.some((j) => j.status === "running" || j.status === "queued");
  useEffect(() => { loadJobs(); const t = setInterval(loadJobs, active ? 1500 : 10_000); return () => clearInterval(t); }, [loadJobs, active]);
  const setOpen = (id: string | null) => router.replace(id ? `/scan-center?scan=${id}` : "/scan-center", { scroll: false });

  return (
    <div className="space-y-4">
      <PageHeader title="Scan Center" subtitle="Authorized discovery and assessment of allowlisted internal networks. Every request is validated server-side before it runs." />

      {engines && (
        <div className="grid gap-3 md:grid-cols-2">
          <div className={cx("flex items-start gap-3 rounded-xl border p-3.5", engines.nmap.available ? "border-emerald/40 bg-emerald/[0.05]" : "border-line bg-panel/60")}>
            <Radar className={cx("mt-0.5 h-5 w-5 shrink-0", engines.nmap.available ? "text-emerald" : "text-ink-3")} />
            <div className="text-[12.5px]"><div className="font-medium text-ink">Nmap engine {engines.nmap.available ? <span className="text-emerald">ready · {engines.nmap.version}</span> : <span className="text-ink-3">unavailable</span>}</div>
              <div className="mt-0.5 text-ink-3">{engines.nmap.available ? "Real network observations. TCP connect scans only; no stealth, evasion or intrusive scripts." : engines.nmap.reason}</div></div>
          </div>
          <div className="flex items-start gap-3 rounded-xl border border-violet/30 bg-violet/[0.05] p-3.5">
            <SimBadge />
            <div className="text-[12.5px]"><div className="font-medium text-ink">Simulated engine available</div><div className="mt-0.5 text-ink-3">{engines.simulated.reason} Results are labelled SIMULATED everywhere and never presented as observations.</div></div>
          </div>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <NewScan engines={engines} canRun={can("scans:run")} onCreated={(id) => { loadJobs(); setOpen(id); }} />
        <AllowlistPanel canEdit={can("scans:allowlist")} limits={engines?.limits} />
      </div>

      {err && <ErrorState message={err} onRetry={loadJobs} />}
      <Panel bodyClass="p-0" title={`Scan jobs${jobs ? ` (${jobs.length})` : ""}`}>
        {!jobs ? <div className="space-y-2 p-4">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div> : jobs.length === 0 ? <Empty icon={<Radar className="h-5 w-5" />} title="No scans yet" body="Configure a scan above. Try a basic vulnerability assessment of 10.10.1.0/24 (the demo DMZ)." /> : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-[12.5px]">
              <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Scan", "Target", "Type", "Engine", "Status", "Hosts up", "Open ports", "Findings", "Requested", ""].map((h, i) => <th key={i} className="px-3 py-2 font-medium whitespace-nowrap">{h}</th>)}</tr></thead>
              <tbody>{jobs.map((j) => (
                <tr key={j.id} onClick={() => setOpen(j.id)} className={cx("cursor-pointer border-b border-line/40 hover:bg-emerald/[0.04]", openId === j.id && "bg-emerald/[0.08]")}>
                  <td className="px-3 py-2"><div className="max-w-[240px] truncate text-ink">{j.name}</div><div className="font-mono text-[10.5px] text-ink-3">{j.id}{j.schedule.kind === "recurring" && ` · every ${j.schedule.everyHours}h`}</div></td>
                  <td className="px-3 font-mono text-ink-2">{j.network}</td>
                  <td className="px-3 text-ink-2 whitespace-nowrap">{TYPE_LABEL[j.type]}</td>
                  <td className="px-3">{j.simulated ? <SimBadge /> : <Tag className="text-emerald">nmap</Tag>}</td>
                  <td className="px-3 whitespace-nowrap">
                    <div className={cx("text-[12px]", STATUS[j.status])}>{j.status}{j.status === "scheduled" && j.nextRunAt && <span className="text-ink-3"> · {fmtDateTime(j.nextRunAt)}</span>}</div>
                    {(j.status === "running" || j.status === "queued") && <div className="mt-1 h-1 w-28 overflow-hidden rounded-full bg-line"><div className="h-full bg-emerald transition-all" style={{ width: `${j.progress}%` }} /></div>}
                    {j.error && j.status !== "cancelled" && <div className="max-w-[200px] truncate text-[10.5px] text-red-300" title={j.error}>{j.error}</div>}
                  </td>
                  <td className="px-3 font-mono tnum">{j.results ? fmtNum(j.results.up) : "—"}</td>
                  <td className="px-3 font-mono tnum">{j.results ? fmtNum(j.results.openPorts) : "—"}</td>
                  <td className="px-3 font-mono tnum">{j.type === "vuln_basic" && j.status === "completed" ? <span className={j.findings.length ? "text-sev-high" : "text-ink-3"}>{j.findings.length}</span> : "—"}</td>
                  <td className="px-3 text-ink-3 whitespace-nowrap">{j.createdBy} · {relTime(j.createdAt)}</td>
                  <td className="px-3 text-right" onClick={(e) => e.stopPropagation()}>{["queued", "scheduled", "running"].includes(j.status) && <CancelButton job={j} onDone={loadJobs} />}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </Panel>
      <JobDrawer id={openId} onClose={() => setOpen(null)} />
    </div>
  );
}

function CancelButton({ job, onDone }: { job: Job; onDone: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const { can } = useSession();
  return (
    <Button size="sm" variant="ghost" disabled={!can("scans:run")} title={can("scans:run") ? "Cancel scan" : deniedHint("scans:run")} onClick={async () => {
      if (!(await confirm({ title: `Cancel ${job.name}?`, body: job.schedule.kind === "recurring" ? "Future recurrences of this scan are cancelled too." : undefined, confirmLabel: "Cancel scan", danger: true }))) return;
      try { await api(`/api/scans/${job.id}`, { method: "DELETE" }); toast({ tone: "success", title: "Scan cancelled" }); onDone(); }
      catch (e) { toast({ tone: "error", title: "Could not cancel", body: (e as Error).message }); }
    }}><Square className="h-3.5 w-3.5" />Cancel</Button>
  );
}

// ── new scan form ──────────────────────────────────────────────────────
function NewScan({ engines, canRun, onCreated }: { engines: Engines | null; canRun: boolean; onCreated: (id: string) => void }) {
  const toast = useToast();
  const [f, setF] = useState({ name: "", target: "10.10.1.0/24", type: "vuln_basic" as ScanType, ports: "top100", intensity: 3, timeoutSec: 300, engine: "simulated" as "nmap" | "simulated", schedule: "now", at: "", everyHours: 24 });
  const [v, setV] = useState<Validation | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const t = TYPES.find((x) => x.v === f.type)!;
  const set = <K extends keyof typeof f>(k: K, val: (typeof f)[K]) => setF((x) => ({ ...x, [k]: val }));

  useEffect(() => { if (engines?.nmap.available) setF((x) => ({ ...x, engine: "nmap" })); }, [engines?.nmap.available]);
  // live server-side policy check
  useEffect(() => {
    const h = setTimeout(() => {
      api<Validation>("/api/scans/validate", { method: "POST", json: { target: f.target, ports: f.ports, type: f.type, intensity: f.intensity, timeoutSec: f.timeoutSec } })
        .then(setV).catch((e) => setV({ ok: false, errors: [((e as ApiError).data as { issues?: { message: string }[] })?.issues?.map((i) => i.message).join("; ") ?? (e as Error).message] }));
    }, 350);
    return () => clearTimeout(h);
  }, [f.target, f.ports, f.type, f.intensity, f.timeoutSec]);

  const schedule = f.schedule === "now" ? { kind: "now" } : f.schedule === "once" ? { kind: "once", at: new Date(f.at).getTime() } : { kind: "recurring", everyHours: f.everyHours, ...(f.at ? { at: new Date(f.at).getTime() } : {}) };
  const submit = async () => {
    setBusy(true);
    try {
      const job = await api<Job>("/api/scans", { method: "POST", json: { name: f.name || undefined, target: f.target, ports: f.ports, type: f.type, intensity: f.intensity, timeoutSec: f.timeoutSec, engine: f.engine, schedule, confirmTarget: typed } });
      toast({ tone: "success", title: job.status === "scheduled" ? "Scan scheduled" : "Scan queued", body: `${job.network} · ${TYPE_LABEL[job.type]}${job.simulated ? " · simulated" : ""}` });
      setConfirming(false); setTyped("");
      onCreated(job.id);
    } catch (e) {
      const errs = ((e as ApiError).data as { errors?: string[] })?.errors;
      toast({ tone: "error", title: (e as Error).message, body: errs?.join(" ") });
    } finally { setBusy(false); }
  };
  const scheduleOk = f.schedule === "now" || (f.at && new Date(f.at).getTime() > Date.now() - 60_000) || (f.schedule === "recurring" && !f.at);

  return (
    <Panel title="New scan" subtitle="Targets must be inside your organization’s allowlist">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Target (IPv4 or CIDR, ≤ /22)"><Input value={f.target} onChange={(e) => set("target", e.target.value.trim())} className="font-mono" placeholder="10.20.0.0/24" /></Field>
        <Field label="Scan type" hint={t.desc}><Select value={f.type} onChange={(e) => set("type", e.target.value as ScanType)}>{TYPES.map((x) => <option key={x.v} value={x.v}>{x.label}</option>)}</Select></Field>
        <Field label="Ports" hint={t.ports ? "top100 · 22,80,443 · 1-1024" : "Not used by this scan type"}><Input value={t.ports ? f.ports : "—"} disabled={!t.ports} onChange={(e) => set("ports", e.target.value)} className="font-mono" /></Field>
        <Field label={`Intensity · ${INTENSITY[f.intensity]}`} hint="Timing template T1–T4 (T5 is not offered)"><input type="range" min={1} max={4} value={f.intensity} onChange={(e) => set("intensity", Number(e.target.value))} className="mt-2 accent-emerald" /></Field>
        <Field label="Host timeout (s)"><Input type="number" min={30} max={1800} value={f.timeoutSec} onChange={(e) => set("timeoutSec", Number(e.target.value))} /></Field>
        <Field label="Engine">
          <Select value={f.engine} onChange={(e) => set("engine", e.target.value as "nmap" | "simulated")}>
            <option value="nmap" disabled={!engines?.nmap.available}>Nmap{engines?.nmap.available ? "" : " (unavailable)"}</option>
            <option value="simulated">Simulated (inventory-based)</option>
          </Select>
        </Field>
        <Field label="Schedule"><Select value={f.schedule} onChange={(e) => set("schedule", e.target.value)}><option value="now">Run now</option><option value="once">Once at…</option><option value="recurring">Recurring</option></Select></Field>
        {f.schedule !== "now" && <Field label={f.schedule === "once" ? "Run at" : "First run (optional)"}><Input type="datetime-local" value={f.at} onChange={(e) => set("at", e.target.value)} /></Field>}
        {f.schedule === "recurring" && <Field label="Repeat every"><Select value={f.everyHours} onChange={(e) => set("everyHours", Number(e.target.value))}>{[1, 6, 12, 24, 168].map((h) => <option key={h} value={h}>{h === 168 ? "week" : `${h} h`}</option>)}</Select></Field>}
        <Field label="Name (optional)"><Input value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="Weekly DMZ assessment" /></Field>
      </div>

      <div className={cx("mt-3 rounded-lg border p-3 text-[12.5px]", !v ? "border-line" : v.ok ? "border-emerald/40 bg-emerald/[0.05]" : "border-sev-critical/40 bg-sev-critical/[0.06]")}>
        {!v ? <span className="text-ink-3">Checking authorization…</span> : v.ok ? (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1"><span className="flex items-center gap-1.5 text-emerald"><ShieldCheck className="h-4 w-4" />Authorized by allowlist {v.allowlist}</span>
            <span className="text-ink-2"><span className="font-mono">{v.network}</span> · {fmtNum(v.hosts!)} host(s) · {fmtNum(v.ports!)} port(s) · {fmtNum(v.probes!)} probes</span></div>
        ) : <ul className="space-y-0.5">{v.errors?.map((e) => <li key={e} className="flex items-start gap-1.5 text-red-200"><XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />{e}</li>)}</ul>}
      </div>
      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="text-[11px] text-ink-3">Only scan networks you own or are explicitly authorized to test. Every scan, rejection and cancellation is written to the audit log.</p>
        <Button variant="primary" disabled={!canRun || !v?.ok || !scheduleOk} title={canRun ? undefined : deniedHint("scans:run")} onClick={() => { setTyped(""); setConfirming(true); }}><Play className="h-3.5 w-3.5" />Review & run</Button>
      </div>

      <Modal open={confirming} onClose={() => setConfirming(false)} title="Authorize scan" width={520}
        footer={<><Button variant="ghost" onClick={() => setConfirming(false)}>Cancel</Button><Button variant="primary" loading={busy} disabled={typed !== f.target} onClick={submit}><Play className="h-3.5 w-3.5" />{f.schedule === "now" ? "Start scan" : "Schedule scan"}</Button></>}>
        <div className="space-y-3 text-[13px]">
          {f.engine === "nmap"
            ? <div className="flex items-start gap-2 rounded-lg border border-sev-medium/40 bg-sev-medium/10 p-2.5 text-amber-100"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />This sends real network traffic from the SENTINEL X server to {v?.hosts} host(s).</div>
            : <div className="flex items-start gap-2 rounded-lg border border-violet/40 bg-violet/10 p-2.5 text-violet"><Globe2 className="mt-0.5 h-4 w-4 shrink-0" />Simulated engine: no packets are sent; results come from the asset inventory and are labelled SIMULATED.</div>}
          <div className="rounded-lg border border-line bg-base/60 p-3 font-mono text-[12px]">
            <KV k="target" v={v?.network} /><KV k="type" v={TYPE_LABEL[f.type]} mono={false} /><KV k="ports" v={t.ports ? v?.portSpec : "—"} /><KV k="intensity" v={`T${f.intensity} (${INTENSITY[f.intensity]})`} />
            <KV k="schedule" v={f.schedule === "now" ? "immediately" : f.schedule === "once" ? `once at ${f.at}` : `every ${f.everyHours} h`} /><KV k="allowlist" v={v?.allowlist} />
          </div>
          <Field label={`Type the target to confirm: ${f.target}`}><Input value={typed} onChange={(e) => setTyped(e.target.value.trim())} className="font-mono" autoFocus /></Field>
        </div>
      </Modal>
    </Panel>
  );
}

function AllowlistPanel({ canEdit, limits }: { canEdit: boolean; limits?: Engines["limits"] }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [list, setList] = useState<AllowEntry[] | null>(null);
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const load = useCallback(() => api<AllowEntry[]>("/api/scans/allowlist").then(setList).catch(() => setList([])), []);
  useEffect(() => { load(); }, [load]);
  const add = async () => {
    try { const r = await api<{ cidr: string }>("/api/scans/allowlist", { method: "POST", json: { cidr, label } }); toast({ tone: "success", title: `${r.cidr} allowlisted` }); setCidr(""); setLabel(""); load(); }
    catch (e) { toast({ tone: "error", title: "Not added", body: (e as Error).message }); }
  };
  const remove = async (a: AllowEntry) => {
    if (!(await confirm({ title: `Remove ${a.cidr} from the allowlist?`, body: "Queued and scheduled scans of this range will be refused when they come due.", confirmLabel: "Remove", danger: true }))) return;
    await api(`/api/scans/allowlist/${a.id}`, { method: "DELETE" });
    toast({ tone: "success", title: `${a.cidr} removed` });
    load();
  };
  return (
    <Panel title={<span className="flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5" />Authorized ranges</span>} subtitle={limits ? `Private ranges only${limits.allowPublic ? " (public enabled)" : ""} · targets ≤ /${limits.maxPrefix}` : undefined}>
      {!list ? <Skeleton className="h-20" /> : list.length === 0 ? <Empty title="Allowlist is empty" body="No scan can run until an administrator authorizes a range." /> : (
        <ul className="space-y-1">{list.map((a) => (
          <li key={a.id} className="group flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald" /><span className="font-mono text-[12.5px] text-ink">{a.cidr}</span>
            <span className="truncate text-[11.5px] text-ink-3">{a.label}</span>
            {canEdit && <button aria-label={`Remove ${a.cidr}`} onClick={() => remove(a)} className="ml-auto text-ink-3 opacity-0 hover:text-red-300 group-hover:opacity-100"><Trash2 className="h-3.5 w-3.5" /></button>}
          </li>
        ))}</ul>
      )}
      {canEdit ? (
        <div className="mt-3 space-y-2 border-t border-line/60 pt-3">
          <Input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.40.0.0/16" className="w-full font-mono" aria-label="CIDR" />
          <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label (e.g. Lab network, change #4711)" className="w-full" aria-label="Label" />
          <Button size="sm" onClick={add} disabled={!cidr || label.trim().length < 2}><Plus className="h-3.5 w-3.5" />Authorize range</Button>
        </div>
      ) : <p className="mt-3 text-[11px] text-ink-3">{deniedHint("scans:allowlist")} to change authorized ranges.</p>}
    </Panel>
  );
}

function JobDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [j, setJ] = useState<Job | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!id) return;
    setJ(null); setErr(null);
    let stop = false;
    const load = () => api<Job>(`/api/scans/${id}`).then((x) => { if (!stop) setJ(x); }).catch((e) => setErr(e.message));
    load();
    const t = setInterval(load, 1500);
    return () => { stop = true; clearInterval(t); };
  }, [id]);
  const upHosts = useMemo(() => j?.results?.hosts.filter((h) => h.state === "up") ?? [], [j]);
  return (
    <Drawer open={!!id} onClose={onClose} width={860}
      title={j ? <span className="flex items-center gap-2">{j.name}{j.simulated ? <SimBadge /> : <Tag className="text-emerald">nmap</Tag>}</span> : "Scan"}
      subtitle={j && <span className="font-mono">{j.id} · {j.network} · {j.status}{j.status === "running" ? ` ${j.progress}%` : ""}</span>}
      actions={j && ["queued", "scheduled", "running"].includes(j.status) && <CancelButton job={j} onDone={() => {}} />}>
      {err && <div className="p-5"><ErrorState message={err} /></div>}
      {!j && !err && <div className="space-y-2 p-5">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div>}
      {j && (
        <div className="space-y-5 p-5">
          {j.simulated && <div className="rounded-lg border border-violet/40 bg-violet/10 p-2.5 text-[12.5px] text-violet">SIMULATED RESULTS — generated from the asset inventory. No packets were sent; these are not network observations.</div>}
          {(j.status === "running" || j.status === "queued") && <div><div className="mb-1 flex justify-between text-[11px] text-ink-3"><span>{j.status === "queued" ? "Waiting for a scan slot…" : "Scanning…"}</span><span className="tnum">{j.progress}%</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-line"><div className="h-full bg-emerald transition-all" style={{ width: `${j.progress}%` }} /></div></div>}
          {j.error && j.status !== "cancelled" && <ErrorState message={j.error} />}
          <div className="grid gap-4 sm:grid-cols-2">
            <div><KV k="type" v={TYPE_LABEL[j.type]} mono={false} /><KV k="target" v={`${j.target} → ${j.network}`} /><KV k="hosts in range" v={fmtNum(j.hosts)} /><KV k="ports" v={j.ports || "—"} /><KV k="intensity" v={`T${j.intensity}`} /><KV k="timeout" v={`${j.timeoutSec}s`} /></div>
            <div><KV k="engine" v={j.engine} /><KV k="allowlist" v={j.allowlistMatch} /><KV k="requested" v={`${j.createdBy} · ${fmtDateTime(j.createdAt)}`} mono={false} />
              <KV k="started" v={j.startedAt ? fmtDateTime(j.startedAt) : j.nextRunAt ? `scheduled ${fmtDateTime(j.nextRunAt)}` : "—"} /><KV k="finished" v={j.finishedAt ? fmtDateTime(j.finishedAt) : "—"} />
              <KV k="schedule" v={j.schedule.kind === "recurring" ? `every ${j.schedule.everyHours} h` : j.schedule.kind} /></div>
          </div>
          {j.args && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">Command executed</div><code className="block break-all rounded-lg border border-line bg-void p-2.5 font-mono text-[11.5px] text-emerald">nmap {j.args.join(" ")}</code></div>}
          {j.results && (
            <>
              <div className="grid grid-cols-3 gap-2">{[["Hosts up", j.results.up], ["Hosts down", j.results.down], ["Open ports", j.results.openPorts]].map(([k, v]) => (
                <div key={k as string} className="rounded-lg border border-line bg-base/60 p-3"><div className="text-[10.5px] uppercase tracking-wider text-ink-3">{k}</div><div className="mt-0.5 font-mono text-lg tnum">{fmtNum(v as number)}</div></div>
              ))}</div>
              {j.type === "vuln_basic" && (
                <div>
                  <div className="mb-1.5 flex items-center justify-between"><span className="text-[11px] uppercase tracking-wider text-ink-3">Findings ({j.findings.length})</span><Link href="/vulnerabilities" onClick={onClose} className="text-[11.5px] text-emerald hover:underline">Open vulnerability register →</Link></div>
                  {j.findings.length ? <ul className="space-y-1">{j.findings.map((f) => (
                    <li key={f.ip + f.checkId + f.port} className="rounded-lg border border-line px-3 py-1.5 text-[12.5px]"><div className="flex items-center gap-2"><SevBadge s={f.severity} /><span className="text-ink">{f.title}</span>{f.cve && <Tag className="font-mono">{f.cve}</Tag>}<span className="ml-auto font-mono text-[11px] text-ink-3">{f.hostname ?? f.ip}:{f.port}/{f.proto}</span></div>
                      <div className="mt-0.5 text-[11.5px] text-ink-3">{f.evidence}</div></li>
                  ))}</ul> : <div className="text-[12px] text-ink-3">No findings.</div>}
                </div>
              )}
              <div>
                <div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Hosts ({upHosts.length} up)</div>
                {upHosts.length ? <div className="space-y-2">{upHosts.map((h) => (
                  <div key={h.ip} className="rounded-lg border border-line">
                    <div className="flex items-center gap-2 border-b border-line/60 px-3 py-1.5 text-[12.5px]"><span className="h-1.5 w-1.5 rounded-full bg-emerald" /><span className="font-mono text-ink">{h.ip}</span><span className="text-ink-2">{h.hostname}</span><span className="ml-auto text-[11px] text-ink-3">{h.os}</span></div>
                    {h.ports.length ? <table className="w-full text-[11.5px]"><tbody>{h.ports.map((p) => (
                      <tr key={p.proto + p.port} className="border-b border-line/30 last:border-0"><td className="w-20 px-3 py-1 font-mono text-ink">{p.port}/{p.proto}</td><td className="w-16 text-emerald">{p.state}</td><td className="w-28 font-mono text-ink-2">{p.service ?? "—"}</td><td className="text-ink-3">{[p.product, p.version].filter(Boolean).join(" ") || "—"}</td></tr>
                    ))}</tbody></table> : <div className="px-3 py-1.5 text-[11.5px] text-ink-3">{j.type === "host_discovery" ? "Host is up (no port probing for this scan type)" : "No open ports among those scanned"}</div>}
                  </div>
                ))}</div> : <Empty icon={<Clock className="h-5 w-5" />} title={j.status === "completed" ? "No hosts answered" : "Results appear when the scan completes"} body={j.simulated && j.status === "completed" ? "The simulated engine only reports hosts that exist in the asset inventory within the target range." : undefined} />}
              </div>
            </>
          )}
        </div>
      )}
    </Drawer>
  );
}
