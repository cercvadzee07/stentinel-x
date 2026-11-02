"use client";

import { motion } from "framer-motion";
import { Bell, CheckCircle2, Circle, Flag, MessageSquare, Plus, Search, Siren, Zap } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { deniedHint, useSession } from "@/components/session";
import { useLive } from "@/components/live";
import { CreateIncident, useAnalysts } from "@/components/triage";
import { Button, Drawer, Empty, ErrorState, Field, Input, PageHeader, Panel, Select, SevBadge, Skeleton, StatusBadge, Tabs, Tag, Textarea, useConfirm, useToast } from "@/components/ui";
import { SEV_COLOR, api, cx, fmtDateTime, relTime } from "@/lib/client";
import { anyOf } from "@/lib/query";
import { INCIDENT_STATUSES, SEVERITIES, type Alert, type Incident, type IncidentStatus, type TimelineEntry } from "@/lib/types";

const STATUS_TONE: Record<IncidentStatus, string> = {
  open: "text-sev-critical border-sev-critical/40 bg-sev-critical/10", investigating: "text-cyan border-cyan/40 bg-cyan/10",
  contained: "text-sev-medium border-sev-medium/40 bg-sev-medium/10", resolved: "text-emerald border-emerald/40 bg-emerald/10", closed: "text-ink-3 border-line-strong bg-raised",
};
const IncStatus = ({ s }: { s: IncidentStatus }) => <span className={cx("inline-flex rounded-md border px-1.5 py-[1px] text-[10.5px] font-medium capitalize", STATUS_TONE[s])}>{s}</span>;

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><Incidents /></Suspense>;
}

function Incidents() {
  const params = useSearchParams();
  const router = useRouter();
  const analysts = useAnalysts();
  const { can } = useSession();
  const { alertVersion } = useLive();
  const [items, setItems] = useState<Incident[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState<"active" | "all">("active");
  const [q, setQ] = useState("");
  const openId = params.get("id");

  const load = useCallback(() => api<Incident[]>("/api/incidents").then((x) => { setItems(x); setErr(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load, alertVersion]);
  const setOpen = (id: string | null) => router.replace(id ? `/incidents?id=${id}` : "/incidents", { scroll: false });

  const shown = items?.filter((i) => (filter === "all" || !["resolved", "closed"].includes(i.status)) &&
    (!q || `${i.id} ${i.title} ${i.assets.join(" ")} ${i.sourceIps.join(" ")} ${i.assignee ?? ""}`.toLowerCase().includes(q.toLowerCase())));

  return (
    <div>
      <PageHeader title="Incident Management" subtitle="Cases grouping related alerts, with an auto-built attack timeline, notes and resolution tracking."
        actions={<>
          <Tabs value={filter} onChange={setFilter} items={[{ value: "active", label: "Active" }, { value: "all", label: "All" }]} />
          <Input placeholder="Search incidents…" value={q} onChange={(e) => setQ(e.target.value)} className="w-56" aria-label="Search incidents" />
          <Button variant="primary" disabled={!can("incidents:write")} title={can("incidents:write") ? undefined : deniedHint("incidents:write")} onClick={() => setCreating(true)}><Plus className="h-3.5 w-3.5" />New incident</Button>
        </>} />
      {err && <ErrorState message={err} onRetry={load} />}
      {!shown ? <div className="grid gap-3 md:grid-cols-2">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-36" />)}</div>
        : shown.length === 0 ? <Panel><Empty icon={<Siren className="h-5 w-5" />} title="No incidents" body="Select alerts in Security Alerts and choose “Create incident”, or create one manually." /></Panel> : (
        <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {shown.map((i) => (
            <motion.button layout key={i.id} onClick={() => setOpen(i.id)} className={cx("glass rounded-xl p-4 text-left transition-colors hover:border-line-strong", i.severity === "critical" && i.status === "open" && "glow-critical", openId === i.id && "border-emerald/50")}>
              <div className="flex items-center gap-2"><span className="font-mono text-[11px] text-ink-3">{i.id}</span><SevBadge s={i.severity} glow /><IncStatus s={i.status} /><span className="ml-auto text-[11px] text-ink-3">{relTime(i.updatedAt)}</span></div>
              <div className="mt-2 line-clamp-2 text-[14px] font-medium text-ink">{i.title}</div>
              <div className="mt-1 line-clamp-2 text-[12px] text-ink-3">{i.description}</div>
              <div className="mt-3 flex flex-wrap gap-1">{i.assets.slice(0, 4).map((a) => <Tag key={a}>{a}</Tag>)}{i.sourceIps.slice(0, 3).map((s) => <Tag key={s} className="font-mono text-red-300">{s}</Tag>)}</div>
              <div className="mt-3 flex items-center gap-3 text-[11.5px] text-ink-3"><span className="flex items-center gap-1"><Bell className="h-3.5 w-3.5" />{i.alertIds.length} alerts</span><span className="flex items-center gap-1"><MessageSquare className="h-3.5 w-3.5" />{i.notes.length} notes</span><span className="ml-auto text-ink-2">{i.assignee ?? "unassigned"}</span></div>
            </motion.button>
          ))}
        </div>
      )}
      <IncidentDrawer id={openId} onClose={() => setOpen(null)} analysts={analysts} onChanged={load} />
      <CreateIncident ids={creating ? [] : null} alerts={[]} analysts={analysts} onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); load(); setOpen(id); }} />
    </div>
  );
}

const KIND: Record<TimelineEntry["kind"], { icon: typeof Zap; color: string }> = {
  created: { icon: Flag, color: "#10f0a0" }, alert: { icon: Bell, color: "#f97316" }, event: { icon: Zap, color: "#22d3ee" },
  note: { icon: MessageSquare, color: "#a78bfa" }, status: { icon: CheckCircle2, color: "#a7b3bf" },
};

function IncidentDrawer({ id, onClose, analysts, onChanged }: { id: string | null; onClose: () => void; analysts: string[]; onChanged: () => void }) {
  const toast = useToast();
  const { can } = useSession();
  const write = can("incidents:write");
  const lock = write ? {} : { disabled: true, title: deniedHint("incidents:write") };
  const confirm = useConfirm();
  const [d, setD] = useState<{ incident: Incident; alerts: Alert[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<"timeline" | "alerts" | "notes" | "resolution">("timeline");
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");

  const load = useCallback(() => { if (id) api<{ incident: Incident; alerts: Alert[] }>(`/api/incidents/${id}`).then((x) => { setD(x); setResolution(x.incident.resolution ?? ""); setErr(null); }).catch((e) => setErr(e.message)); }, [id]);
  useEffect(() => { setD(null); setTab("timeline"); load(); }, [id, load]);

  const patch = async (p: Record<string, unknown>, msg: string) => {
    try { await api(`/api/incidents/${id}`, { method: "PATCH", json: p }); toast({ tone: "success", title: msg }); load(); onChanged(); }
    catch (e) { toast({ tone: "error", title: "Update failed", body: (e as Error).message }); }
  };
  const resolve = async () => {
    if (!(await confirm({ title: "Resolve incident?", body: "The incident is marked resolved with the resolution details below. Linked alerts are not changed.", confirmLabel: "Resolve" }))) return;
    patch({ status: "resolved", resolution }, "Incident resolved");
  };

  const i = d?.incident;
  const t0 = i?.timeline[0]?.at ?? 0;
  return (
    <Drawer open={!!id} onClose={onClose} width={840}
      title={i ? <span className="flex items-center gap-2"><SevBadge s={i.severity} glow />{i.title}</span> : "Incident"}
      subtitle={i && <span className="font-mono">{i.id} · opened {fmtDateTime(i.createdAt)} · {i.alertIds.length} alerts</span>}
      actions={i && i.sourceIps.length > 0 && <Link href={`/log-explorer?q=${encodeURIComponent(anyOf("source.ip", i.sourceIps))}`} onClick={onClose}><Button size="sm"><Search className="h-3.5 w-3.5" />Hunt sources</Button></Link>}>
      {err && <div className="p-5"><ErrorState message={err} /></div>}
      {!i && !err && <div className="space-y-2 p-5">{Array.from({ length: 10 }, (_, k) => <Skeleton key={k} className="h-7" />)}</div>}
      {i && d && (
        <div className="p-5">
          <div className="mb-4 grid gap-2 sm:grid-cols-3">
            <Field label="Status"><Select {...lock} value={i.status} onChange={(e) => patch({ status: e.target.value }, `Status → ${e.target.value}`)}>{INCIDENT_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}</Select></Field>
            <Field label="Severity"><Select {...lock} value={i.severity} onChange={(e) => patch({ severity: e.target.value }, `Severity → ${e.target.value}`)}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</Select></Field>
            <Field label="Assigned analyst"><Select {...lock} value={i.assignee ?? ""} onChange={(e) => patch({ assignee: e.target.value || null }, e.target.value ? `Assigned to ${e.target.value}` : "Unassigned")}><option value="">Unassigned</option>{analysts.map((a) => <option key={a}>{a}</option>)}</Select></Field>
          </div>
          <p className="mb-3 text-[13px] text-ink-2">{i.description || <span className="text-ink-3">No description.</span>}</p>
          <div className="mb-4 grid gap-3 sm:grid-cols-2">
            <div><div className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-3">Affected assets</div><div className="flex flex-wrap gap-1">{i.assets.length ? i.assets.map((a) => <Link key={a} href={`/log-explorer?q=${encodeURIComponent(`destination.host:${a}`)}`}><Tag className="hover:text-emerald">{a}</Tag></Link>) : <span className="text-[12px] text-ink-3">—</span>}</div></div>
            <div><div className="mb-1 text-[10.5px] uppercase tracking-wider text-ink-3">Attacker sources</div><div className="flex flex-wrap gap-1">{i.sourceIps.length ? i.sourceIps.map((s) => <Link key={s} href={`/log-explorer?q=source.ip:${s}`}><Tag className="font-mono text-red-300 hover:text-emerald">{s}</Tag></Link>) : <span className="text-[12px] text-ink-3">—</span>}</div></div>
          </div>
          <div className="mb-3"><Tabs value={tab} onChange={setTab} items={[{ value: "timeline", label: `Timeline (${i.timeline.length})` }, { value: "alerts", label: `Alerts (${d.alerts.length})` }, { value: "notes", label: `Notes & history (${i.notes.length})` }, { value: "resolution", label: "Resolution" }]} /></div>

          {tab === "timeline" && (
            <ol className="relative ml-2 border-l border-line">
              {i.timeline.map((x, k) => {
                const K = KIND[x.kind];
                const Icon = K.icon;
                return (
                  <motion.li key={k} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(k * 0.04, 0.6) }} className="relative mb-4 pl-6">
                    <span className="absolute -left-[11px] top-0 grid h-[22px] w-[22px] place-items-center rounded-full border border-line-strong bg-panel" style={{ color: x.severity ? SEV_COLOR[x.severity] : K.color }}><Icon className="h-3 w-3" /></span>
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-3"><span className="font-mono">{fmtDateTime(x.at)}</span><span className="font-mono">T+{Math.max(0, Math.round((x.at - t0) / 1000))}s</span><span className="uppercase tracking-wider">{x.kind}</span>{x.severity && <SevBadge s={x.severity} />}</div>
                    <div className="mt-0.5 text-[13px] text-ink">
                      {x.ref && x.kind === "alert" ? <Link href={`/alerts?id=${x.ref}`} className="hover:text-emerald">{x.title}</Link>
                        : x.ref && x.kind === "event" ? <Link href={`/log-explorer?q=${encodeURIComponent(`source.ip:${x.detail?.split(" ")[0] ?? ""}`)}`} className="hover:text-emerald">{x.title}</Link> : x.title}
                    </div>
                    {x.detail && <div className="font-mono text-[11.5px] text-ink-3">{x.detail}</div>}
                  </motion.li>
                );
              })}
            </ol>
          )}

          {tab === "alerts" && (d.alerts.length ? (
            <ul className="space-y-1.5">{d.alerts.map((a) => (
              <li key={a.id}><Link href={`/alerts?id=${a.id}`} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-[12.5px] hover:border-line-strong">
                <SevBadge s={a.severity} /><span className="font-mono text-[11px] text-ink-3">{a.id}</span><span className="flex-1 truncate">{a.title}</span><StatusBadge s={a.status} /><span className="text-[11px] text-ink-3">{a.eventCount} ev</span>
              </Link></li>
            ))}</ul>
          ) : <Empty title="No linked alerts" body="Link alerts from the Security Alerts page." />)}

          {tab === "notes" && (
            <div>
              {write && <div className="mb-4 flex gap-2">
                <Textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Investigation note (findings, containment steps, IOCs)…" className="flex-1" />
                <Button variant="primary" disabled={!note.trim()} onClick={() => { patch({ note }, "Note added"); setNote(""); }}>Add note</Button>
              </div>}
              <ol className="space-y-3">
                {[...i.notes.map((n) => ({ at: n.at, who: n.author, what: "note", text: n.text })), ...i.history.map((h) => ({ at: h.at, who: h.actor, what: h.action, text: h.detail }))]
                  .sort((a, b) => b.at - a.at).map((x, k) => (
                    <li key={k} className="flex gap-2.5">
                      {x.what === "note" ? <MessageSquare className="mt-0.5 h-4 w-4 shrink-0 text-violet" /> : <Circle className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />}
                      <div className="min-w-0 flex-1">
                        <div className="text-[12px]"><span className="text-ink">{x.who}</span> <span className="text-ink-3">{x.what === "note" ? "added a note" : x.what}</span> <span className="text-[11px] text-ink-3">· {fmtDateTime(x.at)}</span></div>
                        {x.text && <div className={cx("mt-0.5 whitespace-pre-wrap text-[12.5px]", x.what === "note" ? "rounded-md border border-line bg-base/60 px-2.5 py-1.5 text-ink-2" : "font-mono text-[11.5px] text-ink-3")}>{x.text}</div>}
                      </div>
                    </li>
                  ))}
              </ol>
            </div>
          )}

          {tab === "resolution" && (
            <div className="space-y-3">
              <Field label="Resolution details" hint="Root cause, actions taken, follow-ups."><Textarea {...lock} rows={6} value={resolution} onChange={(e) => setResolution(e.target.value)} placeholder="e.g. Blocked 203.0.113.17 at edge, rotated root credentials on web-01, enforced key-only SSH." /></Field>
              <div className="flex gap-2">
                <Button onClick={() => patch({ resolution }, "Resolution saved")} disabled={!write || resolution === (i.resolution ?? "")}>Save draft</Button>
                <Button variant="primary" onClick={resolve} disabled={!write || !resolution.trim() || i.status === "resolved" || i.status === "closed"}><CheckCircle2 className="h-3.5 w-3.5" />Resolve incident</Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
