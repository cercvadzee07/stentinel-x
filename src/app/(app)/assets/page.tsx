"use client";

import { ArrowDown, ArrowUp, Boxes, Pencil, Plus, Search, ShieldAlert, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { deniedHint, useSession } from "@/components/session";
import {
  Button, Drawer, Empty, ErrorState, Field, Input, KV, Modal, PageHeader, Panel, Select, SevBadge, SimBadge, Skeleton, StatusBadge, Tag, Textarea, useConfirm, useToast,
} from "@/components/ui";
import { ApiError, api, cx, fmtDateTime, fmtNum, relTime } from "@/lib/client";
import { EVENT_TYPE_LABEL, type Alert, type EventType, type Severity } from "@/lib/types";

interface Asset {
  id: string; hostname: string; ip: string; mac: string | null; os: string | null; type: string; location: string | null; owner: string | null;
  criticality: number; monitored: boolean; online: boolean; simulated: boolean; notes: string | null; lastSeen: number | null;
  events: number; highEvents: number; openAlerts: number;
}
interface Activity { asSource: number; asTarget: number; highSev: number; lastSeen: number | null; types: { key: string; value: number }[]; alerts: Alert[] }

const TYPES = ["server", "workstation", "firewall", "router", "switch", "domain_controller", "database", "web", "iot", "other"] as const;
const TYPE_LABEL: Record<string, string> = { domain_controller: "Domain controller", iot: "IoT" };
const typeLabel = (t: string) => TYPE_LABEL[t] ?? t[0].toUpperCase() + t.slice(1);
const CRIT_LABEL = ["", "Minimal", "Low", "Moderate", "High", "Mission-critical"];

function Crit({ n }: { n: number }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={`${n} · ${CRIT_LABEL[n]}`}>
      <span className="flex gap-[2px]">{[1, 2, 3, 4, 5].map((i) => <span key={i} className={cx("h-3 w-1 rounded-sm", i <= n ? (n >= 5 ? "bg-sev-critical" : n >= 4 ? "bg-sev-high" : n >= 3 ? "bg-sev-medium" : "bg-cyan") : "bg-line-strong")} />)}</span>
      <span className="font-mono text-[11px] text-ink-3">{n}</span>
    </span>
  );
}

function Status({ a }: { a: Asset }) {
  if (!a.monitored) return <span className="text-[11.5px] text-ink-3">unmonitored</span>;
  return <span className={cx("inline-flex items-center gap-1.5 text-[11.5px]", a.online ? "text-emerald" : "text-sev-high")}><span className={cx("h-1.5 w-1.5 rounded-full", a.online ? "bg-emerald" : "bg-sev-high")} />{a.online ? "online" : "offline"}</span>;
}

type SortKey = "hostname" | "ip" | "type" | "criticality" | "events" | "openAlerts" | "lastSeen";
const ipNum = (ip: string) => ip.split(".").reduce((n, p) => n * 256 + Number(p), 0);

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><Assets /></Suspense>;
}

function Assets() {
  const params = useSearchParams();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const { can } = useSession();
  const write = can("assets:write");
  const lock = write ? {} : { disabled: true, title: deniedHint("assets:write") };
  const [items, setItems] = useState<Asset[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [status, setStatus] = useState("");
  const [minCrit, setMinCrit] = useState(1);
  const [sort, setSort] = useState<{ k: SortKey; dir: 1 | -1 }>({ k: "criticality", dir: -1 });
  const [editing, setEditing] = useState<Partial<Asset> | null>(null);
  const openId = params.get("id");

  const load = useCallback(() => api<Asset[]>("/api/assets").then((x) => { setItems(x); setErr(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (params.get("new") && write) { setEditing({}); router.replace("/assets"); } }, [params, router, write]);
  const setOpen = (id: string | null) => router.replace(id ? `/assets?id=${id}` : "/assets", { scroll: false });

  const shown = useMemo(() => {
    if (!items) return null;
    const s = q.trim().toLowerCase();
    const out = items.filter((a) => (!type || a.type === type) && a.criticality >= minCrit &&
      (!status || (status === "online" ? a.monitored && a.online : status === "offline" ? a.monitored && !a.online : !a.monitored)) &&
      (!s || [a.hostname, a.ip, a.mac, a.os, a.owner, a.location].some((v) => v?.toLowerCase().includes(s))));
    const { k, dir } = sort;
    return out.sort((x, y) => {
      const a = x[k], b = y[k];
      if (k === "ip") return (ipNum(x.ip) - ipNum(y.ip)) * dir;
      if (typeof a === "number" || typeof b === "number") return ((Number(a) || 0) - (Number(b) || 0)) * dir;
      return String(a ?? "").localeCompare(String(b ?? "")) * dir;
    });
  }, [items, q, type, status, minCrit, sort]);

  const remove = async (a: Asset) => {
    if (!(await confirm({ title: `Remove ${a.hostname}?`, body: "The asset leaves the inventory. Its historical events are kept but will no longer be enriched with this hostname.", confirmLabel: "Remove asset", danger: true }))) return;
    try { await api(`/api/assets/${a.id}`, { method: "DELETE" }); toast({ tone: "success", title: `${a.hostname} removed` }); if (openId === a.id) setOpen(null); load(); }
    catch (e) { toast({ tone: "error", title: "Could not remove asset", body: (e as Error).message }); }
  };

  const th = (k: SortKey, label: string) => (
    <th className="px-3 py-2 font-medium whitespace-nowrap">
      <button className={cx("inline-flex items-center gap-1 hover:text-ink", sort.k === k && "text-emerald")} onClick={() => setSort((s) => ({ k, dir: s.k === k ? (s.dir === 1 ? -1 : 1) : -1 }))}>
        {label}{sort.k === k && (sort.dir === 1 ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
      </button>
    </th>
  );

  const totals = useMemo(() => items && ({ all: items.length, online: items.filter((a) => a.monitored && a.online).length, offline: items.filter((a) => a.monitored && !a.online).length, crit: items.filter((a) => a.criticality >= 5).length, alerting: items.filter((a) => a.openAlerts > 0).length }), [items]);

  return (
    <div>
      <PageHeader title="Asset Inventory" subtitle="Hosts and network devices of your organization. Events are enriched with these hostnames at ingestion."
        actions={<Button variant="primary" {...lock} onClick={() => setEditing({})}><Plus className="h-3.5 w-3.5" />Add asset</Button>} />

      {totals && (
        <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {[["Assets", totals.all, "text-ink"], ["Online", totals.online, "text-emerald"], ["Offline", totals.offline, "text-sev-high"], ["Mission-critical", totals.crit, "text-sev-critical"], ["With open alerts", totals.alerting, "text-sev-medium"]].map(([l, v, c]) => (
            <div key={l as string} className="glass rounded-xl px-3 py-2"><div className="text-[10.5px] uppercase tracking-wider text-ink-3">{l}</div><div className={cx("text-xl font-semibold tnum", c as string)}>{v}</div></div>
          ))}
        </div>
      )}

      <Panel bodyClass="p-3" className="mb-3">
        <div className="flex flex-wrap gap-2">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search hostname, IP, MAC, OS, owner, location…" className="min-w-[260px] flex-1" aria-label="Search assets" />
          <Select value={type} onChange={(e) => setType(e.target.value)} aria-label="Asset type"><option value="">All types</option>{TYPES.map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}</Select>
          <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status"><option value="">Any status</option><option value="online">Online</option><option value="offline">Offline</option><option value="unmonitored">Unmonitored</option></Select>
          <Select value={minCrit} onChange={(e) => setMinCrit(Number(e.target.value))} aria-label="Minimum criticality">{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>Criticality ≥ {n}</option>)}</Select>
        </div>
      </Panel>

      {err && <ErrorState message={err} onRetry={load} />}
      <Panel bodyClass="p-0" title={shown ? `${shown.length} of ${items?.length ?? 0} assets` : "Assets"}>
        {!shown ? <div className="space-y-2 p-4">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div>
          : shown.length === 0 ? <Empty icon={<Boxes className="h-5 w-5" />} title={items?.length ? "No assets match these filters" : "No assets yet"} body={items?.length ? undefined : "Add the hosts you monitor so events are enriched with hostnames and criticality."} /> : (
          <div className="max-h-[calc(100vh-360px)] overflow-auto scrollbar-thin">
            <table className="w-full text-[12.5px]">
              <thead className="sticky top-0 z-10 bg-panel/95 backdrop-blur"><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">
                {th("hostname", "Hostname")}{th("ip", "IP address")}<th className="px-3 py-2 font-medium">MAC</th><th className="px-3 py-2 font-medium">OS</th>
                {th("type", "Type")}<th className="px-3 py-2 font-medium">Location / Owner</th>{th("criticality", "Criticality")}<th className="px-3 py-2 font-medium">Monitoring</th>
                {th("lastSeen", "Last seen")}{th("events", "Events")}{th("openAlerts", "Alerts")}<th />
              </tr></thead>
              <tbody>
                {shown.map((a) => (
                  <tr key={a.id} onClick={() => setOpen(a.id)} className={cx("cursor-pointer border-b border-line/40 hover:bg-emerald/[0.04]", openId === a.id && "bg-emerald/[0.08]")}>
                    <td className="px-3 py-2 whitespace-nowrap"><span className="flex items-center gap-1.5 font-medium text-ink">{a.hostname}{a.simulated && <SimBadge />}</span></td>
                    <td className="px-3 font-mono text-ink-2">{a.ip}</td>
                    <td className="px-3 font-mono text-[11px] text-ink-3 whitespace-nowrap">{a.mac ?? "—"}</td>
                    <td className="px-3 text-ink-2 whitespace-nowrap">{a.os ?? "—"}</td>
                    <td className="px-3 whitespace-nowrap"><Tag>{typeLabel(a.type)}</Tag></td>
                    <td className="px-3 text-ink-2 whitespace-nowrap">{a.location ?? "—"}<span className="text-ink-3"> · {a.owner ?? "—"}</span></td>
                    <td className="px-3"><Crit n={a.criticality} /></td>
                    <td className="px-3"><Status a={a} /></td>
                    <td className="px-3 text-ink-2 whitespace-nowrap" title={a.lastSeen ? fmtDateTime(a.lastSeen) : ""}>{a.lastSeen ? relTime(a.lastSeen) : "never"}</td>
                    <td className="px-3 font-mono tnum">{fmtNum(a.events)}{a.highEvents > 0 && <span className="ml-1 text-sev-high">({a.highEvents} high)</span>}</td>
                    <td className="px-3 font-mono tnum">{a.openAlerts > 0 ? <span className="text-sev-critical">{a.openAlerts}</span> : <span className="text-ink-3">0</span>}</td>
                    <td className="px-3 whitespace-nowrap text-right" onClick={(e) => e.stopPropagation()}>
                      <Button size="sm" variant="ghost" {...lock} onClick={() => setEditing(a)} aria-label={`Edit ${a.hostname}`}><Pencil className="h-3.5 w-3.5" /></Button>
                      <Button size="sm" variant="ghost" {...lock} onClick={() => remove(a)} aria-label={`Remove ${a.hostname}`}><Trash2 className="h-3.5 w-3.5" /></Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {editing && <AssetEditor initial={editing} onClose={() => setEditing(null)} onSaved={(id) => { setEditing(null); load(); setOpen(id); }} />}
      <AssetDrawer id={openId} onClose={() => setOpen(null)} onEdit={(a) => setEditing(a)} write={write} />
    </div>
  );
}

function AssetFindings({ ip, onNavigate }: { ip: string; onNavigate: () => void }) {
  const [list, setList] = useState<{ id: string; title: string; severity: Severity; status: string; port: number; proto: string; cve: string | null; simulated: boolean }[] | null>(null);
  useEffect(() => { api<NonNullable<typeof list>>(`/api/vulns?ip=${encodeURIComponent(ip)}`).then(setList).catch(() => setList([])); }, [ip]);
  const open = list?.filter((f) => f.status === "open") ?? [];
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-[11px] uppercase tracking-wider text-ink-3"><span className="flex items-center gap-1.5"><ShieldAlert className="h-3.5 w-3.5" />Vulnerabilities ({open.length} open)</span>
        <Link href={`/vulnerabilities?ip=${encodeURIComponent(ip)}`} onClick={onNavigate} className="normal-case tracking-normal text-emerald hover:underline">register →</Link></div>
      {!list ? <Skeleton className="h-10" /> : list.length === 0 ? <div className="text-[12px] text-ink-3">No findings recorded. Run a basic vulnerability assessment of this host from the Scan Center.</div> : (
        <ul className="space-y-1">{list.map((f) => (
          <li key={f.id}><Link href={`/vulnerabilities?id=${f.id}`} onClick={onNavigate} className={cx("flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-[12.5px] hover:border-line-strong", f.status !== "open" && "opacity-60")}>
            <SevBadge s={f.severity} /><span className="flex-1 truncate">{f.title}</span>{f.simulated && <SimBadge />}<span className="font-mono text-[11px] text-ink-3">{f.cve ?? `${f.port}/${f.proto}`}</span><span className="text-[11px] text-ink-3">{f.status}</span>
          </Link></li>
        ))}</ul>
      )}
    </div>
  );
}

function AssetEditor({ initial, onClose, onSaved }: { initial: Partial<Asset>; onClose: () => void; onSaved: (id: string) => void }) {
  const toast = useToast();
  const [f, setF] = useState({
    hostname: initial.hostname ?? "", ip: initial.ip ?? "", mac: initial.mac ?? "", os: initial.os ?? "", type: initial.type ?? "server",
    location: initial.location ?? "", owner: initial.owner ?? "", criticality: initial.criticality ?? 3, monitored: initial.monitored ?? true,
    online: initial.online ?? true, notes: initial.notes ?? "",
  });
  const [issues, setIssues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((x) => ({ ...x, [k]: v }));
  const save = async () => {
    setBusy(true); setIssues({});
    const body = { ...f, mac: f.mac || null, os: f.os || null, location: f.location || null, owner: f.owner || null, notes: f.notes || null };
    try {
      const r = await api<{ id: string }>(initial.id ? `/api/assets/${initial.id}` : "/api/assets", { method: initial.id ? "PATCH" : "POST", json: body });
      toast({ tone: "success", title: initial.id ? `${f.hostname} updated` : `${f.hostname} added to inventory` });
      onSaved(r.id ?? initial.id!);
    } catch (e) {
      const list = ((e as ApiError).data as { issues?: { path: string; message: string }[] })?.issues ?? [];
      setIssues(Object.fromEntries(list.map((i) => [i.path, i.message])));
      if (!list.length) toast({ tone: "error", title: "Could not save asset", body: (e as Error).message });
    } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title={initial.id ? `Edit ${initial.hostname}` : "Add asset"} width={640}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={save} disabled={!f.hostname || !f.ip}>{initial.id ? "Save changes" : "Add asset"}</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Hostname" error={issues.hostname}><Input value={f.hostname} onChange={(e) => set("hostname", e.target.value)} placeholder="db-prod-03" autoFocus /></Field>
        <Field label="IP address" error={issues.ip}><Input value={f.ip} onChange={(e) => set("ip", e.target.value)} placeholder="10.20.0.32" className="font-mono" /></Field>
        <Field label="MAC address" error={issues.mac}><Input value={f.mac} onChange={(e) => set("mac", e.target.value)} placeholder="00:1a:2b:3c:4d:5e" className="font-mono" /></Field>
        <Field label="Operating system" error={issues.os}><Input value={f.os} onChange={(e) => set("os", e.target.value)} placeholder="RHEL 9" /></Field>
        <Field label="Type"><Select value={f.type} onChange={(e) => set("type", e.target.value)}>{TYPES.map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}</Select></Field>
        <Field label="Criticality" hint={CRIT_LABEL[f.criticality]}><Select value={f.criticality} onChange={(e) => set("criticality", Number(e.target.value))}>{[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n} · {CRIT_LABEL[n]}</option>)}</Select></Field>
        <Field label="Location" error={issues.location}><Input value={f.location} onChange={(e) => set("location", e.target.value)} placeholder="DC-East" /></Field>
        <Field label="Owner" error={issues.owner}><Input value={f.owner} onChange={(e) => set("owner", e.target.value)} placeholder="data-platform" /></Field>
        <div className="sm:col-span-2"><Field label="Notes" error={issues.notes}><Textarea rows={2} value={f.notes} onChange={(e) => set("notes", e.target.value)} /></Field></div>
        <label className="flex items-center gap-2 text-[13px] text-ink-2"><input type="checkbox" className="accent-emerald" checked={f.monitored} onChange={(e) => set("monitored", e.target.checked)} />Monitored</label>
        <label className="flex items-center gap-2 text-[13px] text-ink-2"><input type="checkbox" className="accent-emerald" checked={f.online} onChange={(e) => set("online", e.target.checked)} />Reachable (online)</label>
      </div>
    </Modal>
  );
}

function AssetDrawer({ id, onClose, onEdit, write }: { id: string | null; onClose: () => void; onEdit: (a: Asset) => void; write: boolean }) {
  const [d, setD] = useState<{ asset: Asset; activity: Activity } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!id) return;
    setD(null); setErr(null);
    api<{ asset: Asset; activity: Activity }>(`/api/assets/${id}`).then(setD).catch((e) => setErr(e.message));
  }, [id]);
  const a = d?.asset, act = d?.activity;
  return (
    <Drawer open={!!id} onClose={onClose} width={720} title={a ? <span className="flex items-center gap-2">{a.hostname}{a.simulated && <SimBadge />}</span> : "Asset"}
      subtitle={a && <span className="font-mono">{a.ip} · {typeLabel(a.type)} · criticality {a.criticality}</span>}
      actions={a && <>
        <Link href={`/log-explorer?q=${encodeURIComponent(`source.ip:${a.ip} OR destination.ip:${a.ip}`)}`} onClick={onClose}><Button size="sm" variant="primary"><Search className="h-3.5 w-3.5" />Investigate events</Button></Link>
        {write && <Button size="sm" onClick={() => onEdit(a)}><Pencil className="h-3.5 w-3.5" />Edit</Button>}
      </>}>
      {err && <div className="p-5"><ErrorState message={err} /></div>}
      {!d && !err && <div className="space-y-2 p-5">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-7" />)}</div>}
      {a && act && (
        <div className="space-y-5 p-5">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[["As source", act.asSource], ["As target", act.asTarget], ["High / critical", act.highSev], ["Related alerts", act.alerts.length]].map(([l, v]) => (
              <div key={l as string} className="rounded-lg border border-line bg-base/60 p-3"><div className="text-[10.5px] uppercase tracking-wider text-ink-3">{l}</div><div className="mt-1 font-mono text-lg tnum">{fmtNum(v as number)}</div></div>
            ))}
          </div>
          <div>
            <KV k="hostname" v={a.hostname} /><KV k="ip" v={a.ip} /><KV k="mac" v={a.mac} /><KV k="os" v={a.os} mono={false} /><KV k="type" v={typeLabel(a.type)} mono={false} />
            <KV k="location" v={a.location} mono={false} /><KV k="owner" v={a.owner} mono={false} /><KV k="criticality" v={<Crit n={a.criticality} />} />
            <KV k="monitoring" v={<Status a={a} />} /><KV k="last_seen" v={act.lastSeen ? fmtDateTime(act.lastSeen) : "no events in the hot buffer"} />
            {a.notes && <KV k="notes" v={a.notes} mono={false} />}
          </div>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Event types involving this asset</div>
            {act.types.length ? <div className="flex flex-wrap gap-1.5">{act.types.map((t) => (
              <Link key={t.key} onClick={onClose} href={`/log-explorer?q=${encodeURIComponent(`(source.ip:${a.ip} OR destination.ip:${a.ip}) AND event.type:${t.key}`)}`}>
                <Tag className="hover:text-emerald">{EVENT_TYPE_LABEL[t.key as EventType] ?? t.key} · {fmtNum(t.value)}</Tag>
              </Link>
            ))}</div> : <div className="text-[12px] text-ink-3">No events in the hot buffer.</div>}
          </div>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Associated alerts</div>
            {act.alerts.length ? <ul className="space-y-1">{act.alerts.map((al) => (
              <li key={al.id}><Link href={`/alerts?id=${al.id}`} onClick={onClose} className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-[12.5px] hover:border-line-strong">
                <SevBadge s={al.severity} /><span className="flex-1 truncate">{al.title}</span><StatusBadge s={al.status} /><span className="text-[11px] text-ink-3">{relTime(al.lastSeen)}</span>
              </Link></li>
            ))}</ul> : <div className="text-[12px] text-ink-3">No alerts reference this asset.</div>}
          </div>
          <AssetFindings ip={a.ip} onNavigate={onClose} />
        </div>
      )}
    </Drawer>
  );
}
