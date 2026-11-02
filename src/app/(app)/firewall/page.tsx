"use client";

import { Ban, CheckCircle2, Flame, Search, ShieldAlert, X } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { BarList, Donut } from "@/components/charts";
import { EventDrawer, EventTable } from "@/components/events";
import { Button, Empty, ErrorState, Input, PageHeader, Panel, Select, SevBadge, Skeleton, Stat, Tag } from "@/components/ui";
import { api, cx, fmtBytes, fmtCompact, fmtNum, fmtTime } from "@/lib/client";
import { TIME_RANGES } from "@/lib/query";
import type { SecurityEvent, Severity } from "@/lib/types";

interface Stats {
  query: string;
  totals: { events: number; allowed: number; blocked: number; bytes: number; blockRate: number };
  series: { t: number; allow: number; deny: number }[];
  topSources: { key: string; allow: number; deny: number; external: boolean; country: string | null }[];
  topDestinations: { key: string; value: number }[];
  topPorts: { key: string; allow: number; deny: number }[];
  protocols: { key: string; value: number }[];
  devices: { name: string; allow: number; deny: number; hostname: string | null; ip: string | null; health: { status: string; cpu: number; mem: number; sessions: number; wanUtil: number; fault: string | null } | null }[];
  patterns: { kind: string; title: string; severity: Severity; entity: string; count: number; detail: string; query: string }[];
  recent: SecurityEvent[];
  tookMs: number;
}

const EMPTY = { src: "", sport: "", dst: "", dport: "", proto: "", action: "", device: "" };
const PROTO_COLORS = ["#22d3ee", "#3b82f6", "#a78bfa", "#10f0a0", "#f59e0b", "#64748b"];

export default function FirewallPage() {
  const [f, setF] = useState(EMPTY);
  const [applied, setApplied] = useState(EMPTY);
  const [range, setRange] = useState("30m");
  const [s, setS] = useState<Stats | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [devices, setDevices] = useState<string[]>([]);

  const load = useCallback(() => {
    const ms = TIME_RANGES.find((r) => r.value === range)?.ms || 24 * 3_600_000;
    const p = new URLSearchParams({ from: String(Date.now() - ms), ...Object.fromEntries(Object.entries(applied).filter(([, v]) => v)) });
    return api<Stats>(`/api/firewall?${p}`).then((x) => { setS(x); setErr(null); if (!applied.device) setDevices(x.devices.map((d) => d.name)); }).catch((e) => setErr(e.message));
  }, [applied, range]);
  useEffect(() => { load(); const t = setInterval(load, 10_000); return () => clearInterval(t); }, [load]);

  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF((x) => ({ ...x, [k]: e.target.value }));
  const apply = (next = f) => { setF(next); setApplied(next); };
  const pivot = (k: keyof typeof EMPTY, v: string) => apply({ ...f, [k]: v });
  const active = Object.entries(applied).filter(([, v]) => v);
  const maxSrc = useMemo(() => Math.max(1, ...(s?.topSources ?? []).map((x) => x.allow + x.deny)), [s]);

  return (
    <div className="space-y-4">
      <PageHeader title="Firewall Monitoring" subtitle="Perimeter allow / deny analytics computed from normalized firewall events"
        actions={s && <Link href={`/log-explorer?q=${encodeURIComponent(s.query)}`}><Button><Search className="h-3.5 w-3.5" />Open in Log Explorer</Button></Link>} />

      <Panel bodyClass="p-3">
        <form onSubmit={(e) => { e.preventDefault(); apply(); }} className="flex flex-wrap items-end gap-2">
          {([["src", "Source address", "203.0.113.0/24", "w-40"], ["sport", "Src port", "1024..65535", "w-28"], ["dst", "Destination", "10.10.1.10", "w-36"], ["dport", "Dst port", "22", "w-24"]] as const).map(([k, label, ph, w]) => (
            <label key={k} className="flex flex-col gap-1"><span className="text-[10.5px] uppercase tracking-wider text-ink-3">{label}</span><Input value={f[k]} onChange={set(k)} placeholder={ph} className={cx("font-mono", w)} /></label>
          ))}
          <label className="flex flex-col gap-1"><span className="text-[10.5px] uppercase tracking-wider text-ink-3">Protocol</span>
            <Select value={f.proto} onChange={set("proto")}><option value="">Any</option>{["tcp", "udp", "icmp", "dns"].map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}</Select></label>
          <label className="flex flex-col gap-1"><span className="text-[10.5px] uppercase tracking-wider text-ink-3">Action</span>
            <Select value={f.action} onChange={set("action")}><option value="">Allow + deny</option><option value="allow">Allowed</option><option value="deny">Blocked</option></Select></label>
          <label className="flex flex-col gap-1"><span className="text-[10.5px] uppercase tracking-wider text-ink-3">Device</span>
            <Select value={f.device} onChange={set("device")}><option value="">All firewalls</option>{devices.map((d) => <option key={d} value={d}>{d}</option>)}</Select></label>
          <label className="flex flex-col gap-1"><span className="text-[10.5px] uppercase tracking-wider text-ink-3">Time range</span>
            <Select value={range} onChange={(e) => setRange(e.target.value)}>{TIME_RANGES.filter((r) => r.value !== "all").map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}</Select></label>
          <Button type="submit" variant="primary">Apply</Button>
          {active.length > 0 && <Button type="button" variant="ghost" onClick={() => apply(EMPTY)}><X className="h-3.5 w-3.5" />Clear</Button>}
        </form>
        {s && <div className="mt-2 truncate font-mono text-[11px] text-cyan" title={s.query}>{s.query}<span className="ml-2 text-ink-3">· {s.tookMs} ms</span></div>}
      </Panel>

      {err && <ErrorState message={err} onRetry={load} />}
      {!s ? <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-20" />)}</div> : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Allowed connections" value={s.totals.allowed} format={fmtCompact} accent="emerald" icon={<CheckCircle2 className="h-3.5 w-3.5" />} />
            <Stat label="Blocked connections" value={s.totals.blocked} format={fmtCompact} accent="high" icon={<Ban className="h-3.5 w-3.5" />} hint={`${(s.totals.blockRate * 100).toFixed(1)} % block rate`} />
            <Stat label="Suspicious patterns" value={s.patterns.length} accent={s.patterns.some((p) => p.severity === "critical") ? "critical" : "medium"} icon={<ShieldAlert className="h-3.5 w-3.5" />} pulse={s.patterns.some((p) => p.severity === "critical")} />
            <Stat label="Bytes (sampled flows)" value={s.totals.bytes} format={fmtBytes} accent="cyan" />
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Allowed vs denied over time" className="xl:col-span-2">
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={s.series} margin={{ top: 6, right: 4, bottom: 0, left: -12 }}>
                  <CartesianGrid stroke="#1d252e" strokeDasharray="2 4" vertical={false} />
                  <XAxis dataKey="t" tickFormatter={(t) => fmtTime(t).slice(0, 5)} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} minTickGap={40} />
                  <YAxis tickFormatter={fmtCompact} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} width={48} />
                  <Tooltip labelFormatter={(l) => fmtTime(Number(l))} contentStyle={{ background: "#0e1217", border: "1px solid #2a3540", borderRadius: 8, fontSize: 12 }} />
                  <Area type="monotone" dataKey="allow" name="allowed (flows)" stackId="1" stroke="#10f0a0" fill="#10f0a0" fillOpacity={0.15} isAnimationActive={false} />
                  <Area type="monotone" dataKey="deny" name="denied" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.35} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </Panel>
            <Panel title="Suspicious connection patterns" bodyClass="p-2" subtitle="Heuristics over the filtered window">
              {s.patterns.length ? <ul className="max-h-[230px] space-y-1 overflow-y-auto scrollbar-thin">{s.patterns.map((p) => (
                <li key={p.kind + p.entity}><Link href={`/log-explorer?q=${encodeURIComponent(p.query)}`} className="block rounded-lg border border-line px-2.5 py-1.5 hover:border-line-strong">
                  <div className="flex items-center gap-2 text-[12.5px]"><SevBadge s={p.severity} glow /><span className="truncate text-ink">{p.title}</span></div>
                  <div className="mt-0.5 flex gap-2 font-mono text-[11px] text-ink-3"><span className="truncate text-ink-2">{p.entity}</span><span className="ml-auto shrink-0">{p.detail}</span></div>
                </Link></li>
              ))}</ul> : <Empty icon={<Flame className="h-5 w-5" />} title="No suspicious patterns" body="Launch a port scan or C2 scenario from the simulator to see detections here." />}
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
            <Panel title="Top source addresses" className="lg:col-span-2" bodyClass="p-2">
              <table className="w-full text-[12px]"><tbody>{s.topSources.map((x) => (
                <tr key={x.key} className="group">
                  <td className="py-1 pl-2"><button onClick={() => pivot("src", x.key)} className="font-mono text-ink-2 hover:text-emerald" title="Filter on this source">{x.key}</button>
                    {x.external && <span className="ml-1.5 text-[10px] text-ink-3">{x.country ?? "external"}</span>}</td>
                  <td className="w-1/2 px-2">
                    <div className="flex h-2 overflow-hidden rounded-full bg-line" style={{ width: `${((x.allow + x.deny) / maxSrc) * 100}%` }}>
                      <span className="bg-emerald/70" style={{ width: `${(x.allow / Math.max(1, x.allow + x.deny)) * 100}%` }} /><span className="flex-1 bg-sev-high/80" />
                    </div>
                  </td>
                  <td className="pr-2 text-right font-mono tnum text-ink-3"><span className="text-emerald">{fmtNum(x.allow)}</span> / <span className="text-sev-high">{fmtNum(x.deny)}</span></td>
                </tr>
              ))}</tbody></table>
              {!s.topSources.length && <Empty title="No firewall events" />}
            </Panel>
            <Panel title="Top destinations"><BarList items={s.topDestinations.slice(0, 8)} color="#22d3ee" query={(k) => `${s.query} AND destination.ip:${k}`} /></Panel>
            <Panel title="Protocols"><Donut data={s.protocols.map((p, i) => ({ name: p.key, value: p.value, color: PROTO_COLORS[i % PROTO_COLORS.length] }))} height={150} />
              <div className="mt-2 flex flex-wrap justify-center gap-2 text-[11px]">{s.protocols.map((p, i) => <button key={p.key} onClick={() => pivot("proto", p.key)} className="flex items-center gap-1 text-ink-2 hover:text-emerald"><span className="h-2 w-2 rounded-sm" style={{ background: PROTO_COLORS[i % PROTO_COLORS.length] }} />{p.key.toUpperCase()} {fmtCompact(p.value)}</button>)}</div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Top destination ports" bodyClass="p-2">
              <table className="w-full text-[12px]"><thead><tr className="text-left text-[10.5px] uppercase tracking-wider text-ink-3"><th className="px-2 py-1 font-medium">Port</th><th className="font-medium">Allowed</th><th className="font-medium">Denied</th></tr></thead>
                <tbody>{s.topPorts.map((p) => (
                  <tr key={p.key} className="border-t border-line/40"><td className="px-2 py-1"><button onClick={() => pivot("dport", p.key)} className="font-mono text-ink hover:text-emerald">{p.key}</button></td>
                    <td className="font-mono tnum text-emerald">{fmtNum(p.allow)}</td><td className="font-mono tnum text-sev-high">{fmtNum(p.deny)}</td></tr>
                ))}</tbody></table>
            </Panel>
            <Panel title="Firewall device health" className="xl:col-span-2">
              {s.devices.length ? <div className="grid gap-2 sm:grid-cols-2">{s.devices.map((d) => (
                <button key={d.name} onClick={() => pivot("device", d.name)} className="rounded-lg border border-line bg-base/50 p-3 text-left hover:border-line-strong">
                  <div className="flex items-center gap-2"><Flame className="h-4 w-4 text-sev-high" /><span className="text-[13px] font-medium">{d.hostname ?? d.name}</span>
                    {d.health && <span className={cx("ml-auto text-[11px]", d.health.status === "up" ? "text-emerald" : d.health.status === "degraded" ? "text-sev-medium" : "text-sev-critical")}>● {d.health.status}</span>}</div>
                  <div className="mt-0.5 text-[11px] text-ink-3">{d.name}{d.ip && <span className="font-mono"> · {d.ip}</span>}</div>
                  <div className="mt-2 grid grid-cols-4 gap-1 text-center">
                    {[["allowed", fmtCompact(d.allow), "text-emerald"], ["denied", fmtCompact(d.deny), "text-sev-high"], ["cpu", d.health ? `${d.health.cpu.toFixed(0)}%` : "—", "text-ink"], ["WAN", d.health ? `${(d.health.wanUtil * 100).toFixed(0)}%` : "—", "text-cyan"]].map(([k, v, c]) => (
                      <div key={k} className="rounded bg-raised/60 py-1"><div className={cx("font-mono text-[13px] tnum", c)}>{v}</div><div className="text-[9.5px] uppercase tracking-wider text-ink-3">{k}</div></div>
                    ))}
                  </div>
                  {!d.health && <div className="mt-1.5 text-[10.5px] text-ink-3">No telemetry for this device</div>}
                  {d.health?.fault && <div className="mt-1.5 text-[10.5px] text-sev-medium">fault: {d.health.fault} (simulated)</div>}
                </button>
              ))}</div> : <Empty title="No firewall devices seen in this window" />}
            </Panel>
          </div>

          <Panel title="Recent firewall events" bodyClass="p-0" actions={<Tag>{fmtNum(s.totals.events)} matching</Tag>}>
            <div className="max-h-[420px] overflow-y-auto scrollbar-thin">
              <EventTable events={s.recent} onOpen={(e) => setOpen(e.id)} cols={["time", "action", "src", "dst", "proto", "vendor", "product", "bytes", "count"]} dense />
            </div>
          </Panel>
        </>
      )}
      <EventDrawer id={open} onClose={() => setOpen(null)} onOpen={(e) => setOpen(e.id)} />
    </div>
  );
}
