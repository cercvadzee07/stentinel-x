"use client";

import { useReducedMotion } from "framer-motion";
import { Activity, AlertTriangle, Cloud, Cpu, Gauge, HardDrive, Monitor, Network, Router, Search, Server, Shield, Wifi } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button, Drawer, Empty, ErrorState, KV, PageHeader, Panel, SimBadge, Skeleton, Stat, Tag } from "@/components/ui";
import { api, cx, fmtBps, fmtNum, fmtTime } from "@/lib/client";

interface NetNode { id: string; label: string; role: string; tier: number; type: string; ip: string | null; location: string | null; assetIds: string[]; memberIps: string[] }
interface NetLink { id: string; a: string; b: string; aIf: string; bIf: string; speedMbps: number }
interface Iface { name: string; peer: string; speedMbps: number; status: "up" | "down"; inBps: number; outBps: number; util: number; errors: number; discards: number }
interface Sample { t: number; cpu: number; mem: number; latencyMs: number; lossPct: number; inBps: number; outBps: number; up: boolean }
interface Device { nodeId: string; status: "up" | "degraded" | "down"; cpu: number; mem: number; latencyMs: number; lossPct: number; inBps: number; outBps: number; util: number; uptimeSec: number; interfaces: Iface[]; history: Sample[]; availability: { t: number; up: number }[]; fault: string | null }
interface NetState {
  source: "simulator" | "inventory"; simulated: boolean; nodes: NetNode[]; links: NetLink[]; devices: Record<string, Device>;
  linkStats: Record<string, { bps: number; util: number }>; aggregate: { t: number; inBps: number; outBps: number }[];
  health: { up: number; degraded: number; down: number; avgLatencyMs: number; avgLossPct: number; wanBps: number; interfaceErrors: number; busiestLinkUtil: number } | null;
}

const fmtUptime = (s: number) => (s <= 0 ? "—" : s > 86_400 ? `${Math.floor(s / 86_400)}d ${Math.floor((s % 86_400) / 3600)}h` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`);
const utilColor = (u: number) => (u >= 0.85 ? "#ef4444" : u >= 0.6 ? "#f59e0b" : "#10f0a0");
const STATUS_COLOR = { up: "#10f0a0", degraded: "#f59e0b", down: "#ef4444" } as const;
const ROLE_ICON: Record<string, typeof Server> = { internet: Cloud, edge: Shield, core: Router, distribution: Network, access: Wifi, server: Server, endpoints: Monitor };
const TYPE_ICON: Record<string, typeof Server> = { database: HardDrive, domain_controller: Shield, web: Server };

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><NetworkMonitoring /></Suspense>;
}

function NetworkMonitoring() {
  const params = useSearchParams();
  const router = useRouter();
  const [s, setS] = useState<NetState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const openId = params.get("device");
  const load = useCallback(() => api<NetState>("/api/network").then((x) => { setS(x); setErr(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);
  const setOpen = (id: string | null) => router.replace(id ? `/network?device=${encodeURIComponent(id)}` : "/network", { scroll: false });

  const devices = useMemo(() => s ? s.nodes.filter((n) => n.role !== "internet").map((n) => ({ n, d: s.devices[n.id] as Device | undefined })) : [], [s]);
  const ifaceErrors = useMemo(() => devices.flatMap(({ n, d }) => (d?.interfaces ?? []).map((i) => ({ dev: n, i }))).filter((x) => x.i.errors + x.i.discards > 0).sort((a, b) => b.i.errors + b.i.discards - (a.i.errors + a.i.discards)).slice(0, 8), [devices]);

  if (err && !s) return <ErrorState message={err} onRetry={load} />;
  if (!s) return <div className="space-y-4"><Skeleton className="h-8 w-72" /><div className="grid grid-cols-2 gap-3 lg:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-20" />)}</div><Skeleton className="h-[520px]" /></div>;

  const h = s.health;
  return (
    <div className="space-y-4">
      <PageHeader title="Network Monitoring" subtitle={s.simulated
        ? <>Topology inferred from asset inventory · device telemetry <span className="text-violet">simulated</span>; link load derived from live flow events (×{20} sampling)</>
        : "Topology inferred from your asset inventory. No telemetry source (SNMP / streaming telemetry) is connected yet."}
        actions={s.simulated ? <SimBadge /> : <Tag>inventory only</Tag>} />

      {!s.simulated && (
        <div className="flex items-start gap-3 rounded-xl border border-line bg-panel/60 p-4 text-[13px] text-ink-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
          <div>Device health, interface counters and bandwidth require a telemetry integration (SNMP polling or gNMI). The Integrations module ships in Phase 6; until then this page shows the inferred topology only — no metrics are invented.</div>
        </div>
      )}

      {h && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Devices up" value={h.up} accent="emerald" icon={<Activity className="h-3.5 w-3.5" />} hint={`${h.degraded} degraded · ${h.down} down`} />
          <Stat label="Degraded" value={h.degraded} accent={h.degraded ? "medium" : "slate"} pulse={h.degraded > 0} />
          <Stat label="Down" value={h.down} accent={h.down ? "critical" : "slate"} />
          <Stat label="Avg latency" value={h.avgLatencyMs} format={(v) => `${v.toFixed(1)} ms`} accent="cyan" icon={<Gauge className="h-3.5 w-3.5" />} />
          <Stat label="Avg packet loss" value={h.avgLossPct} format={(v) => `${v.toFixed(2)} %`} accent={h.avgLossPct > 0.5 ? "high" : "cyan"} />
          <Stat label="WAN throughput" value={h.wanBps} format={fmtBps} accent="cyan" hint={`busiest link ${(h.busiestLinkUtil * 100).toFixed(0)} % · ${fmtNum(h.interfaceErrors)} if-errors`} />
        </div>
      )}

      <Panel title="Topology" subtitle="Click a device for interfaces, traffic and availability" bodyClass="p-2"
        actions={<div className="flex items-center gap-3 text-[10.5px] text-ink-3">{[["< 60 %", "#10f0a0"], ["60–85 %", "#f59e0b"], ["> 85 %", "#ef4444"]].map(([l, c]) => <span key={l} className="flex items-center gap-1"><span className="h-0.5 w-4 rounded" style={{ background: c }} />{l}</span>)}</div>}>
        <Topology s={s} hover={hover} setHover={setHover} onOpen={setOpen} selected={openId} />
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="WAN traffic" subtitle="Aggregate across edge firewalls" className="xl:col-span-2">
          {s.aggregate.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={s.aggregate} margin={{ top: 6, right: 4, bottom: 0, left: 4 }}>
                <defs>
                  <linearGradient id="wanIn" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.4} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
                  <linearGradient id="wanOut" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity={0.4} /><stop offset="100%" stopColor="#3b82f6" stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid stroke="#1d252e" strokeDasharray="2 4" vertical={false} />
                <XAxis dataKey="t" tickFormatter={fmtTime} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} minTickGap={50} />
                <YAxis tickFormatter={fmtBps} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10.5 }} tickLine={false} axisLine={false} width={64} />
                <Tooltip formatter={(v: number) => fmtBps(v)} labelFormatter={(l) => fmtTime(Number(l))} contentStyle={{ background: "#0e1217", border: "1px solid #2a3540", borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="inBps" name="in" stroke="#22d3ee" fill="url(#wanIn)" isAnimationActive={false} />
                <Area type="monotone" dataKey="outBps" name="out" stroke="#3b82f6" fill="url(#wanOut)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : <Empty title="No telemetry" />}
        </Panel>
        <Panel title="Interface errors" subtitle="Errors + discards since sampling began">
          {ifaceErrors.length ? <ul className="space-y-1.5">{ifaceErrors.map(({ dev, i }) => (
            <li key={dev.id + i.name}><button onClick={() => setOpen(dev.id)} className="flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-[12px] hover:bg-raised">
              <span className="font-medium text-ink">{dev.label}</span><span className="font-mono text-ink-3">{i.name}</span>
              <span className="ml-auto font-mono text-sev-high tnum">{fmtNum(i.errors)} err</span><span className="font-mono text-ink-3 tnum">{fmtNum(i.discards)} disc</span>
            </button></li>
          ))}</ul> : <Empty title={s.simulated ? "No interface errors" : "No telemetry"} body={s.simulated ? "Errors accumulate when links run above 90 % utilisation." : undefined} />}
        </Panel>
      </div>

      <Panel title="Device inventory" bodyClass="p-0">
        <div className="overflow-x-auto scrollbar-thin">
          <table className="w-full text-[12.5px]">
            <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">
              {["Device", "Role", "IP", "Status", "CPU", "Memory", "Latency", "Loss", "In", "Out", "Uptime"].map((x) => <th key={x} className="px-3 py-2 font-medium whitespace-nowrap">{x}</th>)}
            </tr></thead>
            <tbody>
              {devices.map(({ n, d }) => (
                <tr key={n.id} onClick={() => d && setOpen(n.id)} className={cx("border-b border-line/40", d && "cursor-pointer hover:bg-emerald/[0.04]", openId === n.id && "bg-emerald/[0.08]")}>
                  <td className="px-3 py-1.5 whitespace-nowrap font-medium text-ink">{n.label}</td>
                  <td className="px-3 text-ink-2">{n.role}</td>
                  <td className="px-3 font-mono text-ink-3">{n.ip ?? `${n.memberIps.length} hosts`}</td>
                  <td className="px-3">{d ? <span className="inline-flex items-center gap-1.5 text-[11.5px]" style={{ color: STATUS_COLOR[d.status] }}><span className="h-1.5 w-1.5 rounded-full" style={{ background: STATUS_COLOR[d.status] }} />{d.status}{d.fault && <span className="text-ink-3">({d.fault})</span>}</span> : <span className="text-ink-3">no telemetry</span>}</td>
                  <td className="px-3"><Bar v={d?.cpu} /></td>
                  <td className="px-3"><Bar v={d?.mem} /></td>
                  <td className="px-3 font-mono tnum text-ink-2">{d ? `${d.latencyMs.toFixed(1)} ms` : "—"}</td>
                  <td className={cx("px-3 font-mono tnum", d && d.lossPct > 0.5 ? "text-sev-high" : "text-ink-2")}>{d ? `${d.lossPct.toFixed(1)} %` : "—"}</td>
                  <td className="px-3 font-mono tnum text-ink-2 whitespace-nowrap">{d ? fmtBps(d.inBps) : "—"}</td>
                  <td className="px-3 font-mono tnum text-ink-2 whitespace-nowrap">{d ? fmtBps(d.outBps) : "—"}</td>
                  <td className="px-3 font-mono text-ink-3 whitespace-nowrap">{d ? fmtUptime(d.uptimeSec) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <DeviceDrawer id={openId} onClose={() => setOpen(null)} />
    </div>
  );
}

function Bar({ v }: { v?: number }) {
  if (v === undefined) return <span className="text-ink-3">—</span>;
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-1.5 w-14 overflow-hidden rounded-full bg-line-strong"><span className="block h-full rounded-full" style={{ width: `${v}%`, background: v > 85 ? "#ef4444" : v > 65 ? "#f59e0b" : "#10f0a0" }} /></span>
      <span className="font-mono text-[11px] tnum text-ink-2">{v.toFixed(0)}%</span>
    </span>
  );
}

// ── topology ───────────────────────────────────────────────────────────
function Topology({ s, hover, setHover, onOpen, selected }: { s: NetState; hover: string | null; setHover: (id: string | null) => void; onOpen: (id: string) => void; selected: string | null }) {
  const reduce = useReducedMotion();
  const W = 1200, ROW = 100;
  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>();
    const tiers = new Map<number, NetNode[]>();
    for (const n of s.nodes) tiers.set(n.tier, [...(tiers.get(n.tier) ?? []), n]);
    let maxY = 0;
    // barycentric ordering: place each node under the mean x of its already-placed parents to minimise crossings
    const parentX = (id: string) => {
      const xs = s.links.filter((l) => l.b === id).map((l) => pos.get(l.a)?.x).filter((x): x is number => x !== undefined);
      return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : W / 2;
    };
    for (const [tier, list] of [...tiers.entries()].sort((a, b) => a[0] - b[0])) {
      const sorted = [...list].sort((a, b) => parentX(a.id) - parentX(b.id) || (a.location ?? "").localeCompare(b.location ?? "") || a.label.localeCompare(b.label));
      const dense = sorted.length > 11;
      sorted.forEach((n, i) => {
        const x = ((i + 0.5) / sorted.length) * (W - 60) + 30;
        const y = 50 + tier * ROW + (tier >= 4 ? 20 : 0) + (dense ? (i % 2) * 46 : 0) + (tier === 5 ? 46 : 0);
        pos.set(n.id, { x, y });
        maxY = Math.max(maxY, y);
      });
    }
    return { pos, H: maxY + 60 };
  }, [s.nodes]);
  const near = hover ? new Set(s.links.filter((l) => l.a === hover || l.b === hover).flatMap((l) => [l.a, l.b])) : null;

  return (
    <div className="overflow-x-auto scrollbar-thin">
      <svg viewBox={`0 0 ${W} ${layout.H}`} className="min-w-[900px] w-full" role="img" aria-label="Network topology">
        {s.links.map((l) => {
          const a = layout.pos.get(l.a), b = layout.pos.get(l.b);
          if (!a || !b) return null;
          const st = s.linkStats[l.id];
          const u = st?.util ?? 0;
          const color = st ? utilColor(u) : "#2a3540";
          const my = (a.y + b.y) / 2;
          const d = `M${a.x},${a.y} C${a.x},${my} ${b.x},${my} ${b.x},${b.y}`;
          const dim = near && !(near.has(l.a) && near.has(l.b));
          const dots = !st || reduce ? 0 : u > 0.6 ? 3 : u > 0.1 ? 2 : u > 0.005 ? 1 : 0;
          return (
            <g key={l.id} opacity={dim ? 0.15 : 1}>
              <path d={d} fill="none" stroke={color} strokeOpacity={0.35} strokeWidth={l.speedMbps >= 10_000 ? 3 : 1.6} />
              <path d={d} fill="none" stroke={color} strokeOpacity={0.9} strokeWidth={0.8} strokeDasharray={st ? undefined : "3 4"}>
                <title>{`${l.aIf} ↔ ${l.bIf} · ${l.speedMbps >= 1000 ? `${l.speedMbps / 1000} Gbit` : `${l.speedMbps} Mbit`}${st ? ` · ${(u * 100).toFixed(1)} % · ${fmtBps(st.bps)}` : ""}`}</title>
              </path>
              {Array.from({ length: dots }, (_, i) => (
                <circle key={i} r={2.2} fill={color}>
                  <animateMotion dur={`${Math.max(0.8, 3.2 - u * 2.6)}s`} begin={`${i * 0.6}s`} repeatCount="indefinite" path={d} />
                </circle>
              ))}
            </g>
          );
        })}
        {s.nodes.map((n) => {
          const p = layout.pos.get(n.id)!;
          const d = s.devices[n.id];
          const Icon = (n.role === "server" && TYPE_ICON[n.type]) || ROLE_ICON[n.role] || Server;
          const ring = d ? STATUS_COLOR[d.status] : n.role === "internet" ? "#22d3ee" : "#4b5563";
          const dim = near && !near.has(n.id);
          const big = n.role === "internet" || n.role === "edge" || n.role === "core" || n.role === "distribution";
          const r = big ? 20 : 15;
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.25 : 1} style={{ cursor: d ? "pointer" : "default" }}
              onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} onClick={() => d && onOpen(n.id)}>
              {d?.status === "degraded" && !reduce && <circle r={r + 4} fill="none" stroke={ring} strokeOpacity={0.6}><animate attributeName="r" from={r} to={r + 12} dur="1.6s" repeatCount="indefinite" /><animate attributeName="stroke-opacity" from="0.7" to="0" dur="1.6s" repeatCount="indefinite" /></circle>}
              <circle r={r} fill="#0e1217" stroke={ring} strokeWidth={selected === n.id ? 3 : 1.6} />
              <foreignObject x={-r / 1.8} y={-r / 1.8} width={r * 1.1} height={r * 1.1} style={{ pointerEvents: "none" }}>
                <Icon color={ring} width="100%" height="100%" strokeWidth={1.8} />
              </foreignObject>
              <text y={r + 13} textAnchor="middle" fill="#a7b3bf" fontSize={10.5} fontFamily="var(--font-inter)">{n.label}</text>
              {d && big && <text y={r + 25} textAnchor="middle" fill="#6b7785" fontSize={9.5} fontFamily="var(--font-jetbrains)">{d.status === "down" ? "DOWN" : `${d.cpu.toFixed(0)}% cpu · ${d.latencyMs.toFixed(1)}ms`}</text>}
              <title>{`${n.label}${n.ip ? ` (${n.ip})` : ""}${d ? ` — ${d.status}${d.fault ? `, ${d.fault}` : ""}` : ""}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── device drawer ──────────────────────────────────────────────────────
function DeviceDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [d, setD] = useState<{ node: NetNode; device: Device; assets: { id: string; hostname: string; ip: string; os: string | null; owner: string | null }[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!id) return;
    setD(null); setErr(null);
    const load = () => api<NonNullable<typeof d>>(`/api/network/${encodeURIComponent(id)}`).then(setD).catch((e) => setErr(e.message));
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [id]);
  const dev = d?.device;
  const hist = dev?.history.map((h) => ({ ...h, inMbps: h.inBps / 1e6, outMbps: h.outBps / 1e6 })) ?? [];
  const chart = (title: string, lines: { k: string; c: string; n: string }[], fmt: (v: number) => string) => (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">{title}</div>
      <ResponsiveContainer width="100%" height={120}>
        <LineChart data={hist} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="#1d252e" strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="t" tickFormatter={fmtTime} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={60} />
          <YAxis tickFormatter={fmt} stroke="#2a3540" tick={{ fill: "#6b7785", fontSize: 10 }} tickLine={false} axisLine={false} width={52} />
          <Tooltip formatter={(v: number) => fmt(v)} labelFormatter={(l) => fmtTime(Number(l))} contentStyle={{ background: "#0e1217", border: "1px solid #2a3540", borderRadius: 8, fontSize: 12 }} />
          {lines.map((l) => <Line key={l.k} type="monotone" dataKey={l.k} name={l.n} stroke={l.c} dot={false} strokeWidth={1.5} isAnimationActive={false} />)}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
  return (
    <Drawer open={!!id} onClose={onClose} width={800}
      title={d ? <span className="flex items-center gap-2">{d.node.label}<SimBadge /><span className="text-[12px] font-normal" style={{ color: STATUS_COLOR[d.device.status] }}>● {d.device.status}</span></span> : "Device"}
      subtitle={d && <span className="font-mono">{d.node.ip ?? `${d.node.memberIps.length} endpoints`} · {d.node.role} · {d.node.location ?? "—"}</span>}
      actions={d?.node.ip && <Link href={`/log-explorer?q=${encodeURIComponent(`source.ip:${d.node.ip} OR destination.ip:${d.node.ip}`)}`} onClick={onClose}><Button size="sm"><Search className="h-3.5 w-3.5" />Events</Button></Link>}>
      {err && <div className="p-5"><ErrorState message={err} /></div>}
      {!d && !err && <div className="space-y-2 p-5">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div>}
      {d && dev && (
        <div className="space-y-5 p-5">
          {dev.fault && <div className="flex items-center gap-2 rounded-lg border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-[12.5px] text-amber-200"><AlertTriangle className="h-4 w-4" />Active fault: {dev.fault} (simulated fault injection)</div>}
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
            {[["CPU", `${dev.cpu.toFixed(0)} %`], ["Memory", `${dev.mem.toFixed(0)} %`], ["Latency", `${dev.latencyMs.toFixed(1)} ms`], ["Loss", `${dev.lossPct.toFixed(2)} %`], ["In", fmtBps(dev.inBps)], ["Uptime", fmtUptime(dev.uptimeSec)]].map(([k, v]) => (
              <div key={k} className="rounded-lg border border-line bg-base/60 p-2.5"><div className="text-[10px] uppercase tracking-wider text-ink-3">{k}</div><div className="mt-0.5 font-mono text-[14px] tnum">{v}</div></div>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {chart("CPU / memory", [{ k: "cpu", c: "#10f0a0", n: "cpu" }, { k: "mem", c: "#a78bfa", n: "mem" }], (v) => `${v.toFixed(0)}%`)}
            {chart("Latency", [{ k: "latencyMs", c: "#22d3ee", n: "latency" }], (v) => `${v.toFixed(1)}ms`)}
            {chart("Traffic (Mbps)", [{ k: "inMbps", c: "#22d3ee", n: "in" }, { k: "outMbps", c: "#3b82f6", n: "out" }], (v) => v.toFixed(v < 10 ? 1 : 0))}
            {chart("Packet loss", [{ k: "lossPct", c: "#ef4444", n: "loss" }], (v) => `${v.toFixed(1)}%`)}
          </div>
          <div>
            <div className="mb-1.5 flex items-center justify-between text-[11px] uppercase tracking-wider text-ink-3"><span>Availability · last {dev.availability.length} min</span>
              <span className="normal-case tracking-normal">{((dev.availability.reduce((s, a) => s + a.up, 0) / Math.max(1, dev.availability.length)) * 100).toFixed(2)} %</span></div>
            <div className="flex gap-[2px]">{dev.availability.map((a) => <span key={a.t} title={`${fmtTime(a.t)} · ${(a.up * 100).toFixed(0)} % up`} className="h-6 flex-1 rounded-sm" style={{ background: a.up >= 0.999 ? "#10f0a0" : a.up > 0.5 ? "#f59e0b" : "#ef4444", opacity: 0.8 }} />)}</div>
          </div>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">Interfaces</div>
            <table className="w-full text-[12px]">
              <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Interface", "Peer", "Speed", "Status", "Util", "In", "Out", "Errors", "Discards"].map((x) => <th key={x} className="py-1.5 pr-2 font-medium">{x}</th>)}</tr></thead>
              <tbody>{dev.interfaces.map((i) => (
                <tr key={i.name + i.peer} className="border-b border-line/40">
                  <td className="py-1.5 pr-2 font-mono text-ink">{i.name}</td><td className="pr-2 text-ink-2">{i.peer}</td>
                  <td className="pr-2 font-mono text-ink-3">{i.speedMbps >= 1000 ? `${i.speedMbps / 1000}G` : `${i.speedMbps}M`}</td>
                  <td className={cx("pr-2", i.status === "up" ? "text-emerald" : "text-sev-critical")}>{i.status}</td>
                  <td className="pr-2 font-mono tnum" style={{ color: utilColor(i.util) }}>{(i.util * 100).toFixed(1)}%</td>
                  <td className="pr-2 font-mono tnum text-ink-2">{fmtBps(i.inBps)}</td><td className="pr-2 font-mono tnum text-ink-2">{fmtBps(i.outBps)}</td>
                  <td className={cx("pr-2 font-mono tnum", i.errors ? "text-sev-high" : "text-ink-3")}>{fmtNum(i.errors)}</td><td className="font-mono tnum text-ink-3">{fmtNum(i.discards)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          {d.assets.length > 0 && <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">Inventory</div>
            {d.assets.length === 1 ? <><KV k="hostname" v={d.assets[0].hostname} /><KV k="ip" v={d.assets[0].ip} /><KV k="os" v={d.assets[0].os} mono={false} /><KV k="owner" v={d.assets[0].owner} mono={false} /></>
              : <div className="flex flex-wrap gap-1">{d.assets.map((a) => <Link key={a.id} href={`/assets?id=${a.id}`} onClick={onClose}><Tag className="hover:text-emerald">{a.hostname}</Tag></Link>)}</div>}
          </div>}
          <p className="flex items-center gap-1.5 text-[11px] text-ink-3"><Cpu className="h-3.5 w-3.5" />Telemetry is simulated for the demo tenant: CPU, memory and latency respond to link load derived from live flow events.</p>
        </div>
      )}
    </Drawer>
  );
}
