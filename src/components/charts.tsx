"use client";

import { motion, useReducedMotion } from "framer-motion";
import Link from "next/link";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { SEV_COLOR, fmtBytes, fmtCompact, fmtTime } from "@/lib/client";
import { SEVERITIES, type Severity } from "@/lib/types";

const AXIS = { stroke: "#2a3540", tick: { fill: "#6b7785", fontSize: 10.5 }, tickLine: false, axisLine: false } as const;
const GRID = <CartesianGrid stroke="#1d252e" strokeDasharray="2 4" vertical={false} />;

function Tip({ active, payload, label, fmt = fmtCompact, labelFmt = fmtTime }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-line-strong bg-panel/95 px-2.5 py-2 text-[11.5px] shadow-xl backdrop-blur">
      {label !== undefined && <div className="mb-1 font-mono text-ink-3">{typeof label === "number" ? labelFmt(label) : label}</div>}
      {payload.map((p: any) => (
        <div key={p.dataKey ?? p.name} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-sm" style={{ background: p.color ?? p.payload?.fill }} />
          <span className="text-ink-2">{p.name}</span>
          <span className="ml-auto pl-3 font-mono text-ink tnum">{fmt(p.value)}</span>
        </div>
      ))}
    </div>
  );
}

export function EpsChart({ data, height = 150 }: { data: { t: number; v: number }[]; height?: number }) {
  const reduce = useReducedMotion();
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id="eps" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10f0a0" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#10f0a0" stopOpacity={0} />
          </linearGradient>
        </defs>
        {GRID}
        <XAxis dataKey="t" {...AXIS} tickFormatter={fmtTime} minTickGap={50} />
        <YAxis {...AXIS} width={44} tickFormatter={fmtCompact} />
        <Tooltip content={<Tip />} cursor={{ stroke: "#10f0a0", strokeOpacity: 0.3 }} />
        <Area type="monotone" dataKey="v" name="events/s" stroke="#10f0a0" strokeWidth={1.6} fill="url(#eps)" isAnimationActive={!reduce} animationDuration={300} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityTimeline({ data, height = 190, onSelect }: { data: ({ t: number } & Record<Severity, number>)[]; height?: number; onSelect?: (t: number) => void }) {
  const reduce = useReducedMotion();
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -18 }} barCategoryGap={1}
        onClick={(s: any) => s?.activeLabel !== undefined && onSelect?.(Number(s.activeLabel))}>
        {GRID}
        <XAxis dataKey="t" {...AXIS} tickFormatter={(t) => fmtTime(t).slice(0, 5)} minTickGap={40} />
        <YAxis {...AXIS} width={44} tickFormatter={fmtCompact} />
        <Tooltip content={<Tip />} cursor={{ fill: "#ffffff08" }} />
        {SEVERITIES.map((s) => (
          <Bar key={s} dataKey={s} name={s} stackId="a" fill={SEV_COLOR[s]} fillOpacity={s === "info" ? 0.55 : 0.9} isAnimationActive={!reduce} animationDuration={350} style={{ cursor: onSelect ? "pointer" : undefined }} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TrafficChart({ data, height = 190 }: { data: { t: number; inbound: number; outbound: number; internal: number }[]; height?: number }) {
  const series = [
    { k: "inbound", c: "#22d3ee" }, { k: "outbound", c: "#3b82f6" }, { k: "internal", c: "#a78bfa" },
  ];
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -6 }}>
        <defs>
          {series.map((s) => (
            <linearGradient key={s.k} id={`tr-${s.k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.c} stopOpacity={0.35} />
              <stop offset="100%" stopColor={s.c} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        {GRID}
        <XAxis dataKey="t" {...AXIS} tickFormatter={(t) => fmtTime(t).slice(0, 5)} minTickGap={40} />
        <YAxis {...AXIS} width={56} tickFormatter={fmtBytes} />
        <Tooltip content={<Tip fmt={fmtBytes} />} />
        {series.map((s) => <Area key={s.k} type="monotone" dataKey={s.k} name={s.k} stroke={s.c} strokeWidth={1.4} fill={`url(#tr-${s.k})`} isAnimationActive={false} />)}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function Donut({ data, height = 180, center }: { data: { name: string; value: number; color: string }[]; height?: number; center?: React.ReactNode }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Tooltip content={<Tip labelFmt={String} />} />
          <Pie data={data} dataKey="value" nameKey="name" innerRadius="66%" outerRadius="92%" paddingAngle={1.5} stroke="none" isAnimationActive={false}>
            {data.map((d) => <Cell key={d.name} fill={d.color} />)}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
        {center ?? <div><div className="text-lg font-semibold tnum">{fmtCompact(total)}</div><div className="text-[10px] uppercase tracking-wider text-ink-3">total</div></div>}
      </div>
    </div>
  );
}

/** Horizontal ranked bars, each linking into Log Explorer. */
export function BarList({ items, color = "#10f0a0", query, format = fmtCompact, mono = true }: {
  items: { key: string; value: number }[]; color?: string; query?: (key: string) => string; format?: (n: number) => string; mono?: boolean;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <div className="py-6 text-center text-xs text-ink-3">No data yet</div>;
  return (
    <ul className="space-y-1.5">
      {items.map((it) => {
        const row = (
          <div className="group relative flex items-center gap-2 rounded-md px-2 py-1 text-[12px] hover:bg-raised/70">
            <motion.span className="absolute inset-y-0 left-0 rounded-md" style={{ background: color, opacity: 0.12 }}
              initial={false} animate={{ width: `${(it.value / max) * 100}%` }} transition={{ duration: 0.5 }} />
            <span className={`relative flex-1 truncate ${mono ? "font-mono" : ""} text-ink-2 group-hover:text-ink`}>{it.key}</span>
            <span className="relative font-mono text-ink tnum">{format(it.value)}</span>
          </div>
        );
        return <li key={it.key}>{query ? <Link href={`/log-explorer?q=${encodeURIComponent(query(it.key))}`}>{row}</Link> : row}</li>;
      })}
    </ul>
  );
}

export function HBar({ data, height = 200, color = "#22d3ee" }: { data: { name: string; value: number }[]; height?: number; color?: string }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 8 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="name" {...AXIS} width={120} />
        <Tooltip content={<Tip labelFmt={String} />} cursor={{ fill: "#ffffff06" }} />
        <Bar dataKey="value" name="events" fill={color} radius={[0, 4, 4, 0]} barSize={12} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/**
 * Threat origin map: equirectangular projection with graticule, plotted
 * attacker origins and animated arcs to the monitored site.
 * Locations come from the demo GeoIP table (documentation IP ranges).
 */
export function ThreatMap({ points, height = 260 }: { points: { country: string; code: string; lat: number; lon: number; value: number }[]; height?: number }) {
  const reduce = useReducedMotion();
  const W = 720, H = 340;
  const proj = (lat: number, lon: number) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H] as const;
  const [hx, hy] = proj(40.71, -74.0); // SOC / HQ site
  const max = Math.max(1, ...points.map((p) => p.value));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height }} role="img" aria-label="Geographic distribution of event sources">
      <defs>
        <radialGradient id="pt"><stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" /><stop offset="100%" stopColor="#ef4444" stopOpacity="0" /></radialGradient>
        <linearGradient id="arc" x1="0" x2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" /><stop offset="100%" stopColor="#10f0a0" stopOpacity="0.6" /></linearGradient>
      </defs>
      {Array.from({ length: 13 }, (_, i) => <line key={`v${i}`} x1={(i * W) / 12} x2={(i * W) / 12} y1={0} y2={H} stroke="#1d252e" strokeWidth={0.6} />)}
      {Array.from({ length: 7 }, (_, i) => <line key={`h${i}`} y1={(i * H) / 6} y2={(i * H) / 6} x1={0} x2={W} stroke="#1d252e" strokeWidth={0.6} />)}
      <line x1={0} x2={W} y1={H / 2} y2={H / 2} stroke="#2a3540" strokeWidth={0.8} strokeDasharray="3 4" />
      {points.map((p, i) => {
        const [x, y] = proj(p.lat, p.lon);
        const mx = (x + hx) / 2, my = Math.min(y, hy) - 40 - Math.abs(x - hx) * 0.12;
        const r = 4 + (p.value / max) * 14;
        const d = `M${x},${y} Q${mx},${my} ${hx},${hy}`;
        return (
          <g key={p.code}>
            <path d={d} fill="none" stroke="url(#arc)" strokeWidth={0.6 + (p.value / max) * 1.6} strokeOpacity={0.55} />
            {!reduce && (
              <circle r={2} fill="#ffd2d2">
                <animateMotion dur={`${2.2 + (i % 5) * 0.5}s`} repeatCount="indefinite" path={d} />
              </circle>
            )}
            <circle cx={x} cy={y} r={r * 1.8} fill="url(#pt)" opacity={0.5} />
            <circle cx={x} cy={y} r={2.4} fill="#ef4444" />
            <text x={x + 6} y={y - 6} fill="#a7b3bf" fontSize={10} fontFamily="var(--font-jetbrains)">{p.code} {fmtCompact(p.value)}</text>
          </g>
        );
      })}
      <circle cx={hx} cy={hy} r={5} fill="#10f0a0" />
      {!reduce && <circle cx={hx} cy={hy} r={5} fill="none" stroke="#10f0a0"><animate attributeName="r" from="5" to="22" dur="2s" repeatCount="indefinite" /><animate attributeName="opacity" from="0.8" to="0" dur="2s" repeatCount="indefinite" /></circle>}
      <text x={hx + 8} y={hy + 14} fill="#10f0a0" fontSize={10} fontFamily="var(--font-jetbrains)">SOC · HQ</text>
    </svg>
  );
}
