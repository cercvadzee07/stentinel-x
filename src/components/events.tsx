"use client";

import { ArrowDown, ArrowUp, ArrowUpDown, ExternalLink, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, cx, fmtBytes, fmtDateTime, fmtTimeMs } from "@/lib/client";
import { FIELDS } from "@/lib/fields";
import { EVENT_TYPE_LABEL, type SecurityEvent, type Severity } from "@/lib/types";
import { Button, Drawer, Empty, ErrorState, KV, SevBadge, SimBadge, Skeleton, StatusBadge, Tabs } from "./ui";

export interface Column { key: string; label: string; field?: string; width?: string; render: (e: SecurityEvent) => React.ReactNode }

const ep = (ip: string, port: number | null) => <span className="font-mono">{ip}{port != null && <span className="text-ink-3">:{port}</span>}</span>;

export const COLUMNS: Record<string, Column> = {
  time: { key: "time", label: "Timestamp", field: "@timestamp", width: "w-[110px]", render: (e) => <span className="font-mono text-ink-2">{fmtTimeMs(e.timestamp)}</span> },
  id: { key: "id", label: "Event ID", field: "event.id", render: (e) => <span className="font-mono text-ink-3">{e.eventId}</span> },
  type: { key: "type", label: "Event Type", field: "event.type", render: (e) => <span className="flex items-center gap-1.5 whitespace-nowrap">{EVENT_TYPE_LABEL[e.type]}{e.simulated && <SimBadge />}</span> },
  severity: { key: "severity", label: "Severity", field: "event.severity", render: (e) => <SevBadge s={e.severity} glow /> },
  src: { key: "src", label: "Source", field: "source.ip", render: (e) => ep(e.sourceIp, e.sourcePort) },
  dst: { key: "dst", label: "Destination", field: "destination.ip", render: (e) => ep(e.destinationIp, e.destinationPort) },
  proto: { key: "proto", label: "Proto", field: "network.protocol", render: (e) => <span className="font-mono uppercase text-ink-2">{e.protocol}</span> },
  srcHost: { key: "srcHost", label: "Src Host", field: "source.host", render: (e) => <span className="text-ink-2">{e.sourceHost ?? "—"}</span> },
  dstHost: { key: "dstHost", label: "Dst Host", field: "destination.host", render: (e) => <span className="text-ink-2">{e.destinationHost ?? "—"}</span> },
  user: { key: "user", label: "User", field: "user.name", render: (e) => <span className="font-mono text-ink-2">{e.username ?? "—"}</span> },
  app: { key: "app", label: "Application", field: "process.name", render: (e) => <span className="text-ink-2">{e.application ?? "—"}</span> },
  vendor: { key: "vendor", label: "Vendor", field: "observer.vendor", render: (e) => <span className="text-ink-2 whitespace-nowrap">{e.vendor}</span> },
  product: { key: "product", label: "Product", field: "observer.product", render: (e) => <span className="text-ink-2 whitespace-nowrap">{e.product}</span> },
  category: { key: "category", label: "Category", field: "event.category", render: (e) => <span className="text-ink-2">{e.category}</span> },
  action: { key: "action", label: "Action", field: "event.action", render: (e) => <span className={cx("font-mono", ["deny", "drop", "block", "quarantine"].includes(e.action) ? "text-sev-high" : "text-ink-2")}>{e.action}</span> },
  count: { key: "count", label: "Count", field: "event.count", render: (e) => <span className="font-mono tnum">{e.count}</span> },
  bytes: { key: "bytes", label: "Bytes", field: "network.bytes", render: (e) => <span className="font-mono tnum text-ink-2">{fmtBytes(e.bytes)}</span> },
  message: { key: "message", label: "Message", field: "message", render: (e) => <span className="block max-w-[340px] truncate text-ink-2">{e.message}</span> },
};
export const DEFAULT_COLS = ["time", "severity", "type", "src", "dst", "proto", "user", "action", "vendor", "count"];

const sevRow: Record<Severity, string> = {
  info: "", low: "", medium: "", high: "bg-sev-high/[0.03]", critical: "bg-sev-critical/[0.06]",
};

export function EventTable({ events, cols = DEFAULT_COLS, onOpen, sort, onSort, selected, fresh, dense }: {
  events: SecurityEvent[]; cols?: string[]; onOpen: (e: SecurityEvent) => void;
  sort?: { field: string; dir: "asc" | "desc" }; onSort?: (field: string) => void; selected?: string | null; fresh?: Set<string>; dense?: boolean;
}) {
  const columns = cols.map((c) => COLUMNS[c]).filter(Boolean);
  return (
    <div className="overflow-x-auto scrollbar-thin">
      <table className="w-full border-collapse text-[12px]">
        <thead className="sticky top-0 z-10 bg-panel/95 backdrop-blur">
          <tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">
            {columns.map((c) => {
              const active = sort && c.field === sort.field;
              return (
                <th key={c.key} className={cx("px-3 py-2 font-medium whitespace-nowrap", c.width)}>
                  {onSort && c.field ? (
                    <button className={cx("inline-flex items-center gap-1 hover:text-ink", active && "text-emerald")} onClick={() => onSort(c.field!)}>
                      {c.label}
                      {active ? (sort!.dir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />) : <ArrowUpDown className="h-3 w-3 opacity-40" />}
                    </button>
                  ) : c.label}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} onClick={() => onOpen(e)}
              className={cx("cursor-pointer border-b border-line/40 transition-colors hover:bg-emerald/[0.04]", sevRow[e.severity],
                selected === e.id && "bg-emerald/[0.08]", fresh?.has(e.id) && "row-flash")}>
              {columns.map((c, i) => (
                <td key={c.key} className={cx("px-3 whitespace-nowrap", dense ? "py-1" : "py-1.5", i === 0 && e.severity === "critical" && "border-l-2 border-l-sev-critical")}>{c.render(e)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {!events.length && <Empty title="No events match" body="Adjust the query, filters or time range." />}
    </div>
  );
}

interface EventDetail { event: SecurityEvent; related: SecurityEvent[]; alerts: { id: string; title: string; severity: Severity; status: any }[] }

export function EventDrawer({ id, onClose, onOpen }: { id: string | null; onClose: () => void; onOpen: (e: SecurityEvent) => void }) {
  const [data, setData] = useState<EventDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<"fields" | "raw" | "related">("fields");

  useEffect(() => {
    if (!id) return;
    setData(null); setErr(null);
    api<EventDetail>(`/api/events/${id}`).then(setData).catch((e) => setErr(e.message));
  }, [id]);

  const e = data?.event;
  return (
    <Drawer open={!!id} onClose={onClose} width={760}
      title={e ? <span className="flex items-center gap-2"><SevBadge s={e.severity} glow />{EVENT_TYPE_LABEL[e.type]}{e.simulated && <SimBadge />}</span> : "Event"}
      subtitle={e ? <span className="font-mono">{e.eventId} · {fmtDateTime(e.timestamp)} · {e.vendor} {e.product}</span> : null}
      actions={e && (
        <Link href={`/log-explorer?q=${encodeURIComponent(`source.ip:${e.sourceIp} OR destination.ip:${e.sourceIp}`)}`} onClick={onClose}>
          <Button size="sm" variant="primary"><Search className="h-3.5 w-3.5" />Investigate source</Button>
        </Link>
      )}>
      {err && <div className="p-5"><ErrorState message={err} /></div>}
      {!e && !err && <div className="space-y-2 p-5">{Array.from({ length: 10 }, (_, i) => <Skeleton key={i} className="h-6" />)}</div>}
      {e && data && (
        <div className="p-5">
          <div className="mb-4 rounded-lg border border-line bg-base/60 p-3 font-mono text-[12.5px]">
            <span className="text-cyan">{e.sourceHost ?? e.sourceIp}</span>
            <span className="text-ink-3"> ({e.sourceIp}{e.sourcePort != null ? `:${e.sourcePort}` : ""})</span>
            <span className="mx-2 text-emerald">──{e.protocol.toUpperCase()}──▶</span>
            <span className="text-cyan">{e.destinationHost ?? e.destinationIp}</span>
            <span className="text-ink-3"> ({e.destinationIp}{e.destinationPort != null ? `:${e.destinationPort}` : ""})</span>
            <div className="mt-1.5 text-ink-2">{e.message}</div>
          </div>
          {data.alerts.length > 0 && (
            <div className="mb-4 rounded-lg border border-sev-high/40 bg-sev-high/5 p-3">
              <div className="mb-1.5 text-[11px] uppercase tracking-wider text-sev-high">Contributed to {data.alerts.length} alert(s)</div>
              {data.alerts.map((a) => (
                <Link key={a.id} href={`/alerts?id=${a.id}`} onClick={onClose} className="flex items-center gap-2 py-0.5 text-[12.5px] hover:text-emerald">
                  <SevBadge s={a.severity} /><span className="font-mono text-ink-3">{a.id}</span><span className="truncate">{a.title}</span><StatusBadge s={a.status} /><ExternalLink className="ml-auto h-3 w-3" />
                </Link>
              ))}
            </div>
          )}
          <div className="mb-3"><Tabs value={tab} onChange={setTab} items={[{ value: "fields", label: "Normalized fields" }, { value: "raw", label: `Raw (${e.rawFormat.toUpperCase()})` }, { value: "related", label: `Related (${data.related.length})` }]} /></div>
          {tab === "fields" && (
            <div>
              {FIELDS.map((f) => {
                const v = e[f.key];
                const display = f.key === "timestamp" ? new Date(e.timestamp).toISOString() : v === null || v === undefined ? null : String(v);
                return <KV key={f.path} k={f.path} v={display !== null && f.kind !== "text" && f.key !== "timestamp"
                  ? <Link className="hover:text-emerald hover:underline" onClick={onClose} href={`/log-explorer?q=${encodeURIComponent(`${f.path}:${/\s/.test(display) ? `"${display}"` : display}`)}`}>{display}</Link>
                  : display} />;
              })}
            </div>
          )}
          {tab === "raw" && (
            <div className="space-y-3">
              <div className="text-[11px] uppercase tracking-wider text-ink-3">Original payload as received</div>
              <pre className="overflow-x-auto rounded-lg border border-line bg-void p-3 font-mono text-[11.5px] leading-relaxed text-emerald/90 whitespace-pre-wrap break-all">
                {typeof e.raw === "string" ? e.raw : JSON.stringify(e.raw, null, 2)}
              </pre>
              <div className="text-[11px] uppercase tracking-wider text-ink-3">Normalized document</div>
              <pre className="max-h-80 overflow-auto rounded-lg border border-line bg-void p-3 font-mono text-[11.5px] leading-relaxed text-cyan/90 scrollbar-thin">
                {JSON.stringify({ ...e, raw: undefined }, null, 2)}
              </pre>
            </div>
          )}
          {tab === "related" && (
            <div className="-mx-5">
              <p className="px-5 pb-2 text-[12px] text-ink-3">Same source IP, or same destination & type, within ±10 minutes.</p>
              <EventTable events={data.related} cols={["time", "severity", "type", "src", "dst", "action"]} onOpen={onOpen} dense />
              <div className="px-5 pt-3">
                <Link href={`/log-explorer?q=${encodeURIComponent(`source.ip:${e.sourceIp}`)}`} onClick={onClose}><Button size="sm">Open all events from {e.sourceIp}</Button></Link>
              </div>
            </div>
          )}
        </div>
      )}
    </Drawer>
  );
}
