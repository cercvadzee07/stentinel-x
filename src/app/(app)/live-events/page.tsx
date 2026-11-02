"use client";

import { Download, Filter, Pause, Play, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { EventDrawer, EventTable } from "@/components/events";
import { deniedHint, useSession } from "@/components/session";
import { useLive } from "@/components/live";
import { Button, Input, Kbd, PageHeader, Pager, Panel, Select, SevBadge, Tag } from "@/components/ui";
import { cx, downloadUrl, fmtNum } from "@/lib/client";
import { and, anyOf, term } from "@/lib/query";
import { check, compile } from "@/lib/sxql";
import { EVENT_TYPES, EVENT_TYPE_LABEL, SEVERITIES, type SecurityEvent, type Severity } from "@/lib/types";
import { readField } from "@/lib/fields";

const PAGE = 50;
const WINDOWS = [{ v: 60_000, l: "1 min" }, { v: 300_000, l: "5 min" }, { v: 900_000, l: "15 min" }, { v: 0, l: "Buffer" }];

export default function LiveEvents() {
  const { events: live, connected } = useLive();
  const { can } = useSession();
  const exp = can("events:export") ? {} : { disabled: true, title: deniedHint("events:export") };
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<SecurityEvent[]>([]);
  const [text, setText] = useState("");
  const [sev, setSev] = useState<Severity[]>([]);
  const [type, setType] = useState("");
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [port, setPort] = useState("");
  const [proto, setProto] = useState("");
  const [vendor, setVendor] = useState("");
  const [windowMs, setWindowMs] = useState(300_000);
  const [sort, setSort] = useState<{ field: string; dir: "asc" | "desc" }>({ field: "@timestamp", dir: "desc" });
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(null);
  const prevIds = useRef(new Set<string>());

  // Space toggles pause (outside inputs)
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.code === "Space" && !["INPUT", "TEXTAREA", "SELECT", "BUTTON"].includes(t.tagName)) { e.preventDefault(); togglePause(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  });

  const togglePause = () => {
    if (!paused) setFrozen(live);
    setPaused((p) => !p);
  };

  const source = paused ? frozen : live;
  const vendors = useMemo(() => [...new Set(live.map((e) => e.vendor))].sort(), [live]);

  // Every filter compiles into one SXQL query, so the live view and the export are guaranteed identical.
  const query = and(
    anyOf("event.severity", sev), type && term("event.type", type), src && term("source.ip", src), dst && term("destination.ip", dst),
    port && term("destination.port", port), proto && term("network.protocol", proto), vendor && term("observer.vendor", vendor), text.trim(),
  );
  const valid = check(query);

  const filtered = useMemo(() => {
    if (!valid.ok) return [];
    const pred = compile(query);
    const cutoff = windowMs ? (paused ? (frozen[0]?.timestamp ?? Date.now()) : Date.now()) - windowMs : 0;
    const out = source.filter((e) => e.timestamp >= cutoff && pred(e));
    if (sort.field !== "@timestamp" || sort.dir === "asc") {
      const d = sort.dir === "asc" ? 1 : -1;
      out.sort((a, b) => {
        if (sort.field === "event.severity") return (SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)) * d;
        const x = readField(a, sort.field), y = readField(b, sort.field);
        return (typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true })) * d;
      });
    }
    return out;
  }, [source, query, valid.ok, windowMs, sort, paused, frozen]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  useEffect(() => { if (page > pages) setPage(1); }, [page, pages]);
  const rows = filtered.slice((page - 1) * PAGE, page * PAGE);

  const fresh = useMemo(() => {
    const ids = new Set(rows.map((r) => r.id));
    const f = new Set([...ids].filter((id) => prevIds.current.size && !prevIds.current.has(id)));
    prevIds.current = ids;
    return f;
  }, [rows]);

  const onSort = (field: string) => setSort((s) => (s.field === field ? { field, dir: s.dir === "asc" ? "desc" : "asc" } : { field, dir: "desc" }));
  const anyFilter = sev.length || type || src || dst || port || proto || vendor || text;
  const clear = () => { setSev([]); setType(""); setSrc(""); setDst(""); setPort(""); setProto(""); setVendor(""); setText(""); };
  const exportAs = (format: "csv" | "json") => {
    const p = new URLSearchParams({ q: query, format });
    if (windowMs) p.set("from", String(Date.now() - windowMs));
    downloadUrl(`/api/events?${p}`);
  };

  return (
    <div>
      <PageHeader title="Live Events" subtitle="Normalized events as they leave the ingestion pipeline"
        actions={<>
          <span className={cx("flex items-center gap-1.5 rounded-lg border px-2.5 h-8.5 text-[12px]", paused ? "border-sev-medium/50 text-sev-medium" : connected ? "border-emerald/40 text-emerald" : "border-line text-ink-3")}>
            <span className={cx("h-2 w-2 rounded-full", paused ? "bg-sev-medium" : "bg-emerald animate-pulse-dot")} />{paused ? "PAUSED" : connected ? "STREAMING" : "RECONNECTING"}
          </span>
          <Button variant={paused ? "primary" : "outline"} onClick={togglePause}>{paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}{paused ? "Resume" : "Pause"} <Kbd>Space</Kbd></Button>
          <Button {...exp} onClick={() => exportAs("csv")}><Download className="h-3.5 w-3.5" />CSV</Button>
          <Button {...exp} onClick={() => exportAs("json")}><Download className="h-3.5 w-3.5" />JSON</Button>
        </>} />

      <Panel className="mb-3" bodyClass="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Input value={text} onChange={(e) => { setText(e.target.value); setPage(1); }} placeholder="Search (free text or SXQL, e.g. user.name:root)" className="min-w-[260px] flex-1 font-mono" aria-label="Search events" />
          <Select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }} aria-label="Event type"><option value="">All event types</option>{EVENT_TYPES.map((t) => <option key={t} value={t}>{EVENT_TYPE_LABEL[t]}</option>)}</Select>
          <Select value={proto} onChange={(e) => { setProto(e.target.value); setPage(1); }} aria-label="Protocol"><option value="">Any protocol</option>{["tcp", "udp", "icmp", "dns"].map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}</Select>
          <Select value={vendor} onChange={(e) => { setVendor(e.target.value); setPage(1); }} aria-label="Device vendor"><option value="">Any device</option>{vendors.map((v) => <option key={v}>{v}</option>)}</Select>
          <Select value={windowMs} onChange={(e) => setWindowMs(Number(e.target.value))} aria-label="Time range">{WINDOWS.map((w) => <option key={w.v} value={w.v}>{w.l}</option>)}</Select>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Input value={src} onChange={(e) => { setSrc(e.target.value.trim()); setPage(1); }} placeholder="Source IP / CIDR" className="w-40 font-mono" aria-label="Source IP" />
          <Input value={dst} onChange={(e) => { setDst(e.target.value.trim()); setPage(1); }} placeholder="Destination IP / CIDR" className="w-44 font-mono" aria-label="Destination IP" />
          <Input value={port} onChange={(e) => { setPort(e.target.value.trim()); setPage(1); }} placeholder="Dst port (22, 1..1024)" className="w-40 font-mono" aria-label="Destination port" />
          <div className="flex items-center gap-1">
            {SEVERITIES.map((s) => (
              <button key={s} onClick={() => { setSev((xs) => (xs.includes(s) ? xs.filter((x) => x !== s) : [...xs, s])); setPage(1); }}
                className={cx("rounded-md transition-opacity", sev.length > 0 && !sev.includes(s) && "opacity-35")} aria-pressed={sev.includes(s)}><SevBadge s={s} /></button>
            ))}
          </div>
          {anyFilter ? <Button size="sm" variant="ghost" onClick={clear}><X className="h-3.5 w-3.5" />Clear</Button> : null}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[11.5px]">
          <Filter className="h-3.5 w-3.5 text-ink-3" />
          <code className={cx("font-mono", valid.ok ? "text-cyan" : "text-red-300")}>{query || "*"}</code>
          {!valid.ok && <span className="text-red-300">— {valid.message}</span>}
          {query && valid.ok && <Link href={`/log-explorer?q=${encodeURIComponent(query)}`} className="text-ink-3 hover:text-emerald">open in Log Explorer →</Link>}
        </div>
      </Panel>

      <Panel bodyClass="p-0" title={<span>{fmtNum(filtered.length)} events <span className="normal-case tracking-normal text-ink-3">in live buffer of {fmtNum(source.length)}</span></span>}
        actions={<Pager page={page} pages={pages} onPage={setPage} />}>
        <div className="max-h-[calc(100vh-380px)] min-h-[300px] overflow-y-auto scrollbar-thin">
          <EventTable events={rows} onOpen={(e) => setOpen(e.id)} sort={sort} onSort={onSort} selected={open} fresh={paused ? undefined : fresh}
            cols={["time", "id", "severity", "type", "src", "dst", "proto", "srcHost", "dstHost", "user", "app", "vendor", "product", "category", "action", "count"]} />
        </div>
      </Panel>
      <p className="mt-2 text-[11px] text-ink-3">Tip: the live buffer holds the most recent {fmtNum(1500)} events; exports run the same query server-side against the full retention store. <Tag>SIM</Tag> marks simulator-generated events.</p>
      <EventDrawer id={open} onClose={() => setOpen(null)} onOpen={(e) => setOpen(e.id)} />
    </div>
  );
}
