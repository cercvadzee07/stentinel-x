"use client";

import { Bookmark, Clock, Download, History, Loader2, Play, Plus, Star, Trash2, ZoomOut } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SeverityTimeline } from "@/components/charts";
import { deniedHint, useSession } from "@/components/session";
import { EventDrawer, EventTable } from "@/components/events";
import { Button, Empty, ErrorState, Input, PageHeader, Pager, Panel, Select, Skeleton, useToast } from "@/components/ui";
import { api, cx, downloadUrl, fmtDateTime, fmtNum, relTime } from "@/lib/client";
import { FIELDS, getField } from "@/lib/fields";
import { term } from "@/lib/query";
import { TIME_RANGES } from "@/lib/query";
import { check } from "@/lib/sxql";
import type { SecurityEvent, Severity } from "@/lib/types";

interface Result {
  total: number; scanned: number; page: number; size: number; items: SecurityEvent[]; tookMs: number; bucketMs: number;
  histogram: ({ t: number } & Record<Severity, number>)[]; facets: Record<string, { key: string; value: number }[]>;
}
interface Saved { name: string; q: string; range: string }

const EXAMPLES = [
  "source.ip:192.168.1.10", "destination.port:22", "event.severity>=high", "event.category AND event.outcome",
  "destination.port:3389 AND event.outcome:failure", "network.protocol:icmp", "event.category:authentication AND event.severity>=medium",
  "source.ip:203.0.113.0/24 AND NOT event.action:allow", "network.bytes>1000000 AND network.direction:outbound",
];
const FACET_FIELD: Record<string, string> = { type: "event.type", severity: "event.severity", protocol: "network.protocol", source: "source.ip", port: "destination.port" };
const SAVED_KEY = "sx.savedSearches", HIST_KEY = "sx.searchHistory";

const load = <T,>(k: string, d: T): T => { try { return JSON.parse(localStorage.getItem(k) ?? "") as T; } catch { return d; } };
const store = (k: string, v: unknown) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } };

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><LogExplorer /></Suspense>;
}

function LogExplorer() {
  const params = useSearchParams();
  const router = useRouter();
  const toast = useToast();
  const { can } = useSession();
  const noExport = !can("events:export");
  const urlQ = params.get("q") ?? "";
  const urlFrom = params.get("from"), urlTo = params.get("to");
  const [draft, setDraft] = useState(urlQ);
  const [range, setRange] = useState(params.get("range") ?? (urlFrom ? "custom" : "30m"));
  const [abs, setAbs] = useState<{ from: number; to: number } | null>(urlFrom ? { from: Number(urlFrom), to: Number(urlTo ?? Date.now()) } : null);
  const [q, setQ] = useState(urlQ);
  const [sort, setSort] = useState<{ field: string; dir: "asc" | "desc" }>({ field: "@timestamp", dir: "desc" });
  const [page, setPage] = useState(1);
  const [res, setRes] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [saved, setSaved] = useState<Saved[]>([]);
  const [history, setHistory] = useState<{ q: string; at: number; total: number }[]>([]);
  const [runId, setRunId] = useState(0);

  useEffect(() => { setSaved(load(SAVED_KEY, [])); setHistory(load(HIST_KEY, [])); }, []);
  // follow external navigation (command palette, dashboard links)
  useEffect(() => {
    setDraft(urlQ); setQ(urlQ); setPage(1);
    if (urlFrom) { setRange("custom"); setAbs({ from: Number(urlFrom), to: Number(urlTo ?? Date.now()) }); }
  }, [urlQ, urlFrom, urlTo]);

  const timeBounds = useCallback(() => {
    if (range === "custom" && abs) return abs;
    const r = TIME_RANGES.find((x) => x.value === range);
    return r && r.ms ? { from: Date.now() - r.ms, to: Date.now() } : { from: 0, to: Date.now() };
  }, [range, abs]);

  useEffect(() => {
    const v = check(q);
    if (!v.ok) { setErr(`Query error at ${v.position}: ${v.message}`); setRes(null); return; }
    const ctrl = new AbortController();
    const { from, to } = timeBounds();
    const p = new URLSearchParams({ q, page: String(page), size: "50", sort: sort.field, dir: sort.dir, buckets: "60" });
    if (from) p.set("from", String(from));
    p.set("to", String(to));
    setLoading(true); setErr(null);
    fetch(`/api/events?${p}`, { signal: ctrl.signal, cache: "no-store" })
      .then(async (r) => { const d = await r.json(); if (!r.ok) throw new Error(d.error); return d as Result; })
      .then((d) => {
        setRes(d);
        if (page === 1) setHistory((h) => { const n = [{ q, at: Date.now(), total: d.total }, ...h.filter((x) => x.q !== q)].slice(0, 25); store(HIST_KEY, n); return n; });
      })
      .catch((e) => { if (e.name !== "AbortError") setErr(e.message); })
      .finally(() => setLoading(false));
    return () => ctrl.abort();
  }, [q, page, sort, timeBounds, runId]);

  const run = (next = draft) => {
    setQ(next); setPage(1); setRunId((x) => x + 1);
    const p = new URLSearchParams();
    if (next) p.set("q", next);
    if (range === "custom" && abs) { p.set("from", String(abs.from)); p.set("to", String(abs.to)); } else p.set("range", range);
    router.replace(`/log-explorer?${p}`, { scroll: false });
  };
  const addTerm = (t: string, op: "AND" | "OR" = "AND") => { const n = draft.trim() ? `${draft.trim()} ${op} ${t}` : t; setDraft(n); run(n); };
  const exportAs = (format: "csv" | "json") => {
    const { from, to } = timeBounds();
    downloadUrl(`/api/events?${new URLSearchParams({ q, format, from: String(from), to: String(to) })}`);
  };
  const saveSearch = () => {
    const name = window.prompt("Name this search", q.slice(0, 40) || "All events");
    if (!name) return;
    const n = [{ name, q, range }, ...saved.filter((s) => s.name !== name)];
    setSaved(n); store(SAVED_KEY, n); toast({ tone: "success", title: `Saved search “${name}”` });
  };

  const validity = check(draft);

  return (
    <div>
      <PageHeader title="Log Explorer" subtitle="Search all retained events with SXQL — field:value, comparisons, CIDR, ranges, wildcards, AND / OR / NOT, parentheses"
        actions={<>
          <Button onClick={saveSearch} disabled={!res}><Bookmark className="h-3.5 w-3.5" />Save search</Button>
          <Button onClick={() => exportAs("csv")} disabled={noExport || !res?.total} title={noExport ? deniedHint("events:export") : undefined}><Download className="h-3.5 w-3.5" />CSV</Button>
          <Button onClick={() => exportAs("json")} disabled={noExport || !res?.total} title={noExport ? deniedHint("events:export") : undefined}><Download className="h-3.5 w-3.5" />JSON</Button>
        </>} />

      <Panel bodyClass="p-3" className="mb-3">
        <div className="flex flex-wrap gap-2">
          <QueryEditor value={draft} onChange={setDraft} onRun={() => run()} facets={res?.facets} invalid={!validity.ok} />
          <Select value={range} onChange={(e) => { setRange(e.target.value); setAbs(null); setPage(1); }} aria-label="Time range">
            {TIME_RANGES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
            {range === "custom" && <option value="custom">Custom window</option>}
          </Select>
          <Button variant="primary" onClick={() => run()} disabled={!validity.ok}><Play className="h-3.5 w-3.5" />Search</Button>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px]">
          {!validity.ok ? <span className="text-red-300">✕ {validity.message} (col {validity.position + 1})</span> : <span className="text-emerald">✓ valid SXQL</span>}
          {range === "custom" && abs && <span className="flex items-center gap-1 text-cyan"><Clock className="h-3 w-3" />{fmtDateTime(abs.from)} → {fmtDateTime(abs.to)}
            <button className="ml-1 text-ink-3 hover:text-ink" onClick={() => { setRange("30m"); setAbs(null); }}>reset</button></span>}
          <span className="text-ink-3">Examples:</span>
          {EXAMPLES.map((x) => <button key={x} onClick={() => { setDraft(x); run(x); }} className="font-mono text-ink-3 hover:text-emerald">{x}</button>)}
        </div>
        <ConditionBuilder onAdd={addTerm} />
      </Panel>

      <div className="grid gap-3 xl:grid-cols-[1fr_280px]">
        <div className="min-w-0 space-y-3">
          <Panel title={
            <span className="flex items-center gap-2">
              {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald" /> : null}
              {res ? <span><span className="text-ink">{fmtNum(res.total)}</span> hits <span className="normal-case tracking-normal text-ink-3">· {res.tookMs} ms · scanned {fmtNum(res.scanned)} events</span></span> : "Searching…"}
            </span>}
            actions={range === "custom" && <Button size="sm" variant="ghost" onClick={() => { setRange("30m"); setAbs(null); }}><ZoomOut className="h-3.5 w-3.5" />Zoom out</Button>}>
            {res ? (
              <SeverityTimeline data={res.histogram} height={130}
                onSelect={(t) => { setAbs({ from: t, to: t + res.bucketMs }); setRange("custom"); setPage(1); }} />
            ) : <Skeleton className="h-[130px]" />}
            {res && <div className="mt-1 text-[10.5px] text-ink-3">Click a bar to zoom into that {Math.round(res.bucketMs / 1000)}s bucket.</div>}
          </Panel>

          {err && <ErrorState message={err} onRetry={() => setRunId((x) => x + 1)} />}

          <Panel bodyClass="p-0" title="Results" actions={res && <Pager page={page} pages={Math.max(1, Math.ceil(res.total / 50))} onPage={setPage} />}>
            <div className={cx("max-h-[60vh] overflow-y-auto scrollbar-thin transition-opacity", loading && "opacity-60")}>
              {res ? <EventTable events={res.items} onOpen={(e) => setOpen(e.id)} selected={open} sort={sort}
                onSort={(f) => { setSort((s) => (s.field === f ? { field: f, dir: s.dir === "asc" ? "desc" : "asc" } : { field: f, dir: "desc" })); setPage(1); }}
                cols={["time", "severity", "type", "src", "dst", "proto", "user", "action", "bytes", "vendor", "message"]} />
                : !err && <div className="space-y-1.5 p-3">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-7" />)}</div>}
            </div>
          </Panel>
        </div>

        <div className="space-y-3">
          <Panel title="Event distribution" subtitle="Click to add as AND filter">
            {res ? Object.entries(res.facets).map(([k, items]) => (
              <div key={k} className="mb-3 last:mb-0">
                <div className="mb-1 font-mono text-[10.5px] text-ink-3">{FACET_FIELD[k]}</div>
                {items.length ? items.slice(0, 6).map((it) => (
                  <button key={it.key} onClick={() => addTerm(term(FACET_FIELD[k], it.key))} className="group relative flex w-full items-center gap-2 rounded px-1.5 py-0.5 text-left text-[11.5px] hover:bg-raised">
                    <span className="absolute inset-y-0 left-0 rounded bg-emerald/10" style={{ width: `${(it.value / Math.max(1, res.total)) * 100}%` }} />
                    <span className="relative flex-1 truncate font-mono text-ink-2 group-hover:text-ink">{it.key}</span>
                    <span className="relative font-mono text-ink-3 tnum">{fmtNum(it.value)}</span>
                    <Plus className="relative h-3 w-3 text-emerald opacity-0 group-hover:opacity-100" />
                  </button>
                )) : <div className="text-[11px] text-ink-3">—</div>}
              </div>
            )) : <Skeleton className="h-64" />}
          </Panel>

          <Panel title={<span className="flex items-center gap-1.5"><Star className="h-3 w-3" />Saved searches</span>}>
            {saved.length ? saved.map((s) => (
              <div key={s.name} className="group flex items-center gap-1">
                <button onClick={() => { setRange(s.range); setDraft(s.q); run(s.q); }} className="min-w-0 flex-1 rounded px-1.5 py-1 text-left hover:bg-raised">
                  <div className="truncate text-[12px] text-ink">{s.name}</div>
                  <div className="truncate font-mono text-[10.5px] text-ink-3">{s.q || "*"}</div>
                </button>
                <button aria-label={`Delete ${s.name}`} onClick={() => { const n = saved.filter((x) => x !== s); setSaved(n); store(SAVED_KEY, n); }} className="p-1 text-ink-3 opacity-0 hover:text-red-300 group-hover:opacity-100"><Trash2 className="h-3.5 w-3.5" /></button>
              </div>
            )) : <Empty title="No saved searches" body="Run a query and click “Save search”. Stored in this browser until Phase 2 adds server-side persistence." />}
          </Panel>

          <Panel title={<span className="flex items-center gap-1.5"><History className="h-3 w-3" />Search history</span>} actions={history.length > 0 && <button className="text-[11px] text-ink-3 hover:text-ink" onClick={() => { setHistory([]); store(HIST_KEY, []); }}>clear</button>}>
            {history.length ? history.slice(0, 10).map((h) => (
              <button key={h.q + h.at} onClick={() => { setDraft(h.q); run(h.q); }} className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-raised">
                <span className="flex-1 truncate font-mono text-[11px] text-ink-2">{h.q || "*"}</span>
                <span className="text-[10px] text-ink-3 tnum">{fmtNum(h.total)} · {relTime(h.at)}</span>
              </button>
            )) : <div className="text-[12px] text-ink-3">Queries you run appear here.</div>}
          </Panel>
        </div>
      </div>
      <EventDrawer id={open} onClose={() => setOpen(null)} onOpen={(e) => setOpen(e.id)} />
    </div>
  );
}

// ── Query editor with autocomplete ─────────────────────────────────────
function QueryEditor({ value, onChange, onRun, facets, invalid }: { value: string; onChange: (v: string) => void; onRun: () => void; facets?: Result["facets"]; invalid: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  const [caret, setCaret] = useState(0);
  const [focus, setFocus] = useState(false);
  const [sel, setSel] = useState(0);

  // token under the caret
  const before = value.slice(0, caret);
  const tokStart = Math.max(before.lastIndexOf(" "), before.lastIndexOf("(")) + 1;
  const token = before.slice(tokStart);

  const suggestions = useMemo(() => {
    const colon = token.indexOf(":");
    if (colon > 0) {
      const f = getField(token.slice(0, colon));
      if (!f) return [];
      const prefix = token.slice(colon + 1).replace(/^"/, "").toLowerCase();
      const fromFacets = Object.entries(FACET_FIELD).find(([, p]) => p === f.path)?.[0];
      const vals = [...(f.values ?? []), ...((fromFacets && facets?.[fromFacets]?.map((x) => x.key)) || [])];
      return [...new Set(vals)].filter((v) => v.toLowerCase().startsWith(prefix)).slice(0, 10)
        .map((v) => ({ insert: term(f.path, v), label: v, detail: f.label }));
    }
    if (token.length < 1) return [];
    const t = token.toLowerCase().replace(/^-/, "");
    const fields = FIELDS.filter((f) => f.path.toLowerCase().includes(t) || f.label.toLowerCase().includes(t))
      .slice(0, 9).map((f) => ({ insert: `${token.startsWith("-") ? "-" : ""}${f.path}:`, label: f.path, detail: `${f.label} · ${f.kind}` }));
    const ops = ["AND", "OR", "NOT"].filter((o) => o.toLowerCase().startsWith(t) && t.length > 0).map((o) => ({ insert: `${o} `, label: o, detail: "operator" }));
    return [...ops, ...fields];
  }, [token, facets]);

  useEffect(() => setSel(0), [token]);

  const apply = (insert: string) => {
    const next = value.slice(0, tokStart) + insert + value.slice(caret).replace(/^\S*/, "");
    onChange(next);
    const pos = tokStart + insert.length;
    requestAnimationFrame(() => { ref.current?.setSelectionRange(pos, pos); setCaret(pos); ref.current?.focus(); });
  };

  const show = focus && suggestions.length > 0;
  return (
    <div className="relative min-w-[280px] flex-1">
      <Input ref={ref} value={value} spellCheck={false} aria-label="SXQL query" placeholder="e.g. destination.port:3389 AND event.outcome:failure"
        className={cx("w-full font-mono h-9", invalid && "border-sev-critical/60")}
        onChange={(e) => { onChange(e.target.value); setCaret(e.target.selectionStart ?? 0); }}
        onKeyUp={(e) => setCaret((e.target as HTMLInputElement).selectionStart ?? 0)}
        onClick={(e) => setCaret((e.target as HTMLInputElement).selectionStart ?? 0)}
        onFocus={() => setFocus(true)} onBlur={() => setTimeout(() => setFocus(false), 120)}
        onKeyDown={(e) => {
          if (show && e.key === "ArrowDown") { e.preventDefault(); setSel((i) => Math.min(suggestions.length - 1, i + 1)); }
          else if (show && e.key === "ArrowUp") { e.preventDefault(); setSel((i) => Math.max(0, i - 1)); }
          else if (show && e.key === "Tab") { e.preventDefault(); apply(suggestions[sel].insert); }
          else if (e.key === "Enter") { e.preventDefault(); if (show && token.length && !token.includes(":")) apply(suggestions[sel].insert); else { setFocus(false); onRun(); } }
          else if (e.key === "Escape") setFocus(false);
        }} />
      {show && (
        <ul className="glass absolute left-0 right-0 top-full z-30 mt-1 max-h-72 overflow-y-auto rounded-lg bg-panel/95 p-1 scrollbar-thin" role="listbox">
          {suggestions.map((s, i) => (
            <li key={s.insert} role="option" aria-selected={i === sel}>
              <button onMouseDown={(e) => { e.preventDefault(); apply(s.insert); }} onMouseMove={() => setSel(i)}
                className={cx("flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left", i === sel && "bg-emerald/10")}>
                <span className="font-mono text-[12px] text-ink">{s.label}</span>
                <span className="ml-auto text-[10.5px] text-ink-3">{s.detail}</span>
              </button>
            </li>
          ))}
          <li className="px-2 pt-1 text-[10px] text-ink-3">↑↓ select · Tab / Enter insert · Enter on a full query runs it</li>
        </ul>
      )}
    </div>
  );
}

// ── Point-and-click condition builder (writes SXQL) ────────────────────
function ConditionBuilder({ onAdd }: { onAdd: (t: string, op: "AND" | "OR") => void }) {
  const [field, setField] = useState("destination.port");
  const [op, setOp] = useState(":");
  const [value, setValue] = useState("");
  const [conj, setConj] = useState<"AND" | "OR">("AND");
  const f = getField(field)!;
  const numeric = f.kind === "number" || f.kind === "severity";
  const build = () => (op === "exists" ? f.path : op === "not" ? `NOT ${term(f.path, value)}` : op === ":" ? term(f.path, value) : `${f.path}${op}${value}`);
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line/60 pt-3">
      <span className="text-[11px] uppercase tracking-wider text-ink-3">Add condition</span>
      <Select value={conj} onChange={(e) => setConj(e.target.value as "AND" | "OR")} aria-label="Logical operator" className="w-20"><option>AND</option><option>OR</option></Select>
      <Select value={field} onChange={(e) => { setField(e.target.value); setOp(":"); }} aria-label="Field" className="font-mono">{FIELDS.map((x) => <option key={x.path} value={x.path}>{x.path}</option>)}</Select>
      <Select value={op} onChange={(e) => setOp(e.target.value)} aria-label="Operator" className="w-28">
        <option value=":">equals</option><option value="not">not equals</option><option value="exists">exists</option>
        {numeric && <><option value=">">&gt;</option><option value=">=">&ge;</option><option value="<">&lt;</option><option value="<=">&le;</option></>}
      </Select>
      {op !== "exists" && (f.values ? (
        <Select value={value} onChange={(e) => setValue(e.target.value)} aria-label="Value"><option value="">value…</option>{f.values.map((v) => <option key={v}>{v}</option>)}</Select>
      ) : <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder={f.kind === "ip" ? "10.0.0.0/8" : numeric ? "1..1024" : "value or wild*"} className="w-44 font-mono" aria-label="Value" />)}
      <Button size="sm" disabled={op !== "exists" && !value} onClick={() => { onAdd(build(), conj); setValue(""); }}><Plus className="h-3.5 w-3.5" />Add</Button>
    </div>
  );
}
