"use client";

import { FlaskConical, Pencil, Plus, Search, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { deniedHint, useSession } from "@/components/session";
import { useLive } from "@/components/live";
import { Button, Drawer, Empty, ErrorState, Field, Input, Modal, PageHeader, Panel, Select, SevBadge, Skeleton, Tag, Textarea, useConfirm, useToast } from "@/components/ui";
import { api, cx, fmtBytes, fmtDateTime, fmtNum, relTime } from "@/lib/client";
import { FIELDS } from "@/lib/fields";
import { and, term } from "@/lib/query";
import { check } from "@/lib/sxql";
import { SEVERITIES, type DetectionRule, type RuleLogic, type Severity } from "@/lib/types";

interface TestResult { scanned: number; matched: number; tookMs: number; hits: { groupKey: string; firstSeen: number; lastSeen: number; value: number; eventCount: number }[] }
type Draft = { name: string; description: string; severity: Severity; mitre: string; enabled: boolean; logic: RuleLogic };

const blank: Draft = { name: "", description: "", severity: "medium", mitre: "", enabled: true,
  logic: { filter: "", groupBy: ["source.ip"], aggregate: "count", threshold: 10, windowSec: 60 } };
const fmtValue = (l: RuleLogic, v: number) => (l.aggregate === "sum_bytes" ? fmtBytes(v) : fmtNum(v));
const describe = (l: RuleLogic) =>
  `${l.aggregate === "count" ? "count" : l.aggregate === "distinct" ? `distinct(${l.distinctField})` : "sum(network.bytes)"} ≥ ${fmtValue(l, l.threshold)} per ${l.groupBy.join(" + ")} in ${l.windowSec}s`;

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><Rules /></Suspense>;
}

function Rules() {
  const params = useSearchParams();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const { alertVersion } = useLive();
  const { can } = useSession();
  const write = can("rules:write"), canTest = can("rules:test");
  const lock = write ? {} : { disabled: true, title: deniedHint("rules:write") };
  const [rules, setRules] = useState<DetectionRule[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ id: string | null; draft: Draft } | null>(null);
  const [testing, setTesting] = useState<{ rule: DetectionRule | Draft; res: TestResult | null; window: number } | null>(null);
  const [filter, setFilter] = useState("");

  const load = useCallback(() => api<DetectionRule[]>("/api/rules").then(setRules).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load, alertVersion]);
  useEffect(() => { if (params.get("new") && write) { setEditing({ id: null, draft: blank }); router.replace("/rules"); } }, [params, router, write]);

  const toggle = async (r: DetectionRule) => {
    try { await api(`/api/rules/${r.id}`, { method: "PATCH", json: { enabled: !r.enabled } }); toast({ tone: "success", title: `${r.name} ${r.enabled ? "disabled" : "enabled"}` }); load(); }
    catch (e) { toast({ tone: "error", title: "Update failed", body: (e as Error).message }); }
  };
  const remove = async (r: DetectionRule) => {
    if (!(await confirm({ title: `Delete rule “${r.name}”?`, body: "The rule stops evaluating immediately. Existing alerts it produced are kept.", confirmLabel: "Delete rule", danger: true }))) return;
    await api(`/api/rules/${r.id}`, { method: "DELETE" });
    toast({ tone: "success", title: "Rule deleted" });
    load();
  };
  const runTest = async (rule: DetectionRule | Draft, window: number) => {
    setTesting({ rule, res: null, window });
    try {
      const body = "id" in rule ? { ruleId: rule.id, windowMin: window || undefined } : { rule: toInput(rule), windowMin: window || undefined };
      const res = await api<TestResult>("/api/rules/test", { method: "POST", json: body });
      setTesting({ rule, res, window });
    } catch (e) { setTesting(null); toast({ tone: "error", title: "Backtest failed", body: (e as Error).message }); }
  };

  const shown = rules?.filter((r) => !filter || `${r.name} ${r.description} ${r.mitre.join(" ")}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div>
      <PageHeader title="Correlation Rules" subtitle="Sliding-window detections evaluated on every ingested event. Alerts are generated automatically when thresholds are met."
        actions={<>
          <Input placeholder="Filter rules…" value={filter} onChange={(e) => setFilter(e.target.value)} className="w-48" aria-label="Filter rules" />
          <Button variant="primary" {...lock} onClick={() => setEditing({ id: null, draft: blank })}><Plus className="h-3.5 w-3.5" />New rule</Button>
        </>} />
      {err && <ErrorState message={err} onRetry={load} />}
      <Panel bodyClass="p-0">
        {!shown ? <div className="space-y-2 p-4">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-12" />)}</div> : shown.length === 0 ? <Empty title="No rules" /> : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-[12.5px]">
              <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">
                {["", "Rule", "Severity", "Detection logic", "MITRE ATT&CK", "Triggers", "Last triggered", ""].map((h, i) => <th key={i} className="px-3 py-2 font-medium whitespace-nowrap">{h}</th>)}
              </tr></thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.id} className={cx("border-b border-line/40 hover:bg-raised/40", !r.enabled && "opacity-50")}>
                    <td className="px-3 py-2.5">
                      <button role="switch" {...lock} aria-checked={r.enabled} aria-label={`${r.enabled ? "Disable" : "Enable"} ${r.name}`} onClick={() => toggle(r)}
                        className={cx("relative h-5 w-9 rounded-full border transition-colors disabled:opacity-50", r.enabled ? "border-emerald/60 bg-emerald/25" : "border-line-strong bg-raised")}>
                        <span className={cx("absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all", r.enabled ? "left-[18px] bg-emerald shadow-[0_0_8px_rgb(16_240_160)]" : "left-0.5 bg-ink-3")} />
                      </button>
                    </td>
                    <td className="px-3 py-2.5 max-w-[280px]">
                      <div className="flex items-center gap-1.5 font-medium text-ink">{r.name}<span className="font-mono text-[10px] text-ink-3">{r.id}</span>{!r.builtin && <Tag>custom</Tag>}</div>
                      <div className="truncate text-[11.5px] text-ink-3">{r.description}</div>
                    </td>
                    <td className="px-3"><SevBadge s={r.severity} /></td>
                    <td className="px-3 max-w-[360px]">
                      <code className="block truncate font-mono text-[11px] text-cyan" title={r.logic.filter}>{r.logic.filter || "*"}</code>
                      <div className="truncate font-mono text-[10.5px] text-ink-3">{describe(r.logic)}</div>
                    </td>
                    <td className="px-3"><div className="flex flex-wrap gap-1">{r.mitre.map((m) => <Tag key={m} className="font-mono">{m.split(" ")[0]}</Tag>)}</div></td>
                    <td className="px-3 font-mono tnum">{r.triggerCount > 0 ? <Link className="text-emerald hover:underline" href={`/alerts?q=${encodeURIComponent(r.name)}`}>{r.triggerCount}</Link> : <span className="text-ink-3">0</span>}</td>
                    <td className="px-3 text-ink-2 whitespace-nowrap" title={r.lastTriggered ? fmtDateTime(r.lastTriggered) : ""}>{r.lastTriggered ? relTime(r.lastTriggered) : "never"}</td>
                    <td className="px-3 whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" disabled={!canTest} onClick={() => runTest(r, 30)} title={canTest ? "Backtest on history" : deniedHint("rules:test")}><FlaskConical className="h-3.5 w-3.5" />Test</Button>
                      <Button size="sm" variant="ghost" {...lock} onClick={() => setEditing({ id: r.id, draft: { ...r, mitre: r.mitre.join(", ") } })} aria-label={`Edit ${r.name}`}><Pencil className="h-3.5 w-3.5" /></Button>
                      <Button size="sm" variant="ghost" {...lock} onClick={() => remove(r)} aria-label={`Delete ${r.name}`}><Trash2 className="h-3.5 w-3.5" /></Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {editing && <RuleEditor key={editing.id ?? "new"} id={editing.id} initial={editing.draft} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); load(); }} onTest={(d) => runTest(d, 30)} />}
      <TestDrawer state={testing} onClose={() => setTesting(null)} onWindow={(w) => testing && runTest(testing.rule, w)} />
    </div>
  );
}

const toInput = (d: Draft) => ({ ...d, mitre: d.mitre.split(",").map((s) => s.trim()).filter(Boolean),
  logic: { ...d.logic, distinctField: d.logic.aggregate === "distinct" ? d.logic.distinctField ?? "destination.port" : undefined } });

function RuleEditor({ id, initial, onClose, onSaved, onTest }: { id: string | null; initial: Draft; onClose: () => void; onSaved: () => void; onTest: (d: Draft) => void }) {
  const toast = useToast();
  const [d, setD] = useState<Draft>(initial);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const L = d.logic;
  const setL = (p: Partial<RuleLogic>) => setD((x) => ({ ...x, logic: { ...x.logic, ...p } }));
  const sxql = check(L.filter);

  const save = async () => {
    setSaving(true); setErrors({});
    try {
      await api(id ? `/api/rules/${id}` : "/api/rules", { method: id ? "PATCH" : "POST", json: toInput(d) });
      toast({ tone: "success", title: id ? "Rule updated" : "Rule created", body: "Now evaluating on live events" });
      onSaved();
    } catch (e) {
      const issues = ((e as { data?: { issues?: { path: string; message: string }[] } }).data?.issues) ?? [];
      setErrors(Object.fromEntries(issues.map((i) => [i.path, i.message])));
      toast({ tone: "error", title: "Could not save rule", body: (e as Error).message });
    } finally { setSaving(false); }
  };

  return (
    <Modal open onClose={onClose} title={id ? `Edit rule ${id}` : "New detection rule"} width={680}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button onClick={() => onTest(d)} disabled={!sxql.ok || d.name.length < 3}><FlaskConical className="h-3.5 w-3.5" />Test on history</Button>
        <Button variant="primary" loading={saving} onClick={save} disabled={!sxql.ok}>{id ? "Save changes" : "Create rule"}</Button>
      </>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" error={errors.name}><Input value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} placeholder="e.g. SMB brute force" /></Field>
        <Field label="Severity"><Select value={d.severity} onChange={(e) => setD({ ...d, severity: e.target.value as Severity })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</Select></Field>
        <div className="sm:col-span-2"><Field label="Description" error={errors.description}><Textarea rows={2} value={d.description} onChange={(e) => setD({ ...d, description: e.target.value })} /></Field></div>
        <div className="sm:col-span-2">
          <Field label="Event filter (SXQL)" error={!sxql.ok ? `${sxql.message} (col ${sxql.position + 1})` : errors["logic.filter"]} hint="Selects candidate events. Empty matches everything.">
            <Input value={L.filter} onChange={(e) => setL({ filter: e.target.value })} className={cx("font-mono", !sxql.ok && "border-sev-critical/60")} placeholder="event.type:auth_failure AND destination.port:445" />
          </Field>
        </div>
        <div className="sm:col-span-2">
          <Field label="Group by (correlation key)" error={errors["logic.groupBy"]}>
            <div className="flex flex-wrap gap-1.5">
              {["source.ip", "destination.ip", "destination.port", "user.name", "destination.host", "source.host", "event.type"].map((f) => {
                const on = L.groupBy.includes(f);
                return <button key={f} type="button" onClick={() => setL({ groupBy: on ? L.groupBy.filter((x) => x !== f) : [...L.groupBy, f] })}
                  className={cx("rounded-md border px-2 py-1 font-mono text-[11.5px]", on ? "border-emerald/60 bg-emerald/10 text-emerald" : "border-line-strong text-ink-3 hover:text-ink")}>{f}</button>;
              })}
            </div>
          </Field>
        </div>
        <Field label="Aggregate"><Select value={L.aggregate} onChange={(e) => setL({ aggregate: e.target.value as RuleLogic["aggregate"] })}>
          <option value="count">Count of events</option><option value="distinct">Distinct values of field</option><option value="sum_bytes">Sum of bytes</option></Select></Field>
        {L.aggregate === "distinct"
          ? <Field label="Distinct field"><Select value={L.distinctField ?? "destination.port"} onChange={(e) => setL({ distinctField: e.target.value })} className="font-mono">{FIELDS.map((f) => <option key={f.path}>{f.path}</option>)}</Select></Field>
          : <div />}
        <Field label={L.aggregate === "sum_bytes" ? "Threshold (bytes)" : "Threshold"} hint={L.aggregate === "sum_bytes" ? fmtBytes(L.threshold) : undefined} error={errors["logic.threshold"]}>
          <Input type="number" min={1} value={L.threshold} onChange={(e) => setL({ threshold: Number(e.target.value) })} /></Field>
        <Field label="Time window (seconds)" error={errors["logic.windowSec"]}><Input type="number" min={1} max={86400} value={L.windowSec} onChange={(e) => setL({ windowSec: Math.round(Number(e.target.value)) })} /></Field>
        <div className="sm:col-span-2"><Field label="MITRE ATT&CK techniques" hint="Comma-separated, e.g. T1110 Brute Force, T1021.002 SMB"><Input value={d.mitre} onChange={(e) => setD({ ...d, mitre: e.target.value })} /></Field></div>
        <label className="flex items-center gap-2 text-[13px] text-ink-2"><input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} className="accent-emerald" />Enabled</label>
      </div>
      <div className="mt-4 rounded-lg border border-line bg-base/60 p-3 font-mono text-[11.5px] text-ink-2">
        <span className="text-ink-3">WHEN </span><span className="text-cyan">{L.filter || "*"}</span><br />
        <span className="text-ink-3">GROUP BY </span>{L.groupBy.join(", ") || "—"}<br />
        <span className="text-ink-3">ALERT IF </span>{describe(L)}
      </div>
    </Modal>
  );
}

function TestDrawer({ state, onClose, onWindow }: { state: { rule: DetectionRule | Draft; res: TestResult | null; window: number } | null; onClose: () => void; onWindow: (w: number) => void }) {
  const r = state?.rule;
  const hitQuery = (key: string) => {
    if (!r) return "";
    const parts = key.split(" | ");
    return and(r.logic.filter, ...r.logic.groupBy.map((f, i) => (parts[i] && parts[i] !== "∅" ? term(f, parts[i]) : "")));
  };
  return (
    <Drawer open={!!state} onClose={onClose} width={720} title={r ? `Backtest · ${r.name || "draft rule"}` : ""}
      subtitle={r && <span className="font-mono">{describe(r.logic)}</span>}
      actions={<Select value={state?.window ?? 30} onChange={(e) => onWindow(Number(e.target.value))} aria-label="Backtest window">
        <option value={5}>Last 5 min</option><option value={30}>Last 30 min</option><option value={60}>Last 60 min</option><option value={0}>All retained</option></Select>}>
      <div className="p-5">
        {!state?.res ? <div className="space-y-2">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div> : (
          <>
            <div className="grid grid-cols-4 gap-2">
              {[["Scanned", fmtNum(state.res.scanned)], ["Matched filter", fmtNum(state.res.matched)], ["Detections", fmtNum(state.res.hits.length)], ["Runtime", `${state.res.tookMs.toFixed(1)} ms`]].map(([k, v]) => (
                <div key={k} className="rounded-lg border border-line bg-base/60 p-3"><div className="text-[10.5px] uppercase tracking-wider text-ink-3">{k}</div><div className="mt-1 font-mono text-lg tnum">{v}</div></div>
              ))}
            </div>
            <p className="mt-3 text-[12px] text-ink-3">The rule is replayed with fresh state over stored events in timestamp order — identical logic to live detection. Nothing is alerted.</p>
            {state.res.hits.length === 0 ? <Empty title="No detections in this window" body="Lower the threshold, widen the window, or launch a matching attack scenario from the simulator menu." /> : (
              <table className="mt-3 w-full text-[12px]">
                <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3"><th className="py-2">Group key</th><th>Peak value</th><th>First seen</th><th>Last seen</th><th /></tr></thead>
                <tbody>
                  {state.res.hits.map((h, i) => (
                    <tr key={i} className="border-b border-line/40">
                      <td className="py-2 font-mono text-ink">{h.groupKey}</td>
                      <td className="font-mono text-sev-high tnum">{fmtValue(state.rule.logic, h.value)}</td>
                      <td className="text-ink-2">{fmtDateTime(h.firstSeen)}</td>
                      <td className="text-ink-2">{fmtDateTime(h.lastSeen)}</td>
                      <td className="text-right"><Link href={`/log-explorer?q=${encodeURIComponent(hitQuery(h.groupKey))}&from=${h.firstSeen - 1000}&to=${h.lastSeen + 1000}`} onClick={onClose}>
                        <Button size="sm" variant="ghost"><Search className="h-3.5 w-3.5" />Events</Button></Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>
    </Drawer>
  );
}
