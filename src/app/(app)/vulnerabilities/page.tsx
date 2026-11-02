"use client";

import { ExternalLink, Radar, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { deniedHint, useSession } from "@/components/session";
import { Button, Drawer, Empty, ErrorState, Field, Input, KV, PageHeader, Panel, Select, SevBadge, SimBadge, Skeleton, Stat, Tag, Textarea, useToast } from "@/components/ui";
import { api, cx, fmtDateTime, relTime } from "@/lib/client";
import { SEVERITIES, type Severity } from "@/lib/types";

type Status = "open" | "accepted" | "remediated" | "not_detected";
interface Finding {
  id: string; checkId: string; title: string; severity: Severity; cvss: number | null; cve: string | null; port: number; proto: string; service: string | null;
  evidence: string; remediation: string; references: string[]; ip: string; hostname: string | null; status: Status; simulated: boolean;
  firstSeen: number; lastSeen: number; lastScanId: string; note: string | null; history: { at: number; actor: string; action: string }[];
}
const STATUS_LABEL: Record<Status, string> = { open: "Open", accepted: "Risk accepted", remediated: "Remediated", not_detected: "Not detected (latest scan)" };
const STATUS_TONE: Record<Status, string> = { open: "text-sev-high", accepted: "text-violet", remediated: "text-emerald", not_detected: "text-cyan" };

export default function Page() {
  return <Suspense fallback={<Skeleton className="h-96" />}><Vulnerabilities /></Suspense>;
}

function Vulnerabilities() {
  const params = useSearchParams();
  const router = useRouter();
  const [items, setItems] = useState<Finding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [status, setStatus] = useState<Status[]>(["open"]);
  const [sev, setSev] = useState<Severity[]>([]);
  const [q, setQ] = useState(params.get("ip") ?? "");
  const openId = params.get("id");
  const load = useCallback(() => api<Finding[]>("/api/vulns").then((x) => { setItems(x); setErr(null); }).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const setOpen = (id: string | null) => router.replace(id ? `/vulnerabilities?id=${id}` : "/vulnerabilities", { scroll: false });

  const shown = useMemo(() => items?.filter((f) => (!status.length || status.includes(f.status)) && (!sev.length || sev.includes(f.severity)) &&
    (!q || [f.title, f.cve, f.ip, f.hostname, f.checkId, f.service].some((v) => v?.toLowerCase().includes(q.toLowerCase())))), [items, status, sev, q]);
  const open = items?.filter((f) => f.status === "open") ?? [];
  const count = (s: Severity) => open.filter((f) => f.severity === s).length;
  const hosts = new Set(open.map((f) => f.ip)).size;

  return (
    <div className="space-y-4">
      <PageHeader title="Vulnerability Management" subtitle="Findings register built from basic vulnerability assessments in the Scan Center. Version-based findings are potential and need confirmation."
        actions={<Link href="/scan-center"><Button variant="primary"><Radar className="h-3.5 w-3.5" />Run assessment</Button></Link>} />
      {items && items.some((f) => f.simulated) && <div className="flex items-center gap-2 rounded-lg border border-violet/30 bg-violet/[0.06] px-3 py-2 text-[12.5px] text-violet"><SimBadge />Some findings come from the simulated scan engine (asset-inventory based) and are not network observations.</div>}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Stat label="Open findings" value={open.length} accent="high" icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <Stat label="Critical" value={count("critical")} accent="critical" pulse={count("critical") > 0} />
        <Stat label="High" value={count("high")} accent="high" />
        <Stat label="Medium" value={count("medium")} accent="medium" />
        <Stat label="Low" value={count("low")} accent="cyan" />
        <Stat label="Affected hosts" value={hosts} accent="slate" />
      </div>

      <Panel bodyClass="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, CVE, host, IP, service…" className="min-w-[260px] flex-1" aria-label="Search findings" />
          <span className="text-[11px] uppercase tracking-wider text-ink-3">Status</span>
          {(Object.keys(STATUS_LABEL) as Status[]).map((s) => (
            <button key={s} aria-pressed={status.includes(s)} onClick={() => setStatus((xs) => (xs.includes(s) ? xs.filter((x) => x !== s) : [...xs, s]))}
              className={cx("rounded-md border border-line-strong px-1.5 py-[1px] text-[11px]", STATUS_TONE[s], !status.includes(s) && "opacity-35")}>{STATUS_LABEL[s]}</button>
          ))}
          <span className="ml-2 text-[11px] uppercase tracking-wider text-ink-3">Severity</span>
          {SEVERITIES.slice(1).map((s) => <button key={s} aria-pressed={sev.includes(s)} onClick={() => setSev((xs) => (xs.includes(s) ? xs.filter((x) => x !== s) : [...xs, s]))} className={cx(sev.length > 0 && !sev.includes(s) && "opacity-35")}><SevBadge s={s} /></button>)}
        </div>
      </Panel>

      {err && <ErrorState message={err} onRetry={load} />}
      <Panel bodyClass="p-0" title={shown ? `${shown.length} findings` : "Findings"}>
        {!shown ? <div className="space-y-2 p-4">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div>
          : shown.length === 0 ? <Empty icon={<ShieldAlert className="h-5 w-5" />} title={items?.length ? "No findings match these filters" : "No findings yet"} body={items?.length ? undefined : "Run a “Basic vulnerability assessment” from the Scan Center."} /> : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-[12.5px]">
              <thead><tr className="border-b border-line text-left text-[10.5px] uppercase tracking-wider text-ink-3">{["Severity", "Finding", "Host", "Service", "CVSS", "Status", "First seen", "Last seen"].map((h) => <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">{h}</th>)}</tr></thead>
              <tbody>{shown.map((f) => (
                <tr key={f.id} onClick={() => setOpen(f.id)} className={cx("cursor-pointer border-b border-line/40 hover:bg-emerald/[0.04]", openId === f.id && "bg-emerald/[0.08]", f.status !== "open" && "opacity-60")}>
                  <td className="px-3 py-2"><SevBadge s={f.severity} glow /></td>
                  <td className="px-3 max-w-[340px]"><div className="flex items-center gap-1.5 truncate text-ink">{f.title}{f.simulated && <SimBadge />}</div><div className="font-mono text-[10.5px] text-ink-3">{f.cve ?? f.checkId}</div></td>
                  <td className="px-3 whitespace-nowrap"><div className="text-ink-2">{f.hostname ?? "—"}</div><div className="font-mono text-[11px] text-ink-3">{f.ip}</div></td>
                  <td className="px-3 font-mono text-ink-2 whitespace-nowrap">{f.port}/{f.proto} {f.service}</td>
                  <td className="px-3 font-mono tnum text-ink-2">{f.cvss ?? "—"}</td>
                  <td className={cx("px-3 whitespace-nowrap text-[12px]", STATUS_TONE[f.status])}>{STATUS_LABEL[f.status]}</td>
                  <td className="px-3 text-ink-3 whitespace-nowrap">{fmtDateTime(f.firstSeen)}</td>
                  <td className="px-3 text-ink-2 whitespace-nowrap">{relTime(f.lastSeen)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </Panel>
      <FindingDrawer finding={items?.find((f) => f.id === openId) ?? null} open={!!openId} onClose={() => setOpen(null)} onChanged={load} />
    </div>
  );
}

function FindingDrawer({ finding: f, open, onClose, onChanged }: { finding: Finding | null; open: boolean; onClose: () => void; onChanged: () => void }) {
  const toast = useToast();
  const { can } = useSession();
  const write = can("vulns:write");
  const [note, setNote] = useState("");
  useEffect(() => setNote(f?.note ?? ""), [f?.id, f?.note]);
  const patch = async (p: Record<string, unknown>, msg: string) => {
    try { await api(`/api/vulns/${f!.id}`, { method: "PATCH", json: p }); toast({ tone: "success", title: msg }); onChanged(); }
    catch (e) { toast({ tone: "error", title: "Update failed", body: (e as Error).message }); }
  };
  return (
    <Drawer open={open} onClose={onClose} width={720} title={f ? <span className="flex items-center gap-2"><SevBadge s={f.severity} glow />{f.title}{f.simulated && <SimBadge />}</span> : "Finding"}
      subtitle={f && <span className="font-mono">{f.id} · {f.hostname ?? f.ip}:{f.port}/{f.proto}</span>}
      actions={f && <Link href={`/log-explorer?q=${encodeURIComponent(`destination.ip:${f.ip} AND destination.port:${f.port}`)}`} onClick={onClose}><Button size="sm">Related traffic</Button></Link>}>
      {!f ? <div className="p-5"><Skeleton className="h-40" /></div> : (
        <div className="space-y-5 p-5">
          <div>
            <KV k="check" v={f.checkId} /><KV k="cve" v={f.cve ? <a href={f.references[0]} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-emerald">{f.cve}<ExternalLink className="h-3 w-3" /></a> : null} />
            <KV k="cvss" v={f.cvss} /><KV k="host" v={`${f.hostname ?? "—"} (${f.ip})`} /><KV k="service" v={`${f.port}/${f.proto} ${f.service ?? ""}`} />
            <KV k="first_seen" v={fmtDateTime(f.firstSeen)} /><KV k="last_seen" v={`${fmtDateTime(f.lastSeen)} · ${f.lastScanId}`} />
          </div>
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">Evidence</div><p className="rounded-lg border border-line bg-base/60 p-3 text-[13px] text-ink-2">{f.evidence}</p></div>
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-ink-3">Remediation</div><p className="text-[13px] text-ink-2">{f.remediation}</p>
            {f.references.length > 0 && <ul className="mt-1.5 space-y-0.5">{f.references.map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[12px] text-cyan hover:underline">{r}<ExternalLink className="h-3 w-3" /></a></li>)}</ul>}</div>
          <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
            <Field label="Status"><Select value={f.status} disabled={!write} title={write ? undefined : deniedHint("vulns:write")} onChange={(e) => patch({ status: e.target.value }, `Marked ${STATUS_LABEL[e.target.value as Status].toLowerCase()}`)}>
              {(Object.keys(STATUS_LABEL) as Status[]).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}</Select></Field>
            <Field label="Note / justification"><Textarea rows={2} value={note} disabled={!write} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Compensating control: port only reachable from jump host" /></Field>
          </div>
          {write && <Button size="sm" disabled={note === (f.note ?? "")} onClick={() => patch({ note: note || null }, "Note saved")}>Save note</Button>}
          <p className="text-[11.5px] text-ink-3">A later assessment that no longer detects the issue marks it “Not detected”; re-detection reopens it. “Risk accepted” persists across scans.</p>
          <div><div className="mb-1.5 text-[11px] uppercase tracking-wider text-ink-3">History</div>
            <ol className="space-y-1 border-l border-line pl-3">{[...f.history].reverse().map((h, i) => <li key={i} className="text-[12px]"><span className="text-ink-2">{h.actor}</span> <span className="text-ink-3">{h.action}</span> <span className="text-[11px] text-ink-3">· {fmtDateTime(h.at)}</span></li>)}</ol></div>
        </div>
      )}
    </Drawer>
  );
}
