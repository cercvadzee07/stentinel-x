/** Scan allowlist, scan jobs and vulnerability findings — all scoped by org_id. */
import { createHash } from "node:crypto";
import type { Severity } from "../../lib/types.ts";
import type { Db } from "../db/index.ts";
import { HttpError } from "../errors.ts";
import { newId } from "../auth.ts";
import type { Finding, HostResult } from "./checks.ts";
import type { ScanType } from "./policy.ts";

const iso = (v: Date | string | null | undefined) => (v ? new Date(v).getTime() : null);

// ── allowlist ──────────────────────────────────────────────────────────
export async function listAllowlist(db: Db, orgId: string) {
  return (await db.query<{ id: string; cidr: string; label: string; created_by: string | null; created_at: Date }>(
    `SELECT id, cidr, label, created_by, created_at FROM scan_allowlist WHERE org_id = $1 ORDER BY created_at`, [orgId]))
    .map((r) => ({ id: r.id, cidr: r.cidr, label: r.label, createdBy: r.created_by, createdAt: iso(r.created_at)! }));
}

export async function addAllowlist(db: Db, orgId: string, cidr: string, label: string, createdBy: string) {
  const id = newId("al");
  const r = await db.query(`INSERT INTO scan_allowlist (org_id, id, cidr, label, created_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`, [orgId, id, cidr, label, createdBy]);
  if (!r.length) throw new HttpError(409, `${cidr} is already allowlisted`);
  return id;
}

export async function removeAllowlist(db: Db, orgId: string, id: string) {
  const r = await db.query<{ cidr: string }>(`DELETE FROM scan_allowlist WHERE org_id = $1 AND id = $2 RETURNING cidr`, [orgId, id]);
  if (!r.length) throw new HttpError(404, "Allowlist entry not found");
  return r[0].cidr;
}

// ── jobs ───────────────────────────────────────────────────────────────
export type JobStatus = "scheduled" | "queued" | "running" | "completed" | "failed" | "cancelled";
export interface Schedule { kind: "now" | "once" | "recurring"; at?: number; everyHours?: number }

export interface ScanJob {
  id: string; orgId: string; name: string;
  target: string; network: string; ports: string; portCount: number; hosts: number;
  type: ScanType; intensity: number; timeoutSec: number;
  engine: "nmap" | "simulated"; simulated: boolean;
  schedule: Schedule; status: JobStatus; progress: number; error: string | null;
  createdBy: string; createdAt: number; startedAt: number | null; finishedAt: number | null; nextRunAt: number | null;
  allowlistMatch: string; args: string[] | null; parentId: string | null;
  results: { hosts: HostResult[]; up: number; down: number; openPorts: number } | null;
  findings: (Finding & { ip: string; hostname: string | null })[];
}

export async function saveJob(db: Db, j: ScanJob) {
  await db.query(`INSERT INTO scan_jobs (org_id, id, status, engine, next_run_at, created_at, doc) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
                  ON CONFLICT (org_id, id) DO UPDATE SET status = EXCLUDED.status, next_run_at = EXCLUDED.next_run_at, doc = EXCLUDED.doc`,
    [j.orgId, j.id, j.status, j.engine, j.nextRunAt ? new Date(j.nextRunAt) : null, new Date(j.createdAt), JSON.stringify(j)]);
}

export async function getJob(db: Db, orgId: string, id: string): Promise<ScanJob | null> {
  const [r] = await db.query<{ doc: ScanJob }>(`SELECT doc FROM scan_jobs WHERE org_id = $1 AND id = $2`, [orgId, id]);
  return r?.doc ?? null;
}

export async function listJobs(db: Db, orgId: string, limit = 100): Promise<ScanJob[]> {
  // list view keeps result counts but omits per-host details to keep payloads small
  return (await db.query<{ doc: ScanJob }>(`SELECT doc - 'results' || jsonb_build_object('results', CASE WHEN jsonb_typeof(doc->'results') = 'object' THEN jsonb_build_object('up', doc->'results'->'up', 'down', doc->'results'->'down', 'openPorts', doc->'results'->'openPorts', 'hosts', '[]'::jsonb) END) AS doc FROM scan_jobs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`, [orgId, limit])).map((r) => r.doc);
}

export async function dueJobs(db: Db, now: number): Promise<ScanJob[]> {
  return (await db.query<{ doc: ScanJob }>(`SELECT doc FROM scan_jobs WHERE status = 'scheduled' AND next_run_at <= $1 ORDER BY next_run_at LIMIT 20`, [new Date(now)])).map((r) => r.doc);
}

export async function interruptedJobs(db: Db): Promise<ScanJob[]> {
  return (await db.query<{ doc: ScanJob }>(`SELECT doc FROM scan_jobs WHERE status IN ('queued', 'running')`)).map((r) => r.doc);
}

// ── findings ───────────────────────────────────────────────────────────
export type FindingStatus = "open" | "accepted" | "remediated" | "not_detected";
export interface VulnFinding extends Finding {
  id: string; ip: string; hostname: string | null; status: FindingStatus; simulated: boolean;
  firstSeen: number; lastSeen: number; lastScanId: string; note: string | null; history: { at: number; actor: string; action: string }[];
}

const findingId = (orgId: string, ip: string, checkId: string, port: number) =>
  `VLN-${createHash("sha256").update(`${orgId}|${ip}|${checkId}|${port}`).digest("hex").slice(0, 10).toUpperCase()}`;

/** Merge a completed vulnerability scan into the findings register. */
export async function recordFindings(db: Db, job: ScanJob) {
  const now = job.finishedAt ?? Date.now();
  const scannedUp = new Set(job.results?.hosts.filter((h) => h.state === "up").map((h) => h.ip) ?? []);
  const seen = new Set<string>();
  await db.tx(async (q) => {
    for (const f of job.findings) {
      const id = findingId(job.orgId, f.ip, f.checkId, f.port);
      seen.add(id);
      const [prev] = await q<{ doc: VulnFinding }>(`SELECT doc FROM vuln_findings WHERE org_id = $1 AND id = $2`, [job.orgId, id]);
      const p = prev?.doc;
      const status: FindingStatus = p?.status === "accepted" ? "accepted" : "open";
      const history = [...(p?.history ?? [])];
      if (!p) history.push({ at: now, actor: "scan", action: `detected by ${job.id}` });
      else if (p.status === "remediated" || p.status === "not_detected") history.push({ at: now, actor: "scan", action: `re-detected by ${job.id} — reopened` });
      const doc: VulnFinding = { ...f, id, status, simulated: job.simulated, firstSeen: p?.firstSeen ?? now, lastSeen: now, lastScanId: job.id, note: p?.note ?? null, history };
      await q(`INSERT INTO vuln_findings (org_id, id, host_ip, check_id, severity, status, simulated, first_seen, last_seen, doc) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
               ON CONFLICT (org_id, id) DO UPDATE SET severity = EXCLUDED.severity, status = EXCLUDED.status, simulated = EXCLUDED.simulated, last_seen = EXCLUDED.last_seen, doc = EXCLUDED.doc`,
        [job.orgId, id, f.ip, f.checkId, f.severity, status, job.simulated, new Date(doc.firstSeen), new Date(now), JSON.stringify(doc)]);
    }
    // open findings on hosts that were re-assessed but no longer show the issue
    const open = await q<{ id: string; host_ip: string; doc: VulnFinding }>(`SELECT id, host_ip, doc FROM vuln_findings WHERE org_id = $1 AND status = 'open'`, [job.orgId]);
    for (const r of open) {
      if (seen.has(r.id) || !scannedUp.has(r.host_ip)) continue;
      const doc = { ...r.doc, status: "not_detected" as const, history: [...r.doc.history, { at: now, actor: "scan", action: `not detected by ${job.id}` }] };
      await q(`UPDATE vuln_findings SET status = 'not_detected', doc = $3::jsonb WHERE org_id = $1 AND id = $2`, [job.orgId, r.id, JSON.stringify(doc)]);
    }
  });
}

export async function listFindings(db: Db, orgId: string, p: { status?: string[]; severity?: string[]; ip?: string }) {
  const params: unknown[] = [orgId];
  let where = "org_id = $1";
  if (p.status?.length) { params.push(p.status); where += ` AND status = ANY($${params.length}::text[])`; }
  if (p.severity?.length) { params.push(p.severity); where += ` AND severity = ANY($${params.length}::text[])`; }
  if (p.ip) { params.push(p.ip); where += ` AND host_ip = $${params.length}`; }
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (await db.query<{ doc: VulnFinding }>(`SELECT doc FROM vuln_findings WHERE ${where} ORDER BY last_seen DESC LIMIT 2000`, params))
    .map((r) => r.doc).sort((a, b) => rank[a.severity] - rank[b.severity] || b.lastSeen - a.lastSeen);
}

export async function updateFinding(db: Db, orgId: string, id: string, patch: { status?: FindingStatus; note?: string | null }, actor: string) {
  const [r] = await db.query<{ doc: VulnFinding }>(`SELECT doc FROM vuln_findings WHERE org_id = $1 AND id = $2`, [orgId, id]);
  if (!r) throw new HttpError(404, "Finding not found");
  const doc = { ...r.doc, history: [...r.doc.history] };
  if (patch.status && patch.status !== doc.status) { doc.history.push({ at: Date.now(), actor, action: `status ${doc.status} → ${patch.status}` }); doc.status = patch.status; }
  if (patch.note !== undefined) { doc.note = patch.note; doc.history.push({ at: Date.now(), actor, action: "note updated" }); }
  await db.query(`UPDATE vuln_findings SET status = $3, doc = $4::jsonb WHERE org_id = $1 AND id = $2`, [orgId, id, doc.status, JSON.stringify(doc)]);
  return doc;
}
