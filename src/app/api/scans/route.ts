import { newId } from "@/server/auth";
import { ctx } from "@/server/context";
import { body, fail, handle, json, rateLimit } from "@/server/http";
import { scans } from "@/server/scan/manager";
import { nmapStatus } from "@/server/scan/nmap";
import { SCAN_TYPE_LABEL, compactPorts, validateScan } from "@/server/scan/policy";
import { listAllowlist, listJobs, type ScanJob } from "@/server/scan/store";
import { ScanRequestSchema } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "scans:read");
  await scans().init();
  const jobs = await listJobs(c.db, c.user.orgId);
  // running jobs: overlay live in-memory progress
  return json(jobs.map((j) => { const live = scans().live(c.user.orgId, j.id); return live ? { ...j, progress: live.progress, status: live.status } : j; }));
});

export const POST = handle(async (req: Request) => {
  rateLimit(req, 20);
  const c = await ctx(req, "scans:run");
  const r = await body(req, ScanRequestSchema);
  if (r.confirmTarget !== r.target) return fail(428, "Confirmation required: re-type the exact target to authorize this scan", { needsConfirmation: true });
  const allow = (await listAllowlist(c.db, c.user.orgId)).map((a) => a.cidr);
  const v = validateScan({ target: r.target, ports: r.ports, type: r.type, intensity: r.intensity, timeoutSec: r.timeoutSec }, allow, { allowPublic: process.env.SCAN_ALLOW_PUBLIC === "1" });
  if (!v.ok) {
    await c.audit("scan.rejected", r.target, { errors: v.errors, type: r.type });
    return fail(422, "Scan not authorized", { errors: v.errors });
  }
  if (r.engine === "nmap") {
    const st = await nmapStatus();
    if (!st.available) return fail(409, `nmap engine unavailable: ${st.reason}`);
  }
  const now = Date.now();
  const s = r.schedule;
  const runAt = s.kind === "now" ? null : s.kind === "once" ? s.at : (s.at ?? now);
  if (runAt !== null && (runAt < now - 60_000 || runAt > now + 30 * 86_400_000)) return fail(422, "Scheduled time must be within the next 30 days");
  const p = v.plan;
  const job: ScanJob = {
    id: newId("scan"), orgId: c.user.orgId, name: r.name || `${SCAN_TYPE_LABEL[r.type]} · ${p.targetInfo.network}`,
    target: r.target, network: p.targetInfo.network, ports: r.type === "host_discovery" ? "" : r.ports, portCount: p.portList.length, hosts: p.hosts,
    type: r.type, intensity: r.intensity, timeoutSec: r.timeoutSec, engine: r.engine, simulated: r.engine === "simulated",
    schedule: s, status: runAt === null || runAt <= now ? "queued" : "scheduled", progress: 0, error: null,
    createdBy: c.user.name, createdAt: now, startedAt: null, finishedAt: null, nextRunAt: runAt,
    allowlistMatch: p.matchedAllowlist, args: null, parentId: null, results: null, findings: [],
  };
  await scans().submit(c.db, job);
  await c.audit("scan.create", job.network, { id: job.id, type: job.type, engine: job.engine, ports: compactPorts(p.portList).slice(0, 120), schedule: s.kind, allowlist: p.matchedAllowlist });
  return json(job, { status: 201 });
});
