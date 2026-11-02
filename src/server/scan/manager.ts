/**
 * Scan job manager: queue (max 2 concurrent scans per process), scheduler for
 * once/recurring jobs, cancellation, progress, persistence, findings merge.
 * Every job is re-validated against the CURRENT allowlist right before it runs,
 * so removing an allowlist entry also stops scheduled scans of that range.
 */
import { db as getDb, type Db } from "../db/index.ts";
import { listAssets } from "../repo.ts";
import { assess } from "./checks.ts";
import { nmapStatus, runNmap } from "./nmap.ts";
import { validateScan, type ScanPlan } from "./policy.ts";
import { runSimulated } from "./simulated.ts";
import { dueJobs, interruptedJobs, listAllowlist, recordFindings, saveJob, type ScanJob } from "./store.ts";

const CONCURRENCY = 2;
const allowPublic = () => process.env.SCAN_ALLOW_PUBLIC === "1";

class ScanManager {
  queue: { orgId: string; id: string }[] = [];
  running = new Map<string, { job: ScanJob; ctrl: AbortController }>();
  private ready: Promise<void> | null = null;

  init() {
    return (this.ready ??= (async () => {
      const db = await getDb();
      for (const j of await interruptedJobs(db)) {
        Object.assign(j, { status: "failed", error: "Interrupted by a server restart", finishedAt: Date.now() });
        await saveJob(db, j);
      }
      setInterval(() => void this.scheduleTick(), 15_000);
    })());
  }

  live(orgId: string, id: string) {
    const r = this.running.get(id);
    return r && r.job.orgId === orgId ? r.job : null;
  }

  async submit(db: Db, job: ScanJob) {
    await this.init();
    await saveJob(db, job);
    if (job.status === "queued") this.enqueue(job);
  }

  private enqueue(job: ScanJob) {
    this.queue.push({ orgId: job.orgId, id: job.id });
    void this.pump();
  }

  async cancel(db: Db, job: ScanJob, actor: string) {
    const r = this.running.get(job.id);
    if (r) { r.ctrl.abort(); return; }
    this.queue = this.queue.filter((q) => q.id !== job.id);
    Object.assign(job, { status: "cancelled", error: `Cancelled by ${actor}`, finishedAt: Date.now(), nextRunAt: null });
    await saveJob(db, job);
  }

  private async scheduleTick() {
    try {
      const db = await getDb();
      for (const j of await dueJobs(db, Date.now())) {
        j.status = "queued";
        await saveJob(db, j);
        this.enqueue(j);
      }
    } catch (e) { console.error("[scan scheduler]", e); }
  }

  private async pump() {
    while (this.running.size < CONCURRENCY && this.queue.length) {
      const next = this.queue.shift()!;
      const db = await getDb();
      const { getJob } = await import("./store.ts");
      const job = await getJob(db, next.orgId, next.id);
      if (!job || job.status !== "queued") continue;
      void this.execute(db, job);
    }
  }

  private async execute(db: Db, job: ScanJob) {
    const ctrl = new AbortController();
    this.running.set(job.id, { job, ctrl });
    Object.assign(job, { status: "running", startedAt: Date.now(), progress: 0, error: null });
    await saveJob(db, job);
    let lastSave = 0;
    const progress = (pct: number) => {
      job.progress = pct;
      if (Date.now() - lastSave > 2000) { lastSave = Date.now(); void saveJob(db, job); }
    };
    try {
      const allow = (await listAllowlist(db, job.orgId)).map((a) => a.cidr);
      const v = validateScan({ target: job.target, ports: job.ports, type: job.type, intensity: job.intensity, timeoutSec: job.timeoutSec }, allow, { allowPublic: allowPublic() });
      if (!v.ok) throw new Error(`No longer authorized: ${v.errors.join(" ")}`);
      const plan: ScanPlan = v.plan;
      let hosts;
      if (job.engine === "nmap") {
        const st = await nmapStatus();
        if (!st.available) throw new Error(`nmap unavailable: ${st.reason}`);
        const r = await runNmap(plan, progress, ctrl.signal);
        hosts = r.hosts;
        job.args = r.args;
        // enrich with inventory metadata (hostname/location/os) — real observations stay unmodified otherwise
        const inv = new Map((await listAssets(db, job.orgId)).map((a) => [a.ip, a]));
        for (const h of hosts) { const a = inv.get(h.ip); if (a) { h.hostname ??= a.hostname; h.location = a.location; h.os ??= a.os; } }
      } else {
        hosts = await runSimulated(plan, await listAssets(db, job.orgId), progress, ctrl.signal);
      }
      const up = hosts.filter((h) => h.state === "up");
      job.results = { hosts, up: up.length, down: hosts.length - up.length, openPorts: up.reduce((s, h) => s + h.ports.filter((p) => p.state === "open").length, 0) };
      job.findings = job.type === "vuln_basic" ? assess(hosts) : [];
      Object.assign(job, { status: "completed", progress: 100, finishedAt: Date.now() });
      await saveJob(db, job);
      if (job.type === "vuln_basic") await recordFindings(db, job);
    } catch (e) {
      const cancelled = ctrl.signal.aborted;
      Object.assign(job, { status: cancelled ? "cancelled" : "failed", error: cancelled ? "Cancelled" : (e as Error).message, finishedAt: Date.now() });
      if (cancelled) job.nextRunAt = null;
      await saveJob(db, job);
    } finally {
      this.running.delete(job.id);
      if (job.schedule.kind === "recurring" && job.status !== "cancelled" && job.schedule.everyHours) await this.scheduleNext(db, job);
      void this.pump();
    }
  }

  private async scheduleNext(db: Db, prev: ScanJob) {
    const { newId } = await import("../auth.ts");
    const next: ScanJob = {
      ...prev, id: newId("scan"), status: "scheduled", progress: 0, error: null, results: null, findings: [], args: null,
      createdAt: Date.now(), startedAt: null, finishedAt: null, parentId: prev.parentId ?? prev.id,
      nextRunAt: Date.now() + prev.schedule.everyHours! * 3_600_000,
    };
    await saveJob(db, next);
  }
}

const g = globalThis as unknown as { __sxScans?: ScanManager };
export const scans = () => (g.__sxScans ??= new ScanManager());
