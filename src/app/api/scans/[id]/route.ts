import { ctx } from "@/server/context";
import { fail, handle, json } from "@/server/http";
import { scans } from "@/server/scan/manager";
import { getJob } from "@/server/scan/store";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

export const GET = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "scans:read");
  const job = scans().live(c.user.orgId, id) ?? (await getJob(c.db, c.user.orgId, id));
  return job ? json(job) : fail(404, "Scan not found");
});

/** Cancel a queued, scheduled or running scan (stops future recurrences too). */
export const DELETE = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "scans:run");
  const job = await getJob(c.db, c.user.orgId, id);
  if (!job) return fail(404, "Scan not found");
  if (!["queued", "scheduled", "running"].includes(job.status)) return fail(409, `Scan is already ${job.status}`);
  await scans().cancel(c.db, scans().live(c.user.orgId, id) ?? job, c.user.name);
  await c.audit("scan.cancel", job.network, { id });
  return json({ ok: true });
});
