import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { compactPorts, validateScan } from "@/server/scan/policy";
import { listAllowlist } from "@/server/scan/store";
import { ScanRequestSchema } from "@/server/schemas";

export const dynamic = "force-dynamic";

/** Dry-run the authorization policy for the scan form (nothing is queued). */
export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "scans:read");
  const r = await body(req, ScanRequestSchema.partial({ engine: true }));
  const allow = (await listAllowlist(c.db, c.user.orgId)).map((a) => a.cidr);
  const v = validateScan({ target: r.target, ports: r.ports, type: r.type, intensity: r.intensity, timeoutSec: r.timeoutSec }, allow, { allowPublic: process.env.SCAN_ALLOW_PUBLIC === "1" });
  return json(v.ok
    ? { ok: true, network: v.plan.targetInfo.network, hosts: v.plan.hosts, ports: v.plan.portList.length, portSpec: compactPorts(v.plan.portList).slice(0, 200), probes: v.plan.probes, allowlist: v.plan.matchedAllowlist }
    : { ok: false, errors: v.errors });
});
