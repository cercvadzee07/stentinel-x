import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { listFindings } from "@/server/scan/store";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "vulns:read");
  const u = new URL(req.url).searchParams;
  const list = (k: string) => u.get(k)?.split(",").map((x) => x.trim()).filter(Boolean);
  return json(await listFindings(c.db, c.user.orgId, { status: list("status"), severity: list("severity"), ip: u.get("ip") ?? undefined }));
});
