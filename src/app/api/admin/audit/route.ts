import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { listAudit } from "@/server/repo";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "audit:read");
  const u = new URL(req.url).searchParams;
  return json(await listAudit(c.db, c.user.orgId, { limit: Number(u.get("limit") ?? 100), before: u.get("before") ? Number(u.get("before")) : undefined, q: u.get("q") ?? undefined }));
});
