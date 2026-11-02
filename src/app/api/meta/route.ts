import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { assignableAnalysts } from "@/server/repo";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "alerts:read");
  const e = await c.engine();
  return json({ analysts: await assignableAnalysts(c.db, c.user.orgId), ingestErrors: e.ingestErrors.slice(0, 20), db: c.db.driver, demo: c.user.demo });
});
