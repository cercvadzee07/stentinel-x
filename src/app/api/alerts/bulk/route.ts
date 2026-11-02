import { z } from "zod";
import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { AlertPatch } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "alerts:write");
  const { ids, patch } = await body(req, z.object({ ids: z.array(z.string()).min(1).max(500), patch: AlertPatch }));
  const e = await c.engine();
  const updated = ids.map((id) => e.updateAlert(id, patch, c.user.name)).filter(Boolean);
  await c.audit("alert.bulk_update", `${updated.length} alerts`, { ids: ids.slice(0, 50), ...patch });
  return json({ updated: updated.length });
});
