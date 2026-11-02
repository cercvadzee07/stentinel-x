import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { revokeApiKey } from "@/server/repo";

export const dynamic = "force-dynamic";

export const DELETE = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const c = await ctx(req, "keys:manage");
  await revokeApiKey(c.db, c.user.orgId, id);
  await c.audit("apikey.revoke", id);
  return json({ ok: true });
});
