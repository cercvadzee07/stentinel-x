import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { removeAllowlist } from "@/server/scan/store";

export const dynamic = "force-dynamic";

export const DELETE = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const c = await ctx(req, "scans:allowlist");
  const cidr = await removeAllowlist(c.db, c.user.orgId, id);
  await c.audit("scan.allowlist_remove", cidr);
  return json({ ok: true });
});
