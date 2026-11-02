import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { updateFinding } from "@/server/scan/store";
import { FindingPatch } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const PATCH = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const c = await ctx(req, "vulns:write");
  const patch = await body(req, FindingPatch);
  const doc = await updateFinding(c.db, c.user.orgId, id, patch, c.user.name);
  await c.audit("vuln.update", id, { status: patch.status, note: patch.note !== undefined ? "(set)" : undefined });
  return json(doc);
});
