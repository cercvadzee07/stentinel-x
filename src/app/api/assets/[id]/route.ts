import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { deleteAsset, getAsset, listAssets, updateAsset } from "@/server/repo";
import { AssetInputSchema } from "@/server/schemas";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

/** Asset investigation: record + activity summary from the hot store. */
export const GET = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "assets:read");
  const asset = await getAsset(c.db, c.user.orgId, id);
  if (!asset) return fail(404, "Asset not found");
  return json({ asset, activity: (await c.engine()).assetActivity(asset.ip) });
});

export const PATCH = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "assets:write");
  const patch = await body(req, AssetInputSchema.partial());
  const asset = await updateAsset(c.db, c.user.orgId, id, patch);
  (await c.engine()).setAssets(await listAssets(c.db, c.user.orgId));
  await c.audit("asset.update", asset?.hostname ?? id, { fields: Object.keys(patch) });
  return json(asset);
});

export const DELETE = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "assets:write");
  const hostname = await deleteAsset(c.db, c.user.orgId, id);
  (await c.engine()).setAssets(await listAssets(c.db, c.user.orgId));
  await c.audit("asset.delete", hostname, { id });
  return json({ ok: true });
});
