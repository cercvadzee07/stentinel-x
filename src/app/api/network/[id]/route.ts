import { ctx } from "@/server/context";
import { fail, handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const e = await (await ctx(req, "network:read")).engine();
  const node = e.telemetry?.nodes.find((n) => n.id === id);
  const device = e.telemetry?.devices.get(id);
  if (!node || !device) return fail(404, "Device not found or no telemetry source connected");
  const assets = e.assets.filter((a) => node.assetIds.includes(a.id));
  return json({ node, device, assets, simulated: true });
});
