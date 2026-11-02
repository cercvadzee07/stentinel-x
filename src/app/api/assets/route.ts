import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { createAsset, listAssets } from "@/server/repo";
import { AssetCreateSchema } from "@/server/schemas";

export const dynamic = "force-dynamic";

/** Asset list enriched with live activity counts from the tenant's hot event store. */
export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "assets:read");
  const [assets, e] = await Promise.all([listAssets(c.db, c.user.orgId), c.engine()]);
  const counts = new Map<string, { events: number; high: number; last: number }>();
  for (const ev of e.events) {
    for (const ip of [ev.sourceIp, ev.destinationIp]) {
      const x = counts.get(ip) ?? { events: 0, high: 0, last: 0 };
      x.events++;
      if (ev.severity === "high" || ev.severity === "critical") x.high++;
      x.last = Math.max(x.last, ev.timestamp);
      counts.set(ip, x);
    }
  }
  const openAlerts = new Map<string, number>();
  for (const a of e.alerts) if (a.status !== "resolved" && a.status !== "false_positive")
    for (const ip of [a.sourceIp, a.targetIp]) if (ip) openAlerts.set(ip, (openAlerts.get(ip) ?? 0) + 1);
  return json(assets.map((a) => {
    const x = counts.get(a.ip);
    return { ...a, events: x?.events ?? 0, highEvents: x?.high ?? 0, openAlerts: openAlerts.get(a.ip) ?? 0, lastSeen: x?.last || a.lastSeen };
  }));
});

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "assets:write");
  const asset = await createAsset(c.db, c.user.orgId, await body(req, AssetCreateSchema));
  (await c.engine()).setAssets(await listAssets(c.db, c.user.orgId));
  await c.audit("asset.create", asset.hostname, { ip: asset.ip, id: asset.id });
  return json(asset, { status: 201 });
});
