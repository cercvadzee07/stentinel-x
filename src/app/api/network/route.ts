import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { buildTopology } from "@/server/telemetry";

export const dynamic = "force-dynamic";

/** Topology + current device telemetry. telemetry=null when no telemetry source is connected. */
export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "network:read")).engine();
  const t = e.telemetry;
  if (!t) {
    const topo = buildTopology(e.assets);
    return json({ source: "inventory", simulated: false, nodes: topo.nodes, links: topo.links, devices: {}, linkStats: {}, health: null, aggregate: [] });
  }
  const devices = Object.fromEntries([...t.devices.entries()].map(([id, d]) => [id, { ...d, history: d.history.slice(-24), availability: d.availability.slice(-30) }]));
  return json({
    source: "simulator", simulated: true, nodes: t.nodes, links: t.links, devices,
    linkStats: Object.fromEntries(t.linkStat), health: t.health(), aggregate: t.aggregate.slice(-120),
  });
});
