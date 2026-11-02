import { authInvestigate } from "@/server/analytics";
import { ctx } from "@/server/context";
import { fail, handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

/** Failed-login investigation for ?user=<name> or ?source=<ip>, with the alerts that reference it. */
export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "events:read")).engine();
  const u = new URL(req.url).searchParams;
  const user = u.get("user")?.slice(0, 128), source = u.get("source")?.slice(0, 64);
  if (!user && !source) return fail(400, "Provide ?user= or ?source=");
  const kind = user ? "user" : "source";
  const value = (user ?? source)!;
  const res = authInvestigate(e.events, kind, value);
  const alerts = e.alerts.filter((a) => (kind === "source" ? a.sourceIp === value || a.groupKey.split(" | ").includes(value) : a.groupKey.split(" | ").includes(value)))
    .slice(0, 50).map((a) => ({ id: a.id, title: a.title, severity: a.severity, status: a.status, ruleName: a.ruleName, lastSeen: a.lastSeen, incidentId: a.incidentId,
      sourceIp: a.sourceIp, targetIp: a.targetIp, asset: a.asset, eventCount: a.eventCount }));
  return json({ ...res, alerts });
});
