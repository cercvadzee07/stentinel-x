import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "alerts:read")).engine();
  const u = new URL(req.url).searchParams;
  const status = u.get("status")?.split(",").filter(Boolean);
  const severity = u.get("severity")?.split(",").filter(Boolean);
  const q = u.get("q")?.toLowerCase();
  const items = e.alerts.filter((a) =>
    (!status?.length || status.includes(a.status)) &&
    (!severity?.length || severity.includes(a.severity)) &&
    (u.get("suppressed") === "1" || !a.suppressed) &&
    (!q || [a.id, a.title, a.sourceIp, a.targetIp, a.asset, a.ruleName, a.assignee].some((v) => v?.toLowerCase().includes(q))));
  return json({ total: items.length, items: items.slice(0, 1000) });
});
