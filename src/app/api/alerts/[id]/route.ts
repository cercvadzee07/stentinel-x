import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { AlertPatch } from "@/server/schemas";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

export const GET = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const e = await (await ctx(req, "alerts:read")).engine();
  const alert = e.alerts.find((a) => a.id === id);
  if (!alert) return fail(404, "Alert not found");
  const events = alert.eventIds.map((x) => e.byId.get(x)).filter(Boolean).slice(-200);
  const rule = e.rules.find((r) => r.id === alert.ruleId) ?? null;
  return json({ alert, events, rule, agedOut: alert.eventIds.length - events.length });
});

export const PATCH = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "alerts:write");
  const patch = await body(req, AlertPatch);
  const a = (await c.engine()).updateAlert(id, patch, c.user.name);
  if (!a) return fail(404, "Alert not found");
  await c.audit("alert.update", id, { ...patch, comment: patch.comment ? "(added)" : undefined });
  return json(a);
});
