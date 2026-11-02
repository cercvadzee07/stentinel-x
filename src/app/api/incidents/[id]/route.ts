import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { IncidentPatch } from "@/server/schemas";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

export const GET = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const e = await (await ctx(req, "incidents:read")).engine();
  const incident = e.incidents.find((i) => i.id === id);
  if (!incident) return fail(404, "Incident not found");
  return json({ incident, alerts: e.alerts.filter((a) => incident.alertIds.includes(a.id)) });
});

export const PATCH = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "incidents:write");
  const patch = await body(req, IncidentPatch);
  const i = (await c.engine()).updateIncident(id, patch, c.user.name);
  if (!i) return fail(404, "Incident not found");
  await c.audit("incident.update", id, { status: patch.status, assignee: patch.assignee, severity: patch.severity, note: patch.note ? "(added)" : undefined, resolution: patch.resolution !== undefined ? "(set)" : undefined });
  return json(i);
});
