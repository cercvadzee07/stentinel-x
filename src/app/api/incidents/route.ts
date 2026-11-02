import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { IncidentCreate } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => json((await (await ctx(req, "incidents:read")).engine()).incidents));

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "incidents:write");
  const inc = (await c.engine()).createIncident(await body(req, IncidentCreate), c.user.name);
  await c.audit("incident.create", inc.id, { title: inc.title, alerts: inc.alertIds.length });
  return json(inc, { status: 201 });
});
