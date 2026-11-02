import { ctx } from "@/server/context";
import { fail, handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const e = await (await ctx(req, "events:read")).engine();
  const ev = e.byId.get(id);
  if (!ev) return fail(404, "Event not found or aged out of the hot buffer");
  const alerts = e.alerts.filter((a) => a.eventIds.includes(id)).map((a) => ({ id: a.id, title: a.title, severity: a.severity, status: a.status }));
  return json({ event: ev, related: e.related(ev), alerts });
});
