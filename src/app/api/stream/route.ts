import { ctx } from "@/server/context";
import { handle } from "@/server/http";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "events:read");
  const e = await c.engine();
  const enc = new TextEncoder();
  let unsub = () => {};
  let ping: ReturnType<typeof setInterval>;
  const stream = new ReadableStream({
    start(ctrl) {
      const send = (event: string, data: unknown) => ctrl.enqueue(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      send("hello", { metrics: e.metrics(), events: e.events.slice(-60), alerts: e.alerts.slice(0, 50) });
      unsub = e.subscribe((p) => send("tick", p));
      ping = setInterval(() => ctrl.enqueue(enc.encode(": ping\n\n")), 15_000);
      req.signal.addEventListener("abort", () => { unsub(); clearInterval(ping); try { ctrl.close(); } catch {} });
    },
    cancel() { unsub(); clearInterval(ping); },
  });
  return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive" } });
});
