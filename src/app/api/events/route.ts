import { ctx } from "@/server/context";
import { csv, download, handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

const EXPORT_COLS = ["timestamp", "eventId", "type", "severity", "sourceIp", "sourcePort", "destinationIp", "destinationPort", "protocol",
  "sourceHost", "destinationHost", "username", "application", "vendor", "product", "category", "action", "outcome", "count", "bytes", "message", "simulated"];

export const GET = handle(async (req: Request) => {
  const u = new URL(req.url).searchParams;
  const format = u.get("format");
  const exporting = format === "csv" || format === "json";
  const c = await ctx(req, exporting ? "events:export" : "events:read");
  const num = (k: string) => (u.get(k) ? Number(u.get(k)) : undefined);
  const res = (await c.engine()).query({
    q: u.get("q") ?? "", from: num("from"), to: num("to"), sort: u.get("sort") ?? undefined,
    dir: u.get("dir") === "asc" ? "asc" : "desc", page: num("page"), size: num("size"), buckets: num("buckets"),
  });
  if (exporting) {
    const rows = res.all.slice(0, 50_000).map((e) => ({ ...e, timestamp: new Date(e.timestamp).toISOString() }));
    await c.audit("events.export", format, { q: u.get("q") ?? "", rows: rows.length });
    const name = `sentinelx-events-${Date.now()}.${format}`;
    return format === "csv" ? download(csv(rows, EXPORT_COLS), name, "text/csv") : download(JSON.stringify(rows, null, 2), name, "application/json");
  }
  const { all: _all, ...rest } = res;
  return json(rest);
});
