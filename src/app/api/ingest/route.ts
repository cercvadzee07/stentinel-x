import { z } from "zod";
import { ingestCtx } from "@/server/context";
import { getEngine } from "@/server/engines";
import { body, handle, json, rateLimit } from "@/server/http";

export const dynamic = "force-dynamic";

const Item = z.union([
  z.object({ format: z.enum(["cef", "syslog"]), payload: z.string().min(5).max(8192) }),
  z.object({ format: z.literal("json"), payload: z.record(z.unknown()) }),
]);
const Schema = z.union([Item, z.array(Item).min(1).max(1000)]);

/**
 * REST ingestion. Authenticate with an organization API key (`Authorization: Bearer sx_…`)
 * or an analyst session. Events ingested here are NOT flagged simulated.
 */
export const POST = handle(async (req: Request) => {
  rateLimit(req, 120);
  const c = await ingestCtx(req);
  const data = await body(req, Schema);
  const items = Array.isArray(data) ? data : [data];
  const e = await getEngine(c.orgId);
  const accepted: string[] = [];
  const rejected: { index: number; error: string }[] = [];
  items.forEach((it, index) => {
    const before = e.ingestErrors[0];
    const ev = e.ingest({ ...it, receivedAt: Date.now(), simulated: false });
    if (ev) accepted.push(ev.id);
    else rejected.push({ index, error: e.ingestErrors[0] !== before ? e.ingestErrors[0].error : "rejected" });
  });
  return json({ accepted: accepted.length, rejected, ids: accepted }, { status: rejected.length && !accepted.length ? 422 : 202 });
});
