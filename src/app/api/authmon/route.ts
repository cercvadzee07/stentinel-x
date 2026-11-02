import { authStats } from "@/server/analytics";
import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "events:read")).engine();
  const u = new URL(req.url).searchParams;
  const to = Number(u.get("to")) || Date.now();
  const from = Number(u.get("from")) || to - 30 * 60_000;
  return json(authStats(e.events, from, to));
});
