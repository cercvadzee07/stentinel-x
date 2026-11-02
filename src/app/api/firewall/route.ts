import { firewallStats } from "@/server/analytics";
import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "events:read")).engine();
  const u = new URL(req.url).searchParams;
  const to = Number(u.get("to")) || Date.now();
  const from = Number(u.get("from")) || to - 30 * 60_000;
  const s = (k: string) => (u.get(k) ?? "").trim().slice(0, 64) || undefined;
  const action = u.get("action");
  return json(firewallStats(e.events, {
    from, to, src: s("src"), sport: s("sport"), dst: s("dst"), dport: s("dport"), proto: s("proto"), device: s("device"),
    action: action === "allow" || action === "deny" ? action : "",
  }, e.assets, e.telemetry));
});
