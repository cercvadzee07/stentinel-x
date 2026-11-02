import { ctx } from "@/server/context";
import { handle, json } from "@/server/http";
import { nmapStatus } from "@/server/scan/nmap";
import { MAX_HOSTS, MAX_PREFIX, TOP_TCP, TOP_UDP } from "@/server/scan/policy";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  await ctx(req, "scans:read");
  return json({
    nmap: await nmapStatus(),
    simulated: { available: true, reason: "Results are generated from your asset inventory — not network observations." },
    limits: { maxPrefix: MAX_PREFIX, maxHosts: MAX_HOSTS, allowPublic: process.env.SCAN_ALLOW_PUBLIC === "1", topTcp: TOP_TCP.length, topUdp: TOP_UDP.length },
  });
});
