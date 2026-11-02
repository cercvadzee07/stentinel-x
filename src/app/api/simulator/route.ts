import { z } from "zod";
import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { SCENARIOS } from "@/server/simulator";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const e = await (await ctx(req, "events:read")).engine();
  return json({ state: e.simState(), scenarios: SCENARIOS.map(({ id, name, description, duration }) => ({ id, name, description, duration })) });
});

const Schema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("start") }),
  z.object({ action: z.literal("stop") }),
  z.object({ action: z.literal("reset") }),
  z.object({ action: z.literal("config"), rate: z.number().min(1).max(500).optional(), autoScenarios: z.boolean().optional() }),
  z.object({ action: z.literal("scenario"), id: z.string().refine((id) => SCENARIOS.some((s) => s.id === id), "Unknown scenario") }),
]);

export const POST = handle(async (req: Request) => {
  const raw = await req.clone().json().catch(() => ({}));
  // launching a scenario is an analyst action; controlling the generator itself is admin-only
  const c = await ctx(req, raw?.action === "scenario" ? "simulator:scenario" : "simulator:control");
  const cmd = await body(req, Schema);
  const e = await c.engine();
  switch (cmd.action) {
    case "start": e.setSimulator({ running: true }); break;
    case "stop": e.setSimulator({ running: false }); break;
    case "reset": await e.reset(); break;
    case "config": e.setSimulator({ rate: cmd.rate, autoScenarios: cmd.autoScenarios }); break;
    case "scenario": e.launch(cmd.id); break;
  }
  await c.audit(`simulator.${cmd.action}`, cmd.action === "scenario" ? cmd.id : null, cmd.action === "config" ? { rate: cmd.rate, autoScenarios: cmd.autoScenarios } : undefined);
  return json({ state: e.simState() });
});
