import { z } from "zod";
import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { RuleInput } from "@/server/schemas";

export const dynamic = "force-dynamic";

const Schema = z.object({ ruleId: z.string().optional(), rule: RuleInput.optional(), windowMin: z.number().int().min(1).max(1440).optional() });

/** Backtest a saved or draft rule against stored historical events. */
export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "rules:test");
  const { ruleId, rule, windowMin } = await body(req, Schema);
  const e = await c.engine();
  const target = rule
    ? { ...rule, id: "draft", builtin: false, triggerCount: 0, lastTriggered: null, createdAt: 0, updatedAt: 0 }
    : e.rules.find((r) => r.id === ruleId);
  if (!target) return fail(404, "Rule not found");
  const res = e.testRule(target, windowMin ? windowMin * 60_000 : undefined);
  return json({ ...res, hits: res.hits.slice(0, 200), windowMin: windowMin ?? null });
});
