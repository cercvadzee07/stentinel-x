import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { RuleInput } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => json((await (await ctx(req, "rules:read")).engine()).rules));

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "rules:write");
  const input = await body(req, RuleInput);
  const now = Date.now();
  const rule = (await c.engine()).upsertRule({ ...input, id: `R-${now.toString(36).toUpperCase()}`, builtin: false, triggerCount: 0, lastTriggered: null, createdAt: now, updatedAt: now });
  await c.audit("rule.create", rule.id, { name: rule.name, filter: rule.logic.filter });
  return json(rule, { status: 201 });
});
