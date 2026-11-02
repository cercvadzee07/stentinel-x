import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { RuleInput } from "@/server/schemas";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ id: string }> };

export const PATCH = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "rules:write");
  const e = await c.engine();
  const cur = e.rules.find((r) => r.id === id);
  if (!cur) return fail(404, "Rule not found");
  const patch = await body(req, RuleInput.partial());
  const rule = e.upsertRule({ ...cur, ...patch, logic: patch.logic ?? cur.logic, updatedAt: Date.now() });
  await c.audit(patch.enabled !== undefined && Object.keys(patch).length === 1 ? (patch.enabled ? "rule.enable" : "rule.disable") : "rule.update", id, { fields: Object.keys(patch) });
  return json(rule);
});

export const DELETE = handle(async (req: Request, { params }: Ctx) => {
  const { id } = await params;
  const c = await ctx(req, "rules:write");
  const e = await c.engine();
  const rule = e.rules.find((r) => r.id === id);
  if (!rule) return fail(404, "Rule not found");
  e.deleteRule(id);
  await c.audit("rule.delete", id, { name: rule.name });
  return json({ ok: true });
});
