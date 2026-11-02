import { createApiKey } from "@/server/auth";
import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { listApiKeys } from "@/server/repo";
import { KeyCreate } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "keys:manage");
  return json(await listApiKeys(c.db, c.user.orgId));
});

/** The plaintext key is returned exactly once; only its SHA-256 is stored. */
export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "keys:manage");
  const { name } = await body(req, KeyCreate);
  const k = await createApiKey(c.db, c.user.orgId, name, c.user.name);
  await c.audit("apikey.create", k.id, { name, prefix: k.prefix });
  return json(k, { status: 201 });
});
