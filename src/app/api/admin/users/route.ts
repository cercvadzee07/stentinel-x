import { ctx } from "@/server/context";
import { body, handle, json } from "@/server/http";
import { createUser, listUsers } from "@/server/repo";
import { UserCreate } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const GET = handle(async (req: Request) => {
  const c = await ctx(req, "users:manage");
  return json(await listUsers(c.db, c.user.orgId));
});

export const POST = handle(async (req: Request) => {
  const c = await ctx(req, "users:manage");
  const input = await body(req, UserCreate);
  const id = await createUser(c.db, c.user.orgId, input);
  await c.audit("user.create", input.email, { role: input.role, id });
  return json({ id }, { status: 201 });
});
