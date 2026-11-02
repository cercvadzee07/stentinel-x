import { revokeUserSessions } from "@/server/auth";
import { ctx } from "@/server/context";
import { body, fail, handle, json } from "@/server/http";
import { updateUser } from "@/server/repo";
import { UserPatch } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const PATCH = handle(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const { id } = await params;
  const c = await ctx(req, "users:manage");
  const patch = await body(req, UserPatch);
  if (id === c.user.id && (patch.role || patch.disabled)) return fail(409, "You cannot change your own role or disable your own account");
  await updateUser(c.db, c.user.orgId, id, patch);
  // role changes, disabling and admin password resets invalidate existing sessions
  if (patch.role || patch.disabled || patch.password) await revokeUserSessions(c.db, id);
  await c.audit("user.update", id, { role: patch.role, disabled: patch.disabled, passwordReset: !!patch.password, unlock: patch.unlock, name: patch.name });
  return json({ ok: true });
});
