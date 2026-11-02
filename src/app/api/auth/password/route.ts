import { NextResponse } from "next/server";
import { SESSION_TTL_MS, login, revokeUserSessions, verifyPassword } from "@/server/auth";
import { ctx } from "@/server/context";
import { body, fail, handle, rateLimit, sessionCookie } from "@/server/http";
import { updateUser, userPasswordHash } from "@/server/repo";
import { PasswordChange } from "@/server/schemas";

export const dynamic = "force-dynamic";

/** Change own password. Revokes all of the user's sessions, then issues a fresh one for this browser. */
export const POST = handle(async (req: Request) => {
  rateLimit(req, 10);
  const c = await ctx(req, "events:read");
  const { current, next } = await body(req, PasswordChange);
  const hash = await userPasswordHash(c.db, c.user.orgId, c.user.id);
  if (!hash || !(await verifyPassword(current, hash))) return fail(400, "Current password is incorrect");
  if (current === next) return fail(400, "New password must differ from the current one");
  await updateUser(c.db, c.user.orgId, c.user.id, { password: next });
  await revokeUserSessions(c.db, c.user.id);
  await c.audit("auth.password_change", c.user.email);
  const r = await login(c.db, c.user.email, next, { ip: c.ip ?? undefined, ua: req.headers.get("user-agent") ?? undefined });
  const res = NextResponse.json({ ok: true });
  if (r.ok) res.headers.set("set-cookie", sessionCookie(req, r.token, SESSION_TTL_MS / 1000));
  return res;
});
