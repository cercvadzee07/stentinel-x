import { NextResponse } from "next/server";
import { SESSION_COOKIE, audit, logout } from "@/server/auth";
import { assertSameOrigin, clientIp, cookie, optionalUser } from "@/server/context";
import { handle, sessionCookie } from "@/server/http";

export const dynamic = "force-dynamic";

export const POST = handle(async (req: Request) => {
  assertSameOrigin(req);
  const { db, user } = await optionalUser(req);
  await logout(db, cookie(req, SESSION_COOKIE));
  if (user) await audit(db, user.orgId, { id: user.id, name: user.name }, "auth.logout", user.email, undefined, clientIp(req));
  const res = NextResponse.json({ ok: true });
  res.headers.set("set-cookie", sessionCookie(req, null, 0));
  return res;
});
