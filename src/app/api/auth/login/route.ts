import { NextResponse } from "next/server";
import { SESSION_TTL_MS, login } from "@/server/auth";
import { assertSameOrigin, clientIp } from "@/server/context";
import { db } from "@/server/db";
import { body, fail, handle, rateLimit, sessionCookie } from "@/server/http";
import { LoginInput } from "@/server/schemas";

export const dynamic = "force-dynamic";

export const POST = handle(async (req: Request) => {
  assertSameOrigin(req);
  rateLimit(req, 10); // per client IP per minute, on top of per-account lockout
  const { email, password } = await body(req, LoginInput);
  const r = await login(await db(), email, password, { ip: clientIp(req) ?? undefined, ua: req.headers.get("user-agent") ?? undefined });
  if (!r.ok) {
    if (r.reason === "locked") return fail(423, `Account temporarily locked after repeated failures. Try again after ${new Date(r.until!).toLocaleTimeString("en-GB")}.`);
    if (r.reason === "disabled") return fail(403, "This account is disabled. Contact your administrator.");
    return fail(401, "Invalid email or password");
  }
  const res = NextResponse.json({ user: r.user });
  res.headers.set("set-cookie", sessionCookie(req, r.token, SESSION_TTL_MS / 1000));
  return res;
});
