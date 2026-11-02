import { NextResponse } from "next/server";
import { SESSION_TTL_MS, audit, login } from "@/server/auth";
import { assertSameOrigin, clientIp } from "@/server/context";
import { db } from "@/server/db";
import { body, fail, handle, rateLimit, sessionCookie } from "@/server/http";
import { createOrgWithAdmin } from "@/server/repo";
import { SignupInput } from "@/server/schemas";

export const dynamic = "force-dynamic";

/** Self-service organization creation (disable with ALLOW_SIGNUP=0). The creator becomes its first ADMIN. */
export const POST = handle(async (req: Request) => {
  if (process.env.ALLOW_SIGNUP === "0") return fail(403, "Self-service sign-up is disabled on this deployment");
  assertSameOrigin(req);
  rateLimit(req, 5);
  const input = await body(req, SignupInput);
  const d = await db();
  const { orgId, userId } = await createOrgWithAdmin(d, input);
  const ip = clientIp(req);
  await audit(d, orgId, { id: userId, name: input.name }, "org.create", input.orgName, undefined, ip);
  const r = await login(d, input.email, input.password, { ip: ip ?? undefined, ua: req.headers.get("user-agent") ?? undefined });
  if (!r.ok) return fail(500, "Organization created but sign-in failed; please log in");
  const res = NextResponse.json({ user: r.user }, { status: 201 });
  res.headers.set("set-cookie", sessionCookie(req, r.token, SESSION_TTL_MS / 1000));
  return res;
});
