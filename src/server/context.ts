/**
 * Request context for API routes: authenticate, authorize, resolve the tenant.
 * Every protected route starts with `const c = await ctx(req, "<permission>")`.
 */
import { can, type Permission, type SessionUser } from "../lib/rbac.ts";
import { SESSION_COOKIE, apiKeyOrg, audit, sessionUser } from "./auth.ts";
import { db, type Db } from "./db/index.ts";
import type { Engine } from "./engine.ts";
import { getEngine } from "./engines.ts";
import { HttpError } from "./errors.ts";

export interface Ctx {
  db: Db;
  user: SessionUser;
  ip: string | null;
  engine: () => Promise<Engine>;
  audit: (action: string, target?: string | null, meta?: Record<string, unknown>) => Promise<void>;
}

export function cookie(req: Request, name: string): string | undefined {
  const raw = req.headers.get("cookie");
  if (!raw) return undefined;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

export const clientIp = (req: Request) => req.headers.get("x-forwarded-for")?.split(",")[0].trim() || req.headers.get("x-real-ip") || null;

/** CSRF defence in depth (cookies are SameSite=Lax): state-changing requests must be same-origin JSON. */
export function assertSameOrigin(req: Request) {
  if (req.method === "GET" || req.method === "HEAD") return;
  const origin = req.headers.get("origin");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  if (origin && host && new URL(origin).host !== host) throw new HttpError(403, "Cross-origin request rejected");
  const ct = req.headers.get("content-type") ?? "";
  if (req.method !== "DELETE" && !ct.includes("application/json")) throw new HttpError(415, "Content-Type must be application/json");
}

export async function optionalUser(req: Request) {
  const d = await db();
  return { db: d, user: await sessionUser(d, cookie(req, SESSION_COOKIE)) };
}

export async function ctx(req: Request, perm: Permission): Promise<Ctx> {
  assertSameOrigin(req);
  const { db: d, user } = await optionalUser(req);
  if (!user) throw new HttpError(401, "Authentication required");
  if (!can(user.role, perm)) throw new HttpError(403, `Your role (${user.role}) is not allowed to perform this action`, { required: perm });
  const ip = clientIp(req);
  return {
    db: d, user, ip,
    engine: () => getEngine(user.orgId),
    audit: (action, target, meta) => audit(d, user.orgId, { id: user.id, name: user.name }, action, target, meta, ip),
  };
}

/** Ingestion accepts either a session with events:ingest or an organization API key (Bearer). */
export async function ingestCtx(req: Request): Promise<{ db: Db; orgId: string; actor: string }> {
  const auth = req.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const d = await db();
    const k = await apiKeyOrg(d, auth.slice(7).trim());
    if (!k) throw new HttpError(401, "Invalid or revoked API key");
    return { db: d, orgId: k.orgId, actor: `api-key:${k.name}` };
  }
  const c = await ctx(req, "events:ingest");
  return { db: c.db, orgId: c.user.orgId, actor: c.user.name };
}
