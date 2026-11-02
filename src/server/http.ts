import { NextResponse } from "next/server";
import { z, type ZodTypeAny } from "zod";
import { SxqlError } from "../lib/sxql.ts";
import { HttpError } from "./errors.ts";

export { HttpError };

export const json = (data: unknown, init?: ResponseInit) => NextResponse.json(data, init);
export const fail = (status: number, error: string, extra?: Record<string, unknown>) => NextResponse.json({ error, ...extra }, { status });


export async function body<T extends ZodTypeAny>(req: Request, schema: T): Promise<z.infer<T>> {
  let raw: unknown;
  try { raw = await req.json(); } catch { throw new HttpError(400, "Body must be valid JSON"); }
  const r = schema.safeParse(raw);
  if (!r.success) throw new HttpError(422, "Validation failed", { issues: r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
  return r.data;
}


export function handle<A extends unknown[]>(fn: (...a: A) => Promise<Response> | Response) {
  return async (...a: A) => {
    try { return await fn(...a); } catch (err) {
      if (err instanceof HttpError || (err as Error)?.name === "HttpError") return fail((err as HttpError).status, (err as HttpError).message, (err as HttpError).extra);
      // name check, not instanceof: route bundles may hold separate copies of the class
      if (err instanceof SxqlError || (err as Error)?.name === "SxqlError")
        return fail(400, `Query error: ${(err as SxqlError).message}`, { position: (err as SxqlError).position });
      console.error(err);
      return fail(500, "Internal error");
    }
  };
}

/** Fixed-window limiter keyed by client address (in-memory; Redis in production). */
const windows = new Map<string, { start: number; n: number }>();
export function rateLimit(req: Request, limit: number, windowMs = 60_000) {
  const key = (req.headers.get("x-forwarded-for")?.split(",")[0] ?? "local").trim() + new URL(req.url).pathname;
  const now = Date.now();
  const w = windows.get(key);
  if (!w || now - w.start > windowMs) { windows.set(key, { start: now, n: 1 }); return; }
  if (++w.n > limit) throw new HttpError(429, "Rate limit exceeded");
}

const csvCell = (v: unknown) => {
  const s = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return /[",\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${s.replace(/^([=+\-@])/, "'$1").replace(/"/g, '""')}"` : s;
};
export function csv(rows: Record<string, unknown>[], cols: string[]) {
  return [cols.join(","), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\n");
}
export function download(content: string, filename: string, type: string) {
  return new Response(content, { headers: { "content-type": type, "content-disposition": `attachment; filename="${filename}"` } });
}

/** Session cookie. Secure when served over HTTPS (or COOKIE_SECURE=1). */
export function sessionCookie(req: Request, token: string | null, maxAgeSec: number) {
  const https = new URL(req.url).protocol === "https:" || req.headers.get("x-forwarded-proto") === "https" || process.env.COOKIE_SECURE === "1";
  return [`sx_session=${token ?? ""}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${token ? maxAgeSec : 0}`, https ? "Secure" : ""].filter(Boolean).join("; ");
}
