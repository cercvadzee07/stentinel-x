/**
 * Authentication & authorization.
 *  - Passwords: scrypt (N=2^14, r=8, p=1, 64-byte key, 16-byte salt), constant-time compare.
 *  - Sessions: 32-byte random token in an HttpOnly SameSite=Lax cookie; only its SHA-256 is stored.
 *  - Lockout: 5 consecutive failures lock the account for 15 minutes.
 *  - API keys (ingestion): "sx_<prefix>_<secret>", SHA-256 stored, shown once at creation.
 * All authorization decisions are made here, server-side.
 */
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { can, type Permission, type Role, type SessionUser } from "../lib/rbac.ts";
import type { Db } from "./db/index.ts";

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, opts: object) => Promise<Buffer>;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export const SESSION_COOKIE = "sx_session";
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const MAX_FAILED = 5;
export const LOCK_MS = 15 * 60 * 1000;

export const newId = (prefix: string) => `${prefix}_${randomBytes(9).toString("base64url")}`;
export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, N, r, p, salt, hash] = stored.split("$");
  if (alg !== "scrypt" || !hash) return false;
  const expected = Buffer.from(hash, "base64");
  const key = await scrypt(pw, Buffer.from(salt, "base64"), expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

/** Hash used when the email is unknown, so response time doesn't reveal account existence. */
let dummyHash: Promise<string> | null = null;
const dummy = () => (dummyHash ??= hashPassword(randomBytes(12).toString("hex")));

export const passwordPolicy = (pw: string): string | null =>
  pw.length < 10 ? "Password must be at least 10 characters" : !/[a-zA-Z]/.test(pw) || !/\d/.test(pw) ? "Password must contain letters and digits" : null;

// ── login / sessions ───────────────────────────────────────────────────
interface UserRow {
  id: string; org_id: string; email: string; name: string; password_hash: string; role: Role; disabled: boolean;
  failed_logins: number; locked_until: Date | string | null; org_name: string; org_slug: string; demo: boolean;
}
const USER_SELECT = `SELECT u.*, o.name AS org_name, o.slug AS org_slug, o.demo FROM users u JOIN organizations o ON o.id = u.org_id`;
const toSession = (u: UserRow): SessionUser => ({ id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.org_id, orgName: u.org_name, orgSlug: u.org_slug, demo: u.demo });

export type LoginResult =
  | { ok: true; user: SessionUser; token: string }
  | { ok: false; reason: "invalid" | "locked" | "disabled"; until?: number };

export async function login(db: Db, email: string, password: string, meta: { ip?: string; ua?: string }): Promise<LoginResult> {
  const [u] = await db.query<UserRow>(`${USER_SELECT} WHERE lower(u.email) = lower($1)`, [email.trim()]);
  if (!u) { await verifyPassword(password, await dummy()); return { ok: false, reason: "invalid" }; }
  const lockedUntil = u.locked_until ? new Date(u.locked_until).getTime() : 0;
  if (lockedUntil > Date.now()) return { ok: false, reason: "locked", until: lockedUntil };
  const valid = await verifyPassword(password, u.password_hash);
  if (!valid) {
    const fails = u.failed_logins + 1;
    const lock = fails >= MAX_FAILED ? new Date(Date.now() + LOCK_MS) : null;
    await db.query(`UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1`, [u.id, lock ? 0 : fails, lock]);
    await audit(db, u.org_id, { id: u.id, name: u.email }, lock ? "auth.lockout" : "auth.login_failed", u.email, { ip: meta.ip, attempt: fails }, meta.ip);
    return lock ? { ok: false, reason: "locked", until: lock.getTime() } : { ok: false, reason: "invalid" };
  }
  if (u.disabled) return { ok: false, reason: "disabled" };
  const token = randomBytes(32).toString("base64url");
  await db.query(`INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`,
    [newId("ses"), u.id, sha256(token), meta.ip ?? null, meta.ua?.slice(0, 300) ?? null, new Date(Date.now() + SESSION_TTL_MS)]);
  await db.query(`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, [u.id]);
  await audit(db, u.org_id, { id: u.id, name: u.name }, "auth.login", u.email, { ua: meta.ua?.slice(0, 120) }, meta.ip);
  return { ok: true, user: toSession(u), token };
}

export async function sessionUser(db: Db, token: string | undefined | null): Promise<SessionUser | null> {
  if (!token || token.length < 20 || token.length > 100) return null;
  const [row] = await db.query<UserRow & { session_id: string; expires_at: Date | string }>(
    `SELECT u.*, o.name AS org_name, o.slug AS org_slug, o.demo, s.id AS session_id, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id JOIN organizations o ON o.id = u.org_id
      WHERE s.token_hash = $1`, [sha256(token)]);
  if (!row) return null;
  const exp = new Date(row.expires_at).getTime();
  if (exp < Date.now() || row.disabled) { await db.query(`DELETE FROM sessions WHERE id = $1`, [row.session_id]); return null; }
  // sliding expiry: refresh once less than half the lifetime remains
  if (exp - Date.now() < SESSION_TTL_MS / 2) await db.query(`UPDATE sessions SET expires_at = $2 WHERE id = $1`, [row.session_id, new Date(Date.now() + SESSION_TTL_MS)]);
  return toSession(row);
}

export async function logout(db: Db, token: string | undefined) {
  if (token) await db.query(`DELETE FROM sessions WHERE token_hash = $1`, [sha256(token)]);
}

export async function revokeUserSessions(db: Db, userId: string) {
  await db.query(`DELETE FROM sessions WHERE user_id = $1`, [userId]);
}

// ── API keys ───────────────────────────────────────────────────────────
export async function createApiKey(db: Db, orgId: string, name: string, createdBy: string) {
  const prefix = randomBytes(4).toString("hex");
  const secret = randomBytes(24).toString("base64url");
  const key = `sx_${prefix}_${secret}`;
  const id = newId("key");
  await db.query(`INSERT INTO api_keys (id, org_id, name, prefix, key_hash, created_by) VALUES ($1, $2, $3, $4, $5, $6)`, [id, orgId, name, prefix, sha256(key), createdBy]);
  return { id, key, prefix };
}

export async function apiKeyOrg(db: Db, key: string | null): Promise<{ orgId: string; keyId: string; name: string } | null> {
  if (!key || !/^sx_[0-9a-f]{8}_[\w-]{20,}$/.test(key)) return null;
  const [row] = await db.query<{ id: string; org_id: string; name: string }>(`SELECT id, org_id, name FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL`, [sha256(key)]);
  if (!row) return null;
  await db.query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [row.id]);
  return { orgId: row.org_id, keyId: row.id, name: row.name };
}

// ── audit ──────────────────────────────────────────────────────────────
export async function audit(db: Db, orgId: string, actor: { id: string | null; name: string }, action: string, target?: string | null, meta?: Record<string, unknown>, ip?: string | null) {
  await db.query(`INSERT INTO audit_log (org_id, actor_id, actor_name, action, target, meta, ip) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
    [orgId, actor.id, actor.name, action, target ?? null, meta ? JSON.stringify(meta) : null, ip ?? null]);
}

export { can };
export type { Permission };
