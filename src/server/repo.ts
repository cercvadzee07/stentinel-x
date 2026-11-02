/**
 * Repositories. Every function takes the tenant (orgId) explicitly and every
 * statement filters on org_id — tenant isolation lives here, not in callers.
 */
import type { Role } from "../lib/rbac.ts";
import type { Alert, DetectionRule, Incident, SecurityEvent } from "../lib/types.ts";
import { HttpError } from "./errors.ts";
import { hashPassword, newId } from "./auth.ts";
import type { Db } from "./db/index.ts";

const iso = (v: Date | string | null | undefined) => (v ? new Date(v).getTime() : null);

// ── organizations ──────────────────────────────────────────────────────
export interface OrgSettings { simulator?: { running: boolean; rate: number; autoScenarios: boolean } }
export interface Org { id: string; name: string; slug: string; demo: boolean; settings: OrgSettings }

export async function getOrg(db: Db, id: string): Promise<Org | null> {
  const [o] = await db.query<Org>(`SELECT id, name, slug, demo, settings FROM organizations WHERE id = $1`, [id]);
  return o ?? null;
}

export async function updateOrgSettings(db: Db, orgId: string, settings: OrgSettings) {
  await db.query(`UPDATE organizations SET settings = settings || $2::jsonb WHERE id = $1`, [orgId, JSON.stringify(settings)]);
}

export const slugify = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "org";

export async function createOrgWithAdmin(db: Db, p: { orgName: string; name: string; email: string; password: string }) {
  const [taken] = await db.query(`SELECT 1 FROM users WHERE lower(email) = lower($1)`, [p.email]);
  if (taken) throw new HttpError(409, "An account with this email already exists");
  let slug = slugify(p.orgName);
  if ((await db.query(`SELECT 1 FROM organizations WHERE slug = $1`, [slug])).length) slug = `${slug}-${newId("x").slice(2, 7).toLowerCase()}`;
  const orgId = newId("org"), userId = newId("usr");
  const hash = await hashPassword(p.password);
  await db.tx(async (q) => {
    await q(`INSERT INTO organizations (id, name, slug, demo, settings) VALUES ($1, $2, $3, false, $4::jsonb)`,
      [orgId, p.orgName, slug, JSON.stringify({ simulator: { running: false, rate: 20, autoScenarios: false } })]);
    await q(`INSERT INTO users (id, org_id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5, 'ADMIN')`, [userId, orgId, p.email.trim(), p.name, hash]);
  });
  return { orgId, userId, slug };
}

// ── users ──────────────────────────────────────────────────────────────
export interface UserView { id: string; email: string; name: string; role: Role; disabled: boolean; lastLoginAt: number | null; createdAt: number; locked: boolean }
type UserRowDb = { id: string; email: string; name: string; role: Role; disabled: boolean; last_login_at: Date | null; created_at: Date; locked_until: Date | null };
const userView = (r: UserRowDb): UserView => ({ id: r.id, email: r.email, name: r.name, role: r.role, disabled: r.disabled, lastLoginAt: iso(r.last_login_at), createdAt: iso(r.created_at)!, locked: !!r.locked_until && new Date(r.locked_until).getTime() > Date.now() });

export async function listUsers(db: Db, orgId: string): Promise<UserView[]> {
  return (await db.query<UserRowDb>(`SELECT id, email, name, role, disabled, last_login_at, created_at, locked_until FROM users WHERE org_id = $1 ORDER BY created_at`, [orgId])).map(userView);
}

export async function createUser(db: Db, orgId: string, p: { email: string; name: string; role: Role; password: string }) {
  const [taken] = await db.query(`SELECT 1 FROM users WHERE lower(email) = lower($1)`, [p.email]);
  if (taken) throw new HttpError(409, "An account with this email already exists");
  const id = newId("usr");
  await db.query(`INSERT INTO users (id, org_id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5, $6)`, [id, orgId, p.email.trim(), p.name, await hashPassword(p.password), p.role]);
  return id;
}

async function activeAdmins(db: Db, orgId: string) {
  return (await db.query<{ id: string }>(`SELECT id FROM users WHERE org_id = $1 AND role = 'ADMIN' AND NOT disabled`, [orgId])).map((r) => r.id);
}

export async function updateUser(db: Db, orgId: string, id: string, p: { role?: Role; disabled?: boolean; name?: string; password?: string; unlock?: boolean }) {
  const [u] = await db.query<{ role: Role; disabled: boolean }>(`SELECT role, disabled FROM users WHERE id = $1 AND org_id = $2`, [id, orgId]);
  if (!u) throw new HttpError(404, "User not found");
  const losesAdmin = u.role === "ADMIN" && !u.disabled && ((p.role && p.role !== "ADMIN") || p.disabled === true);
  if (losesAdmin && (await activeAdmins(db, orgId)).length <= 1) throw new HttpError(409, "The organization must keep at least one active administrator");
  if (p.role) await db.query(`UPDATE users SET role = $3 WHERE id = $1 AND org_id = $2`, [id, orgId, p.role]);
  if (p.disabled !== undefined) await db.query(`UPDATE users SET disabled = $3 WHERE id = $1 AND org_id = $2`, [id, orgId, p.disabled]);
  if (p.name) await db.query(`UPDATE users SET name = $3 WHERE id = $1 AND org_id = $2`, [id, orgId, p.name]);
  if (p.password) await db.query(`UPDATE users SET password_hash = $3 WHERE id = $1 AND org_id = $2`, [id, orgId, await hashPassword(p.password)]);
  if (p.unlock) await db.query(`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1 AND org_id = $2`, [id, orgId]);
}

export async function userPasswordHash(db: Db, orgId: string, id: string) {
  const [u] = await db.query<{ password_hash: string }>(`SELECT password_hash FROM users WHERE id = $1 AND org_id = $2`, [id, orgId]);
  return u?.password_hash ?? null;
}

/** Analysts eligible for assignment (active, non-viewer). */
export async function assignableAnalysts(db: Db, orgId: string) {
  return (await db.query<{ name: string }>(`SELECT name FROM users WHERE org_id = $1 AND NOT disabled AND role <> 'VIEWER' ORDER BY name`, [orgId])).map((r) => r.name);
}

// ── API keys ───────────────────────────────────────────────────────────
export async function listApiKeys(db: Db, orgId: string) {
  return (await db.query<{ id: string; name: string; prefix: string; created_by: string | null; created_at: Date; last_used_at: Date | null; revoked_at: Date | null }>(
    `SELECT id, name, prefix, created_by, created_at, last_used_at, revoked_at FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, [orgId]))
    .map((k) => ({ id: k.id, name: k.name, prefix: k.prefix, createdBy: k.created_by, createdAt: iso(k.created_at), lastUsedAt: iso(k.last_used_at), revokedAt: iso(k.revoked_at) }));
}

export async function revokeApiKey(db: Db, orgId: string, id: string) {
  const r = await db.query(`UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL RETURNING id`, [id, orgId]);
  if (!r.length) throw new HttpError(404, "Key not found or already revoked");
}

// ── audit ──────────────────────────────────────────────────────────────
export async function listAudit(db: Db, orgId: string, p: { limit?: number; before?: number; q?: string }) {
  const params: unknown[] = [orgId, Math.min(500, p.limit ?? 100)];
  let where = `org_id = $1`;
  if (p.before) { params.push(p.before); where += ` AND id < $${params.length}`; }
  if (p.q) { params.push(`%${p.q}%`); where += ` AND (action ILIKE $${params.length} OR actor_name ILIKE $${params.length} OR target ILIKE $${params.length})`; }
  return (await db.query<{ id: number; actor_name: string; action: string; target: string | null; meta: unknown; ip: string | null; created_at: Date }>(
    `SELECT id, actor_name, action, target, meta, ip, created_at FROM audit_log WHERE ${where} ORDER BY id DESC LIMIT $2`, params))
    .map((r) => ({ id: Number(r.id), actor: r.actor_name, action: r.action, target: r.target, meta: r.meta, ip: r.ip, at: iso(r.created_at)! }));
}

// ── assets ─────────────────────────────────────────────────────────────
export interface AssetRecord {
  id: string; hostname: string; ip: string; mac: string | null; os: string | null; type: string; location: string | null; owner: string | null;
  criticality: number; monitored: boolean; online: boolean; simulated: boolean; notes: string | null; lastSeen: number | null; createdAt: number; updatedAt: number;
}
type AssetRow = Omit<AssetRecord, "lastSeen" | "createdAt" | "updatedAt"> & { last_seen: Date | null; created_at: Date; updated_at: Date };
const assetView = ({ last_seen, created_at, updated_at, ...r }: AssetRow): AssetRecord => ({ ...r, lastSeen: iso(last_seen), createdAt: iso(created_at)!, updatedAt: iso(updated_at)! });
const ASSET_COLS = `id, hostname, ip, mac, os, type, location, owner, criticality, monitored, online, simulated, notes, last_seen, created_at, updated_at`;

export async function listAssets(db: Db, orgId: string): Promise<AssetRecord[]> {
  return (await db.query<AssetRow>(`SELECT ${ASSET_COLS} FROM assets WHERE org_id = $1 ORDER BY criticality DESC, hostname`, [orgId])).map(assetView);
}

export async function getAsset(db: Db, orgId: string, id: string) {
  const [r] = await db.query<AssetRow>(`SELECT ${ASSET_COLS} FROM assets WHERE id = $1 AND org_id = $2`, [id, orgId]);
  return r ? assetView(r) : null;
}

export type AssetInput = Pick<AssetRecord, "hostname" | "ip" | "type" | "criticality" | "monitored"> & Partial<Pick<AssetRecord, "mac" | "os" | "location" | "owner" | "notes" | "online">>;

const uniqueIp = (e: unknown) => { if (String((e as Error).message).includes("assets_org_id_ip_key") || (e as { code?: string }).code === "23505") throw new HttpError(409, "An asset with this IP address already exists"); throw e; };

export async function createAsset(db: Db, orgId: string, a: AssetInput) {
  const id = newId("ast");
  await db.query(`INSERT INTO assets (id, org_id, hostname, ip, mac, os, type, location, owner, criticality, monitored, online, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id, orgId, a.hostname, a.ip, a.mac ?? null, a.os ?? null, a.type, a.location ?? null, a.owner ?? null, a.criticality, a.monitored, a.online ?? true, a.notes ?? null]).catch(uniqueIp);
  return (await getAsset(db, orgId, id))!;
}

export async function updateAsset(db: Db, orgId: string, id: string, a: Partial<AssetInput>) {
  const cols = ["hostname", "ip", "mac", "os", "type", "location", "owner", "criticality", "monitored", "online", "notes"] as const;
  const sets: string[] = [], params: unknown[] = [id, orgId];
  for (const c of cols) if (a[c] !== undefined) { params.push(a[c]); sets.push(`${c} = $${params.length}`); }
  if (!sets.length) return getAsset(db, orgId, id);
  const r = await db.query(`UPDATE assets SET ${sets.join(", ")}, updated_at = now() WHERE id = $1 AND org_id = $2 RETURNING id`, params).catch(uniqueIp);
  if (!r.length) throw new HttpError(404, "Asset not found");
  return getAsset(db, orgId, id);
}

export async function deleteAsset(db: Db, orgId: string, id: string) {
  const r = await db.query<{ hostname: string }>(`DELETE FROM assets WHERE id = $1 AND org_id = $2 RETURNING hostname`, [id, orgId]);
  if (!r.length) throw new HttpError(404, "Asset not found");
  return r[0].hostname;
}

// ── engine persistence ─────────────────────────────────────────────────
export async function loadEngineState(db: Db, orgId: string, eventLimit: number) {
  const [rules, alerts, incidents, events] = await Promise.all([
    db.query<{ doc: DetectionRule }>(`SELECT doc FROM rules WHERE org_id = $1`, [orgId]),
    db.query<{ doc: Alert }>(`SELECT doc FROM alerts WHERE org_id = $1 ORDER BY last_seen DESC LIMIT 2000`, [orgId]),
    db.query<{ doc: Incident }>(`SELECT doc FROM incidents WHERE org_id = $1 ORDER BY updated_at DESC`, [orgId]),
    db.query<{ doc: SecurityEvent }>(`SELECT doc FROM events WHERE org_id = $1 ORDER BY ts DESC LIMIT $2`, [orgId, eventLimit]),
  ]);
  return { rules: rules.map((r) => r.doc), alerts: alerts.map((r) => r.doc), incidents: incidents.map((r) => r.doc), events: events.map((r) => r.doc).reverse() };
}

export interface Flush { events: SecurityEvent[]; alerts: Alert[]; incidents: Incident[]; rules: DetectionRule[]; deletedRules: string[] }

/** Write-behind batch from the engine: one transaction per flush. */
export async function persistBatch(db: Db, orgId: string, f: Flush) {
  await db.tx(async (q) => {
    for (let i = 0; i < f.events.length; i += 400) {
      const chunk = f.events.slice(i, i + 400);
      const params: unknown[] = [orgId];
      const rows = chunk.map((e) => {
        params.push(e.id, new Date(e.timestamp), e.type, e.severity, e.sourceIp, e.destinationIp, e.destinationPort, e.username, e.simulated, JSON.stringify(e));
        const b = params.length - 10;
        return `($1,$${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6},$${b + 7},$${b + 8},$${b + 9},$${b + 10}::jsonb)`;
      });
      await q(`INSERT INTO events (org_id, id, ts, type, severity, source_ip, destination_ip, destination_port, username, simulated, doc) VALUES ${rows.join(",")} ON CONFLICT DO NOTHING`, params);
    }
    for (const a of f.alerts)
      await q(`INSERT INTO alerts (org_id, id, status, severity, last_seen, doc) VALUES ($1,$2,$3,$4,$5,$6::jsonb)
               ON CONFLICT (org_id, id) DO UPDATE SET status = EXCLUDED.status, severity = EXCLUDED.severity, last_seen = EXCLUDED.last_seen, doc = EXCLUDED.doc`,
        [orgId, a.id, a.status, a.severity, new Date(a.lastSeen), JSON.stringify(a)]);
    for (const i of f.incidents)
      await q(`INSERT INTO incidents (org_id, id, status, updated_at, doc) VALUES ($1,$2,$3,$4,$5::jsonb)
               ON CONFLICT (org_id, id) DO UPDATE SET status = EXCLUDED.status, updated_at = EXCLUDED.updated_at, doc = EXCLUDED.doc`,
        [orgId, i.id, i.status, new Date(i.updatedAt), JSON.stringify(i)]);
    for (const r of f.rules)
      await q(`INSERT INTO rules (org_id, id, doc, updated_at) VALUES ($1,$2,$3::jsonb, now()) ON CONFLICT (org_id, id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`,
        [orgId, r.id, JSON.stringify(r)]);
    for (const id of f.deletedRules) await q(`DELETE FROM rules WHERE org_id = $1 AND id = $2`, [orgId, id]);
  });
}

export async function purgeEngineData(db: Db, orgId: string) {
  await db.tx(async (q) => {
    for (const t of ["events", "alerts", "incidents", "rules"]) await q(`DELETE FROM ${t} WHERE org_id = $1`, [orgId]);
  });
}

/** Retention: keep the newest `keep` events per org. */
export async function pruneEvents(db: Db, orgId: string, keep: number) {
  await db.query(`DELETE FROM events WHERE org_id = $1 AND ts < (SELECT ts FROM events WHERE org_id = $1 ORDER BY ts DESC OFFSET $2 LIMIT 1)`, [orgId, keep]);
}
