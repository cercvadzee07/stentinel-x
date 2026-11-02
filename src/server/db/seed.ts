/**
 * Demo tenant seed (idempotent). Runs on first boot when SEED_DEMO is not "0".
 *
 * Demo accounts — local/demo use only. Override the shared password with DEMO_PASSWORD.
 *   admin@acme.test     ADMIN
 *   analyst@acme.test   ANALYST
 *   t.okoye@acme.test   ANALYST
 *   s.lindqvist@acme.test ANALYST
 *   viewer@acme.test    VIEWER
 */
import { hashPassword } from "../auth.ts";
import { ASSETS } from "../inventory.ts";
import type { Db } from "./index.ts";

export const DEMO_ORG = { id: "org_acme", name: "ACME Corp", slug: "acme-corp" };
export const DEMO_PASSWORD = process.env.DEMO_PASSWORD ?? "SentinelDemo2026";
export const DEMO_USERS = [
  { id: "usr_admin", email: "admin@acme.test", name: "N. Carter", role: "ADMIN" },
  { id: "usr_analyst", email: "analyst@acme.test", name: "A. Volkova", role: "ANALYST" },
  { id: "usr_okoye", email: "t.okoye@acme.test", name: "T. Okoye", role: "ANALYST" },
  { id: "usr_lindqvist", email: "s.lindqvist@acme.test", name: "S. Lindqvist", role: "ANALYST" },
  { id: "usr_viewer", email: "viewer@acme.test", name: "R. Mendes", role: "VIEWER" },
] as const;

export async function seed(db: Db) {
  if (process.env.SEED_DEMO === "0") return;
  const [exists] = await db.query(`SELECT 1 FROM organizations WHERE id = $1`, [DEMO_ORG.id]);
  if (exists) return ensureDemoExtras(db);
  const hash = await hashPassword(DEMO_PASSWORD);
  await db.tx(async (q) => {
    await q(`INSERT INTO organizations (id, name, slug, demo, settings) VALUES ($1, $2, $3, true, $4::jsonb)`,
      [DEMO_ORG.id, DEMO_ORG.name, DEMO_ORG.slug, JSON.stringify({ simulator: { running: true, rate: 35, autoScenarios: true } })]);
    for (const u of DEMO_USERS)
      await q(`INSERT INTO users (id, org_id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5, $6)`, [u.id, DEMO_ORG.id, u.email, u.name, hash, u.role]);
    for (const a of ASSETS)
      await q(`INSERT INTO assets (id, org_id, hostname, ip, mac, os, type, location, owner, criticality, monitored, online, simulated, last_seen)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true, now())`,
        [a.id.toLowerCase().replace("ast-", "ast_"), DEMO_ORG.id, a.hostname, a.ip, a.mac, a.os, a.type, a.location, a.owner, a.criticality, a.monitored, a.online]);
  });
  await ensureDemoExtras(db);
}

/** Seed data added by later migrations; safe to run on every boot. */
async function ensureDemoExtras(db: Db) {
  await db.query(`INSERT INTO scan_allowlist (org_id, id, cidr, label, created_by) VALUES ($1, 'al_demo_corp', '10.0.0.0/8', 'ACME internal networks (demo)', 'seed')
                  ON CONFLICT DO NOTHING`, [DEMO_ORG.id]);
}
