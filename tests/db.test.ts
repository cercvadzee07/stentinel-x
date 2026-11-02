import { after, before, test } from "node:test";
import assert from "node:assert/strict";

process.env.SENTINEL_DB = "memory";
delete process.env.DATABASE_URL;

const { openDb, migrate } = await import("../src/server/db/index.ts");
const { seed, DEMO_ORG, DEMO_PASSWORD } = await import("../src/server/db/seed.ts");
const auth = await import("../src/server/auth.ts");
const repo = await import("../src/server/repo.ts");
const { Engine } = await import("../src/server/engine.ts");
const { SCENARIOS } = await import("../src/server/simulator.ts");
const { can } = await import("../src/lib/rbac.ts");

type DbT = Awaited<ReturnType<typeof openDb>>;
let db: DbT;

before(async () => {
  db = await openDb();
  await seed(db);
});
after(async () => { await db.close(); });

test("migrations are idempotent and seed runs once", async () => {
  await migrate(db);
  await seed(db);
  const [{ n }] = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM organizations WHERE id = $1`, [DEMO_ORG.id]);
  assert.equal(n, 1);
});

test("password hashing uses scrypt and verifies in constant-time compare", async () => {
  const h = await auth.hashPassword("correct horse 42");
  assert.match(h, /^scrypt\$16384\$8\$1\$/);
  assert.ok(await auth.verifyPassword("correct horse 42", h));
  assert.ok(!(await auth.verifyPassword("correct horse 43", h)));
});

test("login issues a session; only the token hash is stored; logout revokes it", async () => {
  const r = await auth.login(db, "ADMIN@acme.test", DEMO_PASSWORD, { ip: "127.0.0.1" });
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.user.role, "ADMIN");
  const rows = await db.query<{ token_hash: string }>(`SELECT token_hash FROM sessions`);
  assert.ok(rows.every((x) => x.token_hash !== r.token && x.token_hash.length === 64));
  assert.equal((await auth.sessionUser(db, r.token))?.email, "admin@acme.test");
  await auth.logout(db, r.token);
  assert.equal(await auth.sessionUser(db, r.token), null);
});

test("five failures lock the account, even against the right password", async () => {
  for (let i = 0; i < 4; i++) assert.deepEqual(await auth.login(db, "viewer@acme.test", "wrong-password-1", {}), { ok: false, reason: "invalid" });
  const fifth = await auth.login(db, "viewer@acme.test", "wrong-password-1", {});
  assert.equal(fifth.ok === false && fifth.reason, "locked");
  const right = await auth.login(db, "viewer@acme.test", DEMO_PASSWORD, {});
  assert.equal(right.ok === false && right.reason, "locked");
  await repo.updateUser(db, DEMO_ORG.id, "usr_viewer", { unlock: true });
  assert.ok((await auth.login(db, "viewer@acme.test", DEMO_PASSWORD, {})).ok);
  const audit = await repo.listAudit(db, DEMO_ORG.id, { q: "auth.lockout" });
  assert.equal(audit.length, 1);
});

test("unknown email and wrong password are indistinguishable", async () => {
  assert.deepEqual(await auth.login(db, "nobody@acme.test", "whatever-123", {}), { ok: false, reason: "invalid" });
});

test("tenant isolation: another org cannot read or modify ACME assets", async () => {
  const b = await repo.createOrgWithAdmin(db, { orgName: "Globex", name: "Hank", email: "hank@globex.test", password: "GlobexPass123" });
  const acme = await repo.listAssets(db, DEMO_ORG.id);
  assert.ok(acme.length > 30);
  assert.equal((await repo.listAssets(db, b.orgId)).length, 0);
  assert.equal(await repo.getAsset(db, b.orgId, acme[0].id), null);
  await assert.rejects(repo.updateAsset(db, b.orgId, acme[0].id, { hostname: "pwned" }), /not found/);
  await assert.rejects(repo.deleteAsset(db, b.orgId, acme[0].id), /not found/);
  assert.equal((await repo.getAsset(db, DEMO_ORG.id, acme[0].id))?.hostname, acme[0].hostname);
  // same IP is allowed in a different tenant, but not twice in one
  await repo.createAsset(db, b.orgId, { hostname: "gx-web", ip: acme[0].ip, type: "web", criticality: 3, monitored: true });
  await assert.rejects(repo.createAsset(db, b.orgId, { hostname: "gx-web2", ip: acme[0].ip, type: "web", criticality: 3, monitored: true }), /already exists/);
});

test("an organization always keeps one active administrator", async () => {
  const b = await repo.createOrgWithAdmin(db, { orgName: "Initech", name: "Bill", email: "bill@initech.test", password: "InitechPass123" });
  await assert.rejects(repo.updateUser(db, b.orgId, b.userId, { role: "VIEWER" }), /at least one active administrator/);
  await assert.rejects(repo.updateUser(db, b.orgId, b.userId, { disabled: true }), /at least one active administrator/);
});

test("API keys authenticate ingestion until revoked", async () => {
  const k = await auth.createApiKey(db, DEMO_ORG.id, "suricata-sensor", "test");
  assert.match(k.key, /^sx_[0-9a-f]{8}_/);
  assert.equal((await auth.apiKeyOrg(db, k.key))?.orgId, DEMO_ORG.id);
  assert.equal(await auth.apiKeyOrg(db, k.key.slice(0, -2) + "xx"), null);
  await repo.revokeApiKey(db, DEMO_ORG.id, k.id);
  assert.equal(await auth.apiKeyOrg(db, k.key), null);
});

test("RBAC matrix", () => {
  assert.ok(can("VIEWER", "events:read"));
  assert.ok(!can("VIEWER", "alerts:write"));
  assert.ok(!can("VIEWER", "events:export"));
  assert.ok(can("ANALYST", "alerts:write"));
  assert.ok(!can("ANALYST", "rules:write"));
  assert.ok(!can("ANALYST", "users:manage"));
  assert.ok(can("ADMIN", "users:manage"));
});

test("engine state survives a restart via the database", async () => {
  const org = await repo.createOrgWithAdmin(db, { orgName: "Umbrella", name: "Alice", email: "alice@umbrella.test", password: "UmbrellaPass1" });
  const o = (await repo.getOrg(db, org.orgId))!;
  const e1 = await Engine.create(db, o, { start: false });
  assert.equal(e1.rules.length, 10);
  const def = SCENARIOS.find((s) => s.id === "ssh_bruteforce")!;
  const c = def.init();
  const t0 = Date.now() - 60_000;
  for (let i = 0; i < 30; i++) for (const env of [def.make(t0 + i * 160, i / 30, c)].flat()) e1.ingest(env);
  assert.ok(e1.alerts.length >= 1);
  const alert = e1.alerts.find((a) => a.ruleId === "R-001")!;
  e1.updateAlert(alert.id, { status: "investigating", assignee: "Alice", comment: "looking" }, "Alice");
  const inc = e1.createIncident({ title: "SSH intrusion", description: "", alertIds: [alert.id] }, "Alice");
  e1.deleteRule("R-010");
  await e1.persist();

  const e2 = await Engine.create(db, o, { start: false });
  assert.equal(e2.events.length, e1.events.length);
  assert.equal(e2.rules.length, 9);
  const a2 = e2.alerts.find((a) => a.id === alert.id)!;
  assert.equal(a2.status, "investigating"); // only "new" alerts auto-escalate when linked
  assert.equal(a2.incidentId, inc.id);
  assert.equal(a2.comments[0].text, "looking");
  assert.equal(e2.incidents[0].id, inc.id);
  assert.ok(e2.rules.find((r) => r.id === "R-001")!.triggerCount >= 1);
  // the next incident number continues after a restart
  assert.notEqual(e2.createIncident({ title: "second", description: "", alertIds: [] }, "Alice").id, inc.id);
  // and none of it is visible to the demo tenant
  const [{ n }] = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM events WHERE org_id = $1 AND id = $2`, [DEMO_ORG.id, e1.events[0].id]);
  assert.equal(n, 0);
});
