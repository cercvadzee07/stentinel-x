/**
 * Database access. One interface, two drivers:
 *   - DATABASE_URL set  → node-postgres pool against a real PostgreSQL server
 *   - otherwise         → PGlite (PostgreSQL compiled to WASM, in-process), persisted under .data/pglite
 *                          or in memory when SENTINEL_DB=memory (tests)
 * Both speak the same SQL, so migrations and repositories are shared.
 */
import { HttpError } from "../errors.ts";
import { MIGRATIONS } from "./migrations.ts";

export interface Db {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<T[]>;
  tx<R>(fn: (q: Db["query"]) => Promise<R>): Promise<R>;
  driver: "pglite" | "postgres";
  close(): Promise<void>;
}

async function pglite(dataDir: string | undefined): Promise<Db> {
  const { PGlite } = await import("@electric-sql/pglite");
  if (dataDir) {
    // PGlite creates its own directory but not missing parents
    const [{ mkdirSync }, { dirname, resolve }] = await Promise.all([import("node:fs"), import("node:path")]);
    dataDir = resolve(dataDir);
    mkdirSync(dirname(dataDir), { recursive: true });
    if (/[\\/]OneDrive[\\/]|[\\/]Dropbox[\\/]|[\\/]iCloud/i.test(dataDir))
      console.warn(`[db] ${dataDir} is inside a cloud-synced folder. File syncing can corrupt the embedded database; set PGLITE_DIR to a local, unsynced folder.`);
  }
  let pg: InstanceType<typeof PGlite>;
  try {
    pg = new PGlite(dataDir);
    await pg.waitReady;
  } catch (e) {
    // PGlite aborts with an opaque WASM error on a damaged data directory
    const where = dataDir ?? "memory";
    console.error(`[db] Could not open the embedded database at ${where}:`, e);
    throw new HttpError(503, `The embedded database at ${where} could not be opened and is probably damaged (copied while the app was running, or modified by file sync). Stop the app, delete that folder and start again — the demo data is regenerated automatically.`);
  }
  const query = async <T,>(text: string, params?: unknown[]) => (await pg.query<T>(text, params)).rows;
  return {
    driver: "pglite",
    query,
    tx: (fn) => pg.transaction((t) => fn(async <T,>(text: string, params?: unknown[]) => (await t.query<T>(text, params)).rows)),
    close: () => pg.close(),
  };
}

async function postgres(url: string): Promise<Db> {
  const { default: pg } = await import("pg");
  // int8 → number (ids/counters we store stay well below 2^53)
  pg.types.setTypeParser(20, (v: string) => Number(v));
  const pool = new pg.Pool({ connectionString: url, max: Number(process.env.DATABASE_POOL_MAX ?? 10) });
  const query = async <T,>(text: string, params?: unknown[]) => (await pool.query(text, params as unknown[])).rows as T[];
  return {
    driver: "postgres",
    query,
    tx: async (fn) => {
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        const r = await fn(async <T,>(text: string, params?: unknown[]) => (await c.query(text, params as unknown[])).rows as T[]);
        await c.query("COMMIT");
        return r;
      } catch (e) {
        await c.query("ROLLBACK");
        throw e;
      } finally {
        c.release();
      }
    },
    close: () => pool.end(),
  };
}

export async function migrate(db: Db) {
  await db.query(`CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
  const done = new Set((await db.query<{ version: number }>(`SELECT version FROM schema_migrations`)).map((r) => r.version));
  for (const m of MIGRATIONS) {
    if (done.has(m.version)) continue;
    await db.tx(async (q) => {
      for (const stmt of m.sql.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean)) await q(stmt);
      await q(`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, [m.version, m.name]);
    });
  }
}

export async function openDb(): Promise<Db> {
  const db = process.env.DATABASE_URL
    ? await postgres(process.env.DATABASE_URL)
    : await pglite(process.env.SENTINEL_DB === "memory" ? undefined : (process.env.PGLITE_DIR ?? ".data/pglite"));
  await migrate(db);
  return db;
}

const g = globalThis as unknown as { __sentinelDb?: Promise<Db> };
/** Process-wide database handle (migrated, and seeded with the demo tenant on first boot). */
export function db(): Promise<Db> {
  return (g.__sentinelDb ??= openDb().then(async (d) => {
    const { seed } = await import("./seed.ts");
    await seed(d);
    return d;
  }).catch((e) => { g.__sentinelDb = undefined; throw e; }));
}
