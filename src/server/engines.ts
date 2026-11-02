/** Tenant → engine registry (process-wide; survives Next.js dev reloads via globalThis). */
import { db } from "./db/index.ts";
import { Engine } from "./engine.ts";
import { HttpError } from "./errors.ts";
import { getOrg } from "./repo.ts";

const g = globalThis as unknown as { __sxEngines?: Map<string, Promise<Engine>>; __sxShutdown?: boolean };
const engines = (g.__sxEngines ??= new Map());

export function getEngine(orgId: string): Promise<Engine> {
  let p = engines.get(orgId);
  if (!p) {
    p = (async () => {
      const d = await db();
      const org = await getOrg(d, orgId);
      if (!org) throw new HttpError(404, "Organization not found");
      return Engine.create(d, org);
    })();
    p.catch(() => engines.delete(orgId));
    engines.set(orgId, p);
  }
  return p;
}

/** Flush write-behind buffers before the process exits. */
if (!g.__sxShutdown && typeof process !== "undefined" && typeof process.once === "function") {
  g.__sxShutdown = true;
  const shutdown = async (sig: string) => {
    const all = await Promise.allSettled([...engines.values()]);
    await Promise.allSettled(all.map((r) => (r.status === "fulfilled" ? r.value.stop() : null)));
    if (sig !== "beforeExit") process.exit(0);
  };
  process.once("SIGTERM", () => void shutdown("SIGTERM"));
  process.once("SIGINT", () => void shutdown("SIGINT"));
}
