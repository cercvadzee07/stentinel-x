/** Boot a demo engine without a database and print what the correlator produced. `npm run engine:report` */
import { Engine } from "../../src/server/engine.ts";

const t0 = performance.now();
const e = await Engine.create(null, { id: "report", demo: true, settings: {} }, { start: false });
console.log("boot ms", Math.round(performance.now() - t0), "events", e.events.length, "ingest errors", e.ingestErrors.length);
const by: Record<string, number> = {};
for (const a of e.alerts) by[a.ruleName] = (by[a.ruleName] ?? 0) + 1;
console.table(by);
for (const a of e.alerts.slice(0, 25))
  console.log(a.ruleName.padEnd(26), "<-", [...new Set(a.eventIds.map((id: string) => e.byId.get(id)?.scenario ?? "background"))].join(", "));
const q = e.query({ q: "destination.port:22 AND event.outcome:failure", size: 5 });
console.log("sample query hits", q.total, "in", q.tookMs, "ms");
console.log("incidents", e.incidents.map((i) => `${i.id} ${i.title} (${i.alertIds.length} alerts, ${i.timeline.length} timeline entries)`));
