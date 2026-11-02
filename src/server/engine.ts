/**
 * SENTINEL X engine — one instance per organization (tenant).
 *
 *   raw → normalize() → hot store (ring buffer + id index) → metrics → correlator → alerts → bus (SSE)
 *                                    └──────────── write-behind (2s batches) ────────────► PostgreSQL
 *
 * The hot store serves live views and queries; the database is the system of
 * record. On boot an engine rehydrates rules, alerts, incidents and the most
 * recent events from the database.
 */
import { compile } from "../lib/sxql.ts";
import { readField } from "../lib/fields.ts";
import {
  SEVERITIES, severityRank,
  type Alert, type AlertStatus, type DetectionRule, type Incident, type IncidentStatus, type MetricsSnapshot,
  type SecurityEvent, type Severity, type SimulatorState, type StreamPayload, type TimelineEntry,
} from "../lib/types.ts";
import { DEFAULT_RULES, RuleRuntime, backtest, type Detection } from "./correlator.ts";
import type { Db } from "./db/index.ts";
import { ACTOR_BY_IP, ANALYSTS } from "./inventory.ts";
import { normalize, type HostResolver, type RawEnvelope } from "./normalize.ts";
import { listAssets, loadEngineState, persistBatch, pruneEvents, purgeEngineData, updateOrgSettings, type AssetRecord, type Org } from "./repo.ts";
import { SCENARIOS, SCENARIO_BY_ID, backgroundEvent, type ScenarioDef } from "./simulator.ts";
import { SAMPLE_INTERVAL_MS, Telemetry } from "./telemetry.ts";

export const CAPACITY = 80_000;
const DB_RETENTION = 500_000;
const TICK_MS = 250;
const FLUSH_MS = 2000;
const ALERT_MERGE_MS = 5 * 60_000;
const MINUTES = 60;

type Listener = (p: StreamPayload) => void;
interface RunningScenario { def: ScenarioDef; ctx: Record<string, any>; startedAt: number; carry: number }

const zeroSev = (): Record<Severity, number> => ({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });
const inc = (m: Map<string, number>, k: string | null | undefined, by = 1) => { if (k) m.set(k, (m.get(k) ?? 0) + by); };
const top = (m: Map<string, number>, n = 8) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, value]) => ({ key, value }));
const uid = (p: string) => `${p}-${Date.now().toString(36).slice(-5).toUpperCase()}${Math.random().toString(36).slice(2, 5).toUpperCase()}`;

export class Engine {
  readonly orgId: string;
  readonly db: Db | null;
  readonly demo: boolean;

  events: SecurityEvent[] = [];
  byId = new Map<string, SecurityEvent>();
  rules: DetectionRule[] = [];
  runtimes = new Map<string, RuleRuntime>();
  alerts: Alert[] = [];
  incidents: Incident[] = [];
  ingestErrors: { at: number; error: string }[] = [];

  // tenant asset inventory (enrichment + device metrics)
  assets: AssetRecord[] = [];
  assetByIp = new Map<string, AssetRecord>();
  resolver: HostResolver = { hostOf: (ip) => this.assetByIp.get(ip)?.hostname ?? null, ipOf: (h) => this.assets.find((a) => a.hostname === h)?.ip ?? null };

  // metrics
  perSecond = new Map<number, number>();
  minutes = new Map<number, { sev: Record<Severity, number>; inbound: number; outbound: number; internal: number }>();
  eventsToday = 0;
  failedAuth = 0;
  blocked = 0;
  bytesTotal = 0;
  sevDist = zeroSev();
  cats = new Map<string, number>();
  srcs = new Map<string, number>();
  dsts = new Map<string, number>();
  ports = new Map<string, number>();
  assetsHit = new Map<string, number>();
  geo = new Map<string, number>();
  suspicious = new Set<string>();
  dayStart = new Date().setHours(0, 0, 0, 0);

  // network telemetry (simulated for demo tenants; null = no telemetry source connected)
  telemetry: Telemetry | null = null;
  ipBytes = new Map<string, number>();
  externalBytes = 0;
  lastTelemetry = 0;

  // simulator
  sim: SimulatorState = { running: false, rate: 35, autoScenarios: false, activeScenarios: [], generated: 0 };
  running: RunningScenario[] = [];
  carry = 0;
  nextAuto = Date.now() + 15_000;
  timers: ReturnType<typeof setInterval>[] = [];

  // stream
  listeners = new Set<Listener>();
  pendingEvents: SecurityEvent[] = [];
  pendingAlerts = new Map<string, Alert>();
  snapCache: { at: number; snap: MetricsSnapshot } | null = null;

  // persistence (write-behind)
  dirty = { events: [] as SecurityEvent[], alerts: new Set<Alert>(), incidents: new Set<Incident>(), rules: new Set<DetectionRule>(), deletedRules: new Set<string>() };
  flushing: Promise<void> | null = null;
  persistErrors = 0;

  constructor(orgId: string, db: Db | null, demo: boolean) {
    this.orgId = orgId;
    this.db = db;
    this.demo = demo;
  }

  /** Boot an engine for a tenant: load inventory and state, seed defaults, start loops. */
  static async create(db: Db | null, org: Pick<Org, "id" | "demo" | "settings">, opts: { start?: boolean } = {}) {
    const e = new Engine(org.id, db, org.demo);
    const s = org.settings.simulator;
    if (s) Object.assign(e.sim, { running: s.running, rate: s.rate, autoScenarios: s.autoScenarios });
    if (db) {
      e.setAssets(await listAssets(db, org.id));
      const st = await loadEngineState(db, org.id, CAPACITY);
      e.loadRules(st.rules.length ? st.rules : DEFAULT_RULES.map((r) => ({ ...r })));
      if (!st.rules.length) e.rules.forEach((r) => e.dirty.rules.add(r));
      e.alerts = st.alerts;
      e.incidents = st.incidents;
      for (const ev of st.events) { e.events.push(ev); e.byId.set(ev.id, ev); e.account(ev); }
      for (const a of e.alerts) if (ACTOR_BY_IP.has(a.sourceIp ?? "")) e.suspicious.add(a.sourceIp!);
      e.ipBytes = new Map();
      e.externalBytes = 0;
      if (!st.events.length && org.demo) e.backfill(30 * 60_000);
    } else {
      e.loadRules(DEFAULT_RULES.map((r) => ({ ...r })));
      if (org.demo) e.backfill(30 * 60_000);
    }
    if (opts.start !== false) e.start();
    return e;
  }

  setAssets(list: AssetRecord[]) {
    this.assets = list;
    this.assetByIp = new Map(list.map((a) => [a.ip, a]));
    this.snapCache = null;
    if (this.demo) {
      if (this.telemetry) this.telemetry.rebuild(list);
      else this.telemetry = new Telemetry(list);
    }
  }

  private hostname(ip: string | null | undefined) {
    return ip ? this.assetByIp.get(ip)?.hostname ?? null : null;
  }

  // ── pipeline ─────────────────────────────────────────────────────────
  ingest(env: RawEnvelope): SecurityEvent | null {
    let e: SecurityEvent;
    try {
      e = normalize(env, this.resolver);
    } catch (err) {
      this.ingestErrors.unshift({ at: Date.now(), error: (err as Error).message });
      this.ingestErrors.length = Math.min(this.ingestErrors.length, 50);
      return null;
    }
    this.store(e);
    this.account(e);
    for (const rt of this.runtimes.values()) {
      if (!rt.rule.enabled) continue;
      const d = rt.push(e);
      if (d) this.raise(d);
    }
    return e;
  }

  private store(e: SecurityEvent) {
    // keep chronological order even for late-arriving events (REST ingest with old timestamps)
    if (this.events.length && e.timestamp < this.events[this.events.length - 1].timestamp) {
      let lo = 0, hi = this.events.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (this.events[mid].timestamp <= e.timestamp) lo = mid + 1; else hi = mid; }
      this.events.splice(lo, 0, e);
    } else this.events.push(e);
    this.byId.set(e.id, e);
    if (this.events.length > CAPACITY) {
      const evicted = this.events.splice(0, this.events.length - CAPACITY);
      for (const x of evicted) this.byId.delete(x.id);
    }
    this.pendingEvents.push(e);
    if (this.pendingEvents.length > 400) this.pendingEvents.splice(0, this.pendingEvents.length - 400);
    if (this.db) this.dirty.events.push(e);
  }

  private account(e: SecurityEvent) {
    const sec = Math.floor(e.timestamp / 1000);
    this.perSecond.set(sec, (this.perSecond.get(sec) ?? 0) + 1);
    const min = Math.floor(e.timestamp / 60_000);
    let m = this.minutes.get(min);
    if (!m) this.minutes.set(min, (m = { sev: zeroSev(), inbound: 0, outbound: 0, internal: 0 }));
    m.sev[e.severity]++;
    m[e.direction] += e.bytes;
    if (e.timestamp >= this.dayStart) this.eventsToday++;
    if (e.outcome === "failure" && e.category === "authentication") this.failedAuth++;
    if (e.action === "deny" || e.action === "drop" || e.action === "block") this.blocked++;
    this.bytesTotal += e.bytes;
    if (e.bytes) {
      this.ipBytes.set(e.sourceIp, (this.ipBytes.get(e.sourceIp) ?? 0) + e.bytes);
      this.ipBytes.set(e.destinationIp, (this.ipBytes.get(e.destinationIp) ?? 0) + e.bytes);
      if (e.direction !== "internal") this.externalBytes += e.bytes;
    }
    this.sevDist[e.severity]++;
    inc(this.cats, e.category);
    inc(this.srcs, e.sourceIp);
    inc(this.dsts, e.destinationIp);
    if (e.destinationPort != null) inc(this.ports, String(e.destinationPort));
    if (severityRank(e.severity) >= 2) inc(this.assetsHit, e.destinationHost ?? this.hostname(e.destinationIp));
    const actor = ACTOR_BY_IP.get(e.sourceIp);
    if (actor) {
      inc(this.geo, actor.code, e.count);
      if (severityRank(e.severity) >= 3 || e.action === "deny") this.suspicious.add(e.sourceIp);
    }
  }

  private raise(d: Detection) {
    const { rule, groupKey, trigger } = d;
    const live = this.alerts.find((a) => a.ruleId === rule.id && a.groupKey === groupKey &&
      a.status !== "resolved" && a.status !== "false_positive" && trigger.timestamp - a.lastSeen < ALERT_MERGE_MS);
    if (live) {
      if (live.suppressed) return;
      live.lastSeen = Math.max(live.lastSeen, trigger.timestamp);
      if (!live.eventIds.includes(trigger.id)) { live.eventIds.push(trigger.id); live.eventCount++; }
      if (live.eventIds.length > 300) live.eventIds.splice(0, live.eventIds.length - 300);
      this.pendingAlerts.set(live.id, live);
      this.dirty.alerts.add(live);
      return;
    }
    const target = trigger.destinationIp;
    const alert: Alert = {
      id: uid("ALR"),
      title: `${rule.name}: ${groupKey}`,
      severity: rule.severity,
      sourceIp: trigger.sourceIp,
      targetIp: target,
      asset: trigger.destinationHost ?? this.hostname(target) ?? trigger.sourceHost ?? null,
      ruleId: rule.id,
      ruleName: rule.name,
      groupKey,
      firstSeen: d.events[0].timestamp,
      lastSeen: trigger.timestamp,
      eventCount: d.events.length,
      mitre: rule.mitre,
      status: "new",
      assignee: null,
      suppressed: false,
      eventIds: d.events.slice(-300).map((x) => x.id),
      comments: [],
      history: [{ at: trigger.timestamp, actor: "correlation-engine", action: "created", detail: `${rule.logic.aggregate}=${d.value} ≥ ${rule.logic.threshold} in ${rule.logic.windowSec}s` }],
      incidentId: null,
    };
    rule.triggerCount++;
    rule.lastTriggered = trigger.timestamp;
    this.dirty.rules.add(rule);
    if (ACTOR_BY_IP.has(trigger.sourceIp)) this.suspicious.add(trigger.sourceIp);
    this.alerts.unshift(alert);
    if (this.alerts.length > 2000) this.alerts.length = 2000;
    this.pendingAlerts.set(alert.id, alert);
    this.dirty.alerts.add(alert);
  }

  // ── simulator ────────────────────────────────────────────────────────
  private generate(t: number, dtMs: number) {
    if (this.sim.running) {
      this.carry += (this.sim.rate * dtMs) / 1000;
      const n = Math.floor(this.carry);
      this.carry -= n;
      for (let i = 0; i < n; i++) { this.ingest(backgroundEvent(t - Math.floor(Math.random() * dtMs))); this.sim.generated++; }
    }
    for (const r of [...this.running]) {
      const elapsed = (t - r.startedAt) / 1000;
      if (elapsed > r.def.duration) { this.running.splice(this.running.indexOf(r), 1); continue; }
      r.carry += (r.def.rate * dtMs) / 1000;
      while (r.carry >= 1) {
        r.carry--;
        const out = r.def.make(t, elapsed / r.def.duration, r.ctx);
        for (const env of Array.isArray(out) ? out : [out]) { this.ingest(env); this.sim.generated++; }
      }
    }
  }

  launch(id: string, at = Date.now()) {
    const def = SCENARIO_BY_ID.get(id);
    if (!def) throw new Error(`Unknown scenario ${id}`);
    this.running.push({ def, ctx: def.init(), startedAt: at, carry: 1 });
  }

  private tick = () => {
    const t = Date.now();
    if (this.sim.running && this.sim.autoScenarios && t >= this.nextAuto) {
      this.launch(SCENARIOS[Math.floor(Math.random() * SCENARIOS.length)].id, t);
      this.nextAuto = t + 35_000 + Math.random() * 40_000;
    }
    this.generate(t, TICK_MS);
    if (t - this.lastTelemetry >= SAMPLE_INTERVAL_MS) this.sampleTelemetry(t);
    if (t % 10_000 < TICK_MS) this.housekeep(t);
  };

  private sampleTelemetry(t: number) {
    this.lastTelemetry = t;
    if (this.telemetry) this.telemetry.sample(t, this.ipBytes, this.externalBytes);
    this.ipBytes = new Map();
    this.externalBytes = 0;
  }

  private housekeep(t: number) {
    for (const rt of this.runtimes.values()) rt.sweep(t);
    const minSec = Math.floor(t / 1000) - 600;
    for (const k of this.perSecond.keys()) if (k < minSec) this.perSecond.delete(k);
    const minMin = Math.floor(t / 60_000) - MINUTES * 2;
    for (const k of this.minutes.keys()) if (k < minMin) this.minutes.delete(k);
    if (this.db && t % 600_000 < TICK_MS) pruneEvents(this.db, this.orgId, DB_RETENTION).catch(() => {});
  }

  /** Pre-populate history so dashboards and backtests have data on first boot of a demo tenant. */
  private backfill(spanMs: number) {
    const end = Date.now();
    const plan = new Map<number, string>();
    const ids = SCENARIOS.map((s) => s.id);
    ids.forEach((id, i) => plan.set(Math.floor(((i + 0.5) / ids.length) * (spanMs / TICK_MS)), id));
    const { rate, running } = this.sim;
    this.sim.rate = 14;
    this.sim.running = true;
    let step = 0;
    for (let t = end - spanMs; t < end; t += TICK_MS, step++) {
      const sc = plan.get(step);
      if (sc) this.launch(sc, t);
      this.generate(t, TICK_MS);
    }
    Object.assign(this.sim, { rate, running });
    // seed a realistic triage state on older alerts
    this.alerts.slice(4).forEach((a, i) => {
      if (i % 3 === 0) this.updateAlert(a.id, { status: "investigating", assignee: ANALYSTS[i % ANALYSTS.length] }, "system", a.lastSeen + 60_000);
      if (i % 5 === 1) this.updateAlert(a.id, { status: "resolved", assignee: ANALYSTS[(i + 2) % ANALYSTS.length] }, "system", a.lastSeen + 120_000);
    });
    const crit = this.alerts.filter((a) => severityRank(a.severity) >= 3).slice(-3);
    if (crit.length) this.createIncident({ title: "Coordinated external intrusion attempt", description: "Seeded demo incident grouping early high-severity detections.", alertIds: crit.map((a) => a.id), assignee: ANALYSTS[0] }, "system");
    this.pendingEvents = [];
    this.pendingAlerts.clear();
    // backfilled bytes are history, not current link load
    this.ipBytes = new Map();
    this.externalBytes = 0;
  }

  start() {
    if (this.timers.length) return;
    this.timers.push(setInterval(this.tick, TICK_MS), setInterval(() => this.flush(), 1000), setInterval(() => { void this.persist(); }, FLUSH_MS));
  }

  async stop() {
    this.timers.forEach(clearInterval);
    this.timers = [];
    await this.persist();
  }

  async reset() {
    this.events = []; this.byId.clear(); this.alerts = []; this.incidents = []; this.running = [];
    this.perSecond.clear(); this.minutes.clear(); this.cats.clear(); this.srcs.clear(); this.dsts.clear(); this.ports.clear();
    this.assetsHit.clear(); this.geo.clear(); this.suspicious.clear();
    this.eventsToday = this.failedAuth = this.blocked = this.bytesTotal = this.sim.generated = 0;
    this.sevDist = zeroSev();
    this.dirty = { events: [], alerts: new Set(), incidents: new Set(), rules: new Set(), deletedRules: new Set() };
    if (this.flushing) await this.flushing;
    if (this.db) await purgeEngineData(this.db, this.orgId);
    this.loadRules(DEFAULT_RULES.map((r) => ({ ...r, triggerCount: 0, lastTriggered: null })));
    this.rules.forEach((r) => this.dirty.rules.add(r));
    if (this.demo) this.backfill(30 * 60_000);
    this.snapCache = null;
  }

  setSimulator(p: Partial<Pick<SimulatorState, "running" | "rate" | "autoScenarios">>) {
    if (p.running !== undefined) this.sim.running = p.running;
    if (p.rate !== undefined) this.sim.rate = Math.max(1, Math.min(500, p.rate));
    if (p.autoScenarios !== undefined) this.sim.autoScenarios = p.autoScenarios;
    this.snapCache = null;
    if (this.db) void updateOrgSettings(this.db, this.orgId, { simulator: { running: this.sim.running, rate: this.sim.rate, autoScenarios: this.sim.autoScenarios } });
  }

  simState(): SimulatorState {
    const now = Date.now();
    return { ...this.sim, activeScenarios: this.running.filter((r) => r.startedAt <= now).map((r) => ({ id: r.def.id, name: r.def.name, endsAt: r.startedAt + r.def.duration * 1000 })) };
  }

  // ── persistence ──────────────────────────────────────────────────────
  /** Write dirty state to the database in one transaction. Failed batches are re-queued. */
  persist(): Promise<void> {
    if (!this.db) return Promise.resolve();
    if (this.flushing) return this.flushing;
    const d = this.dirty;
    if (!d.events.length && !d.alerts.size && !d.incidents.size && !d.rules.size && !d.deletedRules.size) return Promise.resolve();
    this.dirty = { events: [], alerts: new Set(), incidents: new Set(), rules: new Set(), deletedRules: new Set() };
    const batch = { events: d.events, alerts: [...d.alerts], incidents: [...d.incidents], rules: [...d.rules].filter((r) => this.rules.includes(r)), deletedRules: [...d.deletedRules] };
    this.flushing = persistBatch(this.db, this.orgId, batch)
      .then(() => { this.persistErrors = 0; })
      .catch((err) => {
        this.persistErrors++;
        console.error(`[engine ${this.orgId}] persist failed (${this.persistErrors})`, err);
        if (this.persistErrors < 5) {
          this.dirty.events.unshift(...batch.events.slice(-20_000));
          batch.alerts.forEach((a) => this.dirty.alerts.add(a));
          batch.incidents.forEach((i) => this.dirty.incidents.add(i));
          batch.rules.forEach((r) => this.dirty.rules.add(r));
          batch.deletedRules.forEach((id) => this.dirty.deletedRules.add(id));
        }
      })
      .finally(() => { this.flushing = null; });
    return this.flushing;
  }

  // ── stream ───────────────────────────────────────────────────────────
  subscribe(fn: Listener) {
    this.listeners.add(fn);
    return () => { this.listeners.delete(fn); };
  }

  private flush() {
    if (!this.listeners.size) { this.pendingEvents = []; this.pendingAlerts.clear(); return; }
    const payload: StreamPayload = { metrics: this.metrics(true), events: this.pendingEvents.slice(-120), alerts: [...this.pendingAlerts.values()] };
    this.pendingEvents = [];
    this.pendingAlerts.clear();
    for (const l of this.listeners) { try { l(payload); } catch { this.listeners.delete(l); } }
  }

  // ── metrics ──────────────────────────────────────────────────────────
  metrics(force = false): MetricsSnapshot {
    const now = Date.now();
    if (!force && this.snapCache && now - this.snapCache.at < 800) return this.snapCache.snap;
    const nowSec = Math.floor(now / 1000);
    const epsSeries = Array.from({ length: 120 }, (_, i) => { const s = nowSec - 120 + i; return { t: s * 1000, v: this.perSecond.get(s) ?? 0 }; });
    const last5 = epsSeries.slice(-6, -1);
    const nowMin = Math.floor(now / 60_000);
    const mins = Array.from({ length: MINUTES }, (_, i) => nowMin - MINUTES + 1 + i);
    const alertsBySeverity = zeroSev();
    let openAlerts = 0;
    for (const a of this.alerts) if (a.status !== "resolved" && a.status !== "false_positive" && !a.suppressed) { alertsBySeverity[a.severity]++; openAlerts++; }
    const monitored = this.assets.filter((x) => x.monitored);
    const online = monitored.filter((x) => x.online).length;
    const snap: MetricsSnapshot = {
      at: now,
      eps: Math.round(last5.reduce((s, x) => s + x.v, 0) / last5.length),
      epsSeries,
      eventsToday: this.eventsToday,
      alertsBySeverity,
      openAlerts,
      activeIncidents: this.incidents.filter((i) => i.status !== "resolved" && i.status !== "closed").length,
      devices: { total: monitored.length, online, offline: monitored.length - online },
      suspiciousIps: this.suspicious.size,
      failedAuth: this.failedAuth,
      blocked: this.blocked,
      bytesTotal: this.bytesTotal,
      timeline: mins.map((m) => ({ t: m * 60_000, ...(this.minutes.get(m)?.sev ?? zeroSev()) })),
      traffic: mins.map((m) => { const x = this.minutes.get(m); return { t: m * 60_000, inbound: x?.inbound ?? 0, outbound: x?.outbound ?? 0, internal: x?.internal ?? 0 }; }),
      severityDist: { ...this.sevDist },
      categories: top(this.cats, 8).map(({ key, value }) => ({ name: key, value })),
      topSources: top(this.srcs),
      topDestinations: top(this.dsts),
      topPorts: top(this.ports),
      topAssets: top(this.assetsHit),
      geo: [...this.geo.entries()].map(([code, value]) => {
        const a = [...ACTOR_BY_IP.values()].find((x) => x.code === code)!;
        return { country: a.country, code, lat: a.lat, lon: a.lon, value };
      }).sort((a, b) => b.value - a.value),
      simulator: this.simState(),
    };
    this.snapCache = { at: now, snap };
    return snap;
  }

  // ── queries ──────────────────────────────────────────────────────────
  query(opts: { q?: string; from?: number; to?: number; sort?: string; dir?: "asc" | "desc"; page?: number; size?: number; buckets?: number }) {
    const t0 = performance.now();
    const pred = compile(opts.q ?? "");
    const from = opts.from ?? 0, to = opts.to ?? Infinity;
    const matched: SecurityEvent[] = [];
    for (let i = this.events.length - 1; i >= 0; i--) {
      const e = this.events[i];
      if (e.timestamp > to) continue;
      if (e.timestamp < from) break;
      if (pred(e)) matched.push(e);
    }
    if (opts.sort && opts.sort !== "@timestamp") {
      const dir = opts.dir === "asc" ? 1 : -1;
      const sev = opts.sort === "event.severity";
      matched.sort((a, b) => {
        const x = readField(a, opts.sort!), y = readField(b, opts.sort!);
        if (sev) return (severityRank(x as Severity) - severityRank(y as Severity)) * dir;
        if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
        return String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true }) * dir;
      });
    } else if (opts.dir === "asc") matched.reverse();

    // histogram across the effective time range
    const nb = opts.buckets ?? 60;
    const hFrom = Number.isFinite(from) && from > 0 ? from : (this.events[0]?.timestamp ?? Date.now());
    const hTo = Number.isFinite(to) ? Math.min(to, Date.now()) : Date.now();
    const width = Math.max(1000, (hTo - hFrom) / nb);
    const histogram = Array.from({ length: nb }, (_, i) => ({ t: hFrom + i * width, ...zeroSev() }));
    const facets = { type: new Map<string, number>(), severity: new Map<string, number>(), protocol: new Map<string, number>(), source: new Map<string, number>(), port: new Map<string, number>() };
    for (const e of matched) {
      const b = Math.min(nb - 1, Math.floor((e.timestamp - hFrom) / width));
      if (b >= 0) histogram[b][e.severity]++;
      inc(facets.type, e.type); inc(facets.severity, e.severity); inc(facets.protocol, e.protocol); inc(facets.source, e.sourceIp);
      if (e.destinationPort != null) inc(facets.port, String(e.destinationPort));
    }
    const size = Math.min(500, Math.max(1, opts.size ?? 50));
    const page = Math.max(1, opts.page ?? 1);
    return {
      total: matched.length,
      scanned: this.events.length,
      page, size,
      items: matched.slice((page - 1) * size, page * size),
      all: matched,
      histogram, bucketMs: width,
      facets: Object.fromEntries(Object.entries(facets).map(([k, m]) => [k, top(m, 8)])),
      tookMs: Math.round((performance.now() - t0) * 100) / 100,
    };
  }

  related(e: SecurityEvent, limit = 50) {
    const lo = e.timestamp - 10 * 60_000, hi = e.timestamp + 10 * 60_000;
    const out: SecurityEvent[] = [];
    for (let i = this.events.length - 1; i >= 0 && out.length < limit; i--) {
      const x = this.events[i];
      if (x.timestamp > hi || x.id === e.id) continue;
      if (x.timestamp < lo) break;
      if (x.sourceIp === e.sourceIp || (x.destinationIp === e.destinationIp && x.type === e.type)) out.push(x);
    }
    return out;
  }

  /** Per-IP activity summary for asset investigation. */
  assetActivity(ip: string) {
    let asSource = 0, asTarget = 0, highSev = 0;
    const types = new Map<string, number>();
    let lastSeen = 0;
    for (const e of this.events) {
      const src = e.sourceIp === ip, dst = e.destinationIp === ip;
      if (!src && !dst) continue;
      if (src) asSource++;
      if (dst) asTarget++;
      if (severityRank(e.severity) >= 3) highSev++;
      inc(types, e.type);
      lastSeen = Math.max(lastSeen, e.timestamp);
    }
    const alerts = this.alerts.filter((a) => a.sourceIp === ip || a.targetIp === ip).slice(0, 50);
    return { asSource, asTarget, highSev, lastSeen: lastSeen || null, types: top(types, 8), alerts };
  }

  // ── rules ────────────────────────────────────────────────────────────
  loadRules(rules: DetectionRule[]) {
    this.rules = rules;
    this.runtimes = new Map(rules.map((r) => [r.id, new RuleRuntime(r)]));
  }

  upsertRule(rule: DetectionRule) {
    const rt = new RuleRuntime(rule); // throws on invalid SXQL
    const i = this.rules.findIndex((r) => r.id === rule.id);
    if (i >= 0) this.rules[i] = rule; else this.rules.push(rule);
    this.runtimes.set(rule.id, rt);
    this.dirty.rules.add(rule);
    return rule;
  }

  deleteRule(id: string) {
    this.rules = this.rules.filter((r) => r.id !== id);
    this.runtimes.delete(id);
    this.dirty.deletedRules.add(id);
  }

  testRule(rule: DetectionRule, windowMs?: number) {
    const from = windowMs ? Date.now() - windowMs : 0;
    const events = from ? this.events.filter((e) => e.timestamp >= from) : this.events;
    return backtest(rule, events);
  }

  // ── alerts ───────────────────────────────────────────────────────────
  updateAlert(id: string, patch: { status?: AlertStatus; assignee?: string | null; severity?: Severity; suppressed?: boolean; comment?: string }, actor: string, at = Date.now()) {
    const a = this.alerts.find((x) => x.id === id);
    if (!a) return null;
    const log = (action: string, detail?: string) => a.history.push({ at, actor, action, detail });
    if (patch.status && patch.status !== a.status) { log("status", `${a.status} → ${patch.status}`); a.status = patch.status; }
    if (patch.assignee !== undefined && patch.assignee !== a.assignee) { log("assigned", patch.assignee ?? "unassigned"); a.assignee = patch.assignee; }
    if (patch.severity && patch.severity !== a.severity) { log("severity", `${a.severity} → ${patch.severity}`); a.severity = patch.severity; }
    if (patch.suppressed !== undefined && patch.suppressed !== a.suppressed) { log(patch.suppressed ? "suppressed" : "unsuppressed"); a.suppressed = patch.suppressed; }
    if (patch.comment?.trim()) { a.comments.push({ id: uid("CMT"), at, author: actor, text: patch.comment.trim() }); log("comment"); }
    this.pendingAlerts.set(a.id, a);
    this.dirty.alerts.add(a);
    this.snapCache = null;
    return a;
  }

  // ── incidents ────────────────────────────────────────────────────────
  private nextIncidentId() {
    const max = this.incidents.reduce((m, i) => Math.max(m, Number(i.id.split("-")[1]) || 0), 1000);
    return `INC-${max + 1}`;
  }

  createIncident(p: { title: string; description: string; alertIds: string[]; assignee?: string | null; severity?: Severity }, actor: string) {
    const alerts = this.alerts.filter((a) => p.alertIds.includes(a.id));
    const now = Date.now();
    const severity = p.severity ?? (alerts.length ? SEVERITIES[Math.max(...alerts.map((a) => severityRank(a.severity)))] : "medium");
    const inc0: Incident = {
      id: this.nextIncidentId(),
      title: p.title, description: p.description, severity, status: "open", assignee: p.assignee ?? null,
      alertIds: alerts.map((a) => a.id),
      assets: [...new Set(alerts.map((a) => a.asset).filter(Boolean) as string[])],
      sourceIps: [...new Set(alerts.map((a) => a.sourceIp).filter(Boolean) as string[])],
      timeline: [], notes: [], history: [{ at: now, actor, action: "created" }], resolution: null, createdAt: now, updatedAt: now,
    };
    for (const a of alerts) {
      a.incidentId = inc0.id;
      if (a.status === "new") { a.status = "escalated"; a.history.push({ at: now, actor, action: "status", detail: `new → escalated (${inc0.id})` }); }
      this.dirty.alerts.add(a);
      this.pendingAlerts.set(a.id, a);
    }
    this.incidents.unshift(inc0);
    this.rebuildTimeline(inc0);
    this.dirty.incidents.add(inc0);
    this.snapCache = null;
    return inc0;
  }

  rebuildTimeline(inc0: Incident) {
    const tl: TimelineEntry[] = [{ at: inc0.createdAt, kind: "created", title: "Incident opened" }];
    for (const a of this.alerts.filter((x) => inc0.alertIds.includes(x.id))) {
      tl.push({ at: a.firstSeen, kind: "alert", title: a.title, severity: a.severity, detail: `${a.ruleName} · ${a.eventCount} events · ${a.mitre.join(", ")}`, ref: a.id });
      const evs = a.eventIds.map((id) => this.byId.get(id)).filter(Boolean) as SecurityEvent[];
      const first = evs[0], last = evs[evs.length - 1];
      if (first) tl.push({ at: first.timestamp, kind: "event", title: `First event: ${first.message || first.type}`, severity: first.severity, detail: `${first.sourceIp} → ${first.destinationIp}:${first.destinationPort ?? "-"}`, ref: first.id });
      if (last && last !== first) tl.push({ at: last.timestamp, kind: "event", title: `Latest event: ${last.message || last.type}`, severity: last.severity, detail: `${last.sourceIp} → ${last.destinationIp}:${last.destinationPort ?? "-"}`, ref: last.id });
      // highlight a compromise signal: successful auth from the attacking source
      const win = this.events.find((e) => e.sourceIp === a.sourceIp && e.outcome === "success" && e.category === "authentication" && e.timestamp >= a.firstSeen);
      if (win) tl.push({ at: win.timestamp, kind: "event", title: `Successful login from attacker ${win.sourceIp} as ${win.username}`, severity: "critical", detail: win.message, ref: win.id });
    }
    for (const n of inc0.notes) tl.push({ at: n.at, kind: "note", title: `${n.author}: note`, detail: n.text });
    for (const h of inc0.history) if (h.action === "status") tl.push({ at: h.at, kind: "status", title: `Status ${h.detail}`, detail: h.actor });
    // keep entries already recorded whose events have aged out of the hot store
    const kept = inc0.timeline.filter((x) => x.kind === "event" && x.ref && !this.byId.has(x.ref));
    inc0.timeline = [...tl, ...kept].sort((a, b) => a.at - b.at);
  }

  updateIncident(id: string, patch: { status?: IncidentStatus; assignee?: string | null; note?: string; resolution?: string; addAlertIds?: string[]; severity?: Severity }, actor: string) {
    const i = this.incidents.find((x) => x.id === id);
    if (!i) return null;
    const now = Date.now();
    if (patch.status && patch.status !== i.status) { i.history.push({ at: now, actor, action: "status", detail: `${i.status} → ${patch.status}` }); i.status = patch.status; }
    if (patch.assignee !== undefined && patch.assignee !== i.assignee) { i.history.push({ at: now, actor, action: "assigned", detail: patch.assignee ?? "unassigned" }); i.assignee = patch.assignee; }
    if (patch.severity && patch.severity !== i.severity) { i.history.push({ at: now, actor, action: "severity", detail: `${i.severity} → ${patch.severity}` }); i.severity = patch.severity; }
    if (patch.note?.trim()) i.notes.push({ id: uid("NOTE"), at: now, author: actor, text: patch.note.trim() });
    if (patch.resolution !== undefined) { i.resolution = patch.resolution; i.history.push({ at: now, actor, action: "resolution" }); }
    if (patch.addAlertIds?.length) {
      for (const a of this.alerts.filter((x) => patch.addAlertIds!.includes(x.id) && !i.alertIds.includes(x.id))) { i.alertIds.push(a.id); a.incidentId = i.id; this.dirty.alerts.add(a); }
      const alerts = this.alerts.filter((a) => i.alertIds.includes(a.id));
      i.assets = [...new Set(alerts.map((a) => a.asset).filter(Boolean) as string[])];
      i.sourceIps = [...new Set(alerts.map((a) => a.sourceIp).filter(Boolean) as string[])];
    }
    i.updatedAt = now;
    this.rebuildTimeline(i);
    this.dirty.incidents.add(i);
    this.snapCache = null;
    return i;
  }
}
