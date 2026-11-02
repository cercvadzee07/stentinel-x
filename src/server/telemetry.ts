/**
 * Network monitoring model.
 *
 * Topology is inferred from the tenant's asset inventory (device types and locations).
 * Device telemetry (CPU, memory, latency, loss, interface counters) is SIMULATED for demo
 * tenants: link throughput is derived from the flow bytes actually passing through the
 * event pipeline, so attack scenarios (DDoS, exfiltration) visibly load the links.
 * Tenants without a telemetry integration get the topology with telemetry = null.
 */
import type { AssetRecord } from "./repo.ts";

export type NodeRole = "internet" | "edge" | "core" | "distribution" | "access" | "server" | "endpoints";

export interface NetNode {
  id: string;
  label: string;
  role: NodeRole;
  tier: number;
  type: string;
  ip: string | null;
  location: string | null;
  /** asset ids represented by this node (several for an endpoint group) */
  assetIds: string[];
  memberIps: string[];
}

export interface NetLink { id: string; a: string; b: string; aIf: string; bIf: string; speedMbps: number }

export interface IfaceStat {
  name: string; peer: string; speedMbps: number; status: "up" | "down";
  inBps: number; outBps: number; util: number; errors: number; discards: number;
}

export interface Sample { t: number; cpu: number; mem: number; latencyMs: number; lossPct: number; inBps: number; outBps: number; up: boolean }

export interface DeviceTelemetry {
  nodeId: string;
  status: "up" | "degraded" | "down";
  cpu: number; mem: number; latencyMs: number; lossPct: number;
  inBps: number; outBps: number; util: number;
  uptimeSec: number;
  interfaces: IfaceStat[];
  history: Sample[];
  /** per-minute availability (fraction of samples up), oldest first */
  availability: { t: number; up: number }[];
  fault: string | null;
}

const NET_TYPES = new Set(["firewall", "router", "switch"]);
const SAMPLE_MS = 5000;
const HISTORY = 360; // 30 minutes at 5 s
/** Each flow event stands for sampled traffic; scale bytes up to link-level throughput. */
export const FLOW_SCALE = 20;

export function buildTopology(assets: AssetRecord[]): { nodes: NetNode[]; links: NetLink[] } {
  const nodes: NetNode[] = [];
  const links: NetLink[] = [];
  const add = (n: Omit<NetNode, "memberIps" | "assetIds"> & { assets?: AssetRecord[] }) => {
    const { assets: members = [], ...rest } = n;
    const node = { ...rest, assetIds: members.map((a) => a.id), memberIps: members.map((a) => a.ip) };
    nodes.push(node);
    return node;
  };
  const link = (a: NetNode, b: NetNode, aIf: string, bIf: string, speedMbps: number) =>
    links.push({ id: `${a.id}~${b.id}`, a: a.id, b: b.id, aIf, bIf, speedMbps });
  const asNode = (a: AssetRecord, role: NodeRole, tier: number) =>
    add({ id: a.id, label: a.hostname, role, tier, type: a.type, ip: a.ip, location: a.location, assets: [a] });

  const monitored = assets.filter((a) => a.monitored);
  const firewalls = monitored.filter((a) => a.type === "firewall");
  const routers = monitored.filter((a) => a.type === "router");
  const switches = monitored.filter((a) => a.type === "switch");
  const coreSw = switches.filter((s) => /core/i.test(s.hostname));
  const core = coreSw.length ? coreSw : switches.slice(0, 1);
  const access = switches.filter((s) => !core.includes(s));
  const servers = monitored.filter((a) => !NET_TYPES.has(a.type) && a.type !== "workstation");
  const workstations = monitored.filter((a) => a.type === "workstation");

  const internet = add({ id: "internet", label: "Internet", role: "internet", tier: 0, type: "cloud", ip: null, location: null });
  const fwNodes = firewalls.map((f) => asNode(f, "edge", 1));
  const rtNodes = routers.map((r) => asNode(r, "core", 2));
  const coreNodes = core.map((s) => asNode(s, "distribution", 3));
  const accNodes = access.map((s) => asNode(s, "access", 4));
  const srvNodes = servers.map((s) => asNode(s, "server", 4));

  fwNodes.forEach((f, i) => link(internet, f, "isp", i === 0 ? "ethernet1/1" : "wan1", 1000));
  const below = rtNodes[0] ?? coreNodes[0];
  if (below) fwNodes.forEach((f) => link(f, below, f.id === fwNodes[0]?.id ? "ethernet1/2" : "port2", `ge-0/0/${fwNodes.indexOf(f)}`, 10_000));
  rtNodes.forEach((r) => coreNodes.forEach((c, i) => link(r, c, `te-1/0/${i}`, "Ethernet49", 10_000)));
  const agg = coreNodes[0] ?? rtNodes[0] ?? fwNodes[0];
  if (agg) accNodes.forEach((s, i) => link(agg, s, `Ethernet${i + 1}`, "Gi1/0/48", 10_000));
  srvNodes.forEach((s, i) => {
    const up = s.location === "DMZ" && fwNodes[0] ? fwNodes[0] : agg;
    if (up) link(up, s, up.role === "edge" ? `ethernet1/${3 + (i % 6)}` : `Ethernet${10 + i}`, "eth0", 1000);
  });

  // endpoints grouped by location, attached to the access switch in that location
  const byLoc = new Map<string, AssetRecord[]>();
  for (const w of workstations) byLoc.set(w.location ?? "unknown", [...(byLoc.get(w.location ?? "unknown") ?? []), w]);
  [...byLoc.entries()].forEach(([loc, ws], i) => {
    const g = add({ id: `endpoints:${loc}`, label: `${loc} endpoints (${ws.length})`, role: "endpoints", tier: 5, type: "workstation", ip: null, location: loc, assets: ws });
    const sw = accNodes.find((s) => s.location === loc) ?? accNodes[i % Math.max(1, accNodes.length)] ?? agg;
    if (sw) link(sw, g, `Gi1/0/${1 + i}-${ws.length}`, "access", 1000);
  });
  return { nodes, links };
}

const BASE: Record<string, { cpu: number; mem: number; lat: number }> = {
  firewall: { cpu: 22, mem: 48, lat: 1.8 }, router: { cpu: 14, mem: 35, lat: 0.9 }, switch: { cpu: 9, mem: 28, lat: 0.3 },
  database: { cpu: 34, mem: 71, lat: 0.6 }, domain_controller: { cpu: 18, mem: 52, lat: 0.5 }, web: { cpu: 26, mem: 44, lat: 0.5 },
  workstation: { cpu: 12, mem: 55, lat: 0.4 },
};
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));
const jitter = (v: number, pct: number) => v * (1 + (Math.random() * 2 - 1) * pct);

export class Telemetry {
  nodes: NetNode[] = [];
  links: NetLink[] = [];
  devices = new Map<string, DeviceTelemetry>();
  linkStat = new Map<string, { bps: number; util: number }>();
  aggregate: { t: number; inBps: number; outBps: number }[] = [];
  private assets: AssetRecord[] = [];
  private lastSample = 0;
  private faults = new Map<string, { kind: string; until: number }>();
  private nextFault = Date.now() + 90_000;

  constructor(assets: AssetRecord[]) {
    this.rebuild(assets);
  }

  rebuild(assets: AssetRecord[]) {
    this.assets = assets;
    const topo = buildTopology(assets);
    this.nodes = topo.nodes;
    this.links = topo.links;
    for (const n of this.nodes) {
      if (n.role === "internet" || this.devices.has(n.id)) continue;
      const b = BASE[n.type] ?? { cpu: 20, mem: 45, lat: 0.7 };
      this.devices.set(n.id, {
        nodeId: n.id, status: "up", cpu: b.cpu, mem: b.mem, latencyMs: b.lat, lossPct: 0, inBps: 0, outBps: 0, util: 0,
        uptimeSec: Math.floor(86_400 * (3 + Math.random() * 120)), interfaces: [], history: [], availability: [], fault: null,
      });
    }
    for (const id of this.devices.keys()) if (!this.nodes.some((n) => n.id === id)) this.devices.delete(id);
  }

  /**
   * Take one sample. `ipBytes` = bytes per IP seen in events since the last sample,
   * `externalBytes` = bytes of inbound+outbound (non-internal) events.
   */
  sample(now: number, ipBytes: Map<string, number>, externalBytes: number) {
    const dt = this.lastSample ? Math.max(1, (now - this.lastSample) / 1000) : SAMPLE_MS / 1000;
    this.lastSample = now;
    const bps = (bytes: number) => (bytes * 8 * FLOW_SCALE) / dt;
    const online = new Map(this.assets.map((a) => [a.id, a.online]));

    // occasional injected faults so the NOC view has something to diagnose (simulated)
    if (now > this.nextFault) {
      const candidates = this.nodes.filter((n) => n.role !== "internet" && n.role !== "endpoints");
      const n = candidates[Math.floor(Math.random() * candidates.length)];
      if (n) this.faults.set(n.id, { kind: Math.random() < 0.5 ? "latency" : "packet-loss", until: now + 60_000 });
      this.nextFault = now + 150_000 + Math.random() * 150_000;
    }

    // traffic per link: leaf links carry their members' bytes; uplinks carry everything beneath
    const nodeBytes = new Map<string, number>();
    for (const n of this.nodes) nodeBytes.set(n.id, n.memberIps.reduce((s, ip) => s + (ipBytes.get(ip) ?? 0), 0));
    const children = new Map<string, string[]>();
    for (const l of this.links) children.set(l.a, [...(children.get(l.a) ?? []), l.b]);
    const subtree = (id: string, seen = new Set<string>()): number => {
      if (seen.has(id)) return 0;
      seen.add(id);
      return (nodeBytes.get(id) ?? 0) + (children.get(id) ?? []).reduce((s, c) => s + subtree(c, seen), 0);
    };
    const fws = this.nodes.filter((n) => n.role === "edge");
    for (const l of this.links) {
      const a = this.nodes.find((n) => n.id === l.a)!;
      const b = this.nodes.find((n) => n.id === l.b)!;
      // WAN and edge→core links carry external traffic, split across edge firewalls (65/35 with two);
      // edge→DMZ server links carry only that server's traffic
      const wanPath = a.role === "internet" || (a.role === "edge" && b.role !== "server");
      const share = fws.length > 1 ? (fws[0].id === (a.role === "internet" ? l.b : l.a) ? 0.65 : 0.35 / (fws.length - 1)) : 1;
      const bytes = wanPath ? externalBytes * share : subtree(l.b);
      const rate = bps(bytes);
      this.linkStat.set(l.id, { bps: Math.min(rate, l.speedMbps * 1e6), util: clamp(rate / (l.speedMbps * 1e6), 0, 1) });
    }

    for (const n of this.nodes) {
      const d = this.devices.get(n.id);
      if (!d) continue;
      const mine = this.links.filter((l) => l.a === n.id || l.b === n.id);
      const up = n.assetIds.length ? n.assetIds.some((id) => online.get(id) !== false) : true;
      d.interfaces = mine.map((l) => {
        const s = this.linkStat.get(l.id) ?? { bps: 0, util: 0 };
        const prev = d.interfaces.find((i) => i.name === (l.a === n.id ? l.aIf : l.bIf));
        const congested = s.util > 0.9;
        const downstream = l.a === n.id; // traffic flows down the tree: out of `a`, into `b`
        return {
          name: downstream ? l.aIf : l.bIf, peer: this.nodes.find((x) => x.id === (downstream ? l.b : l.a))?.label ?? "?",
          speedMbps: l.speedMbps, status: up ? "up" : "down",
          inBps: up ? (downstream ? s.bps * 0.18 : s.bps * 0.82) : 0, outBps: up ? (downstream ? s.bps * 0.82 : s.bps * 0.18) : 0,
          util: up ? s.util : 0,
          errors: (prev?.errors ?? 0) + (congested ? Math.floor(Math.random() * 6) : Math.random() < 0.01 ? 1 : 0),
          discards: (prev?.discards ?? 0) + (congested ? Math.floor(Math.random() * 30) : 0),
        };
      });
      const util = Math.max(0, ...d.interfaces.map((i) => i.util));
      const b = BASE[n.type] ?? { cpu: 20, mem: 45, lat: 0.7 };
      const fault = this.faults.get(n.id);
      const faulty = fault && fault.until > now ? fault.kind : null;
      d.fault = faulty;
      d.util = util;
      d.inBps = d.interfaces.reduce((s, i) => s + i.inBps, 0);
      d.outBps = d.interfaces.reduce((s, i) => s + i.outBps, 0);
      d.cpu = up ? clamp(jitter(b.cpu + util * 45, 0.08), 1, 100) : 0;
      d.mem = up ? clamp(d.mem + (b.mem - d.mem) * 0.05 + (Math.random() - 0.5) * 1.2, 5, 98) : 0;
      d.latencyMs = up ? jitter(b.lat + util ** 4 * 45 + (faulty === "latency" ? 35 : 0), 0.15) : 0;
      d.lossPct = up ? clamp((util > 0.95 ? (util - 0.95) * 60 : 0) + (faulty === "packet-loss" ? 2.5 + Math.random() * 3 : 0), 0, 100) : 100;
      d.status = !up ? "down" : d.lossPct > 1 || d.latencyMs > 20 || d.cpu > 90 ? "degraded" : "up";
      if (up) d.uptimeSec += dt;
      else d.uptimeSec = 0;
      d.history.push({ t: now, cpu: d.cpu, mem: d.mem, latencyMs: d.latencyMs, lossPct: d.lossPct, inBps: d.inBps, outBps: d.outBps, up });
      if (d.history.length > HISTORY) d.history.shift();
      const minute = Math.floor(now / 60_000) * 60_000;
      const last = d.availability[d.availability.length - 1];
      const recent = d.history.filter((h) => h.t >= minute);
      const ratio = recent.filter((h) => h.up).length / Math.max(1, recent.length);
      if (last?.t === minute) last.up = ratio; else d.availability.push({ t: minute, up: ratio });
      if (d.availability.length > 60) d.availability.shift();
    }

    const wan = this.links.filter((l) => l.a === "internet").map((l) => this.linkStat.get(l.id)?.bps ?? 0).reduce((s, v) => s + v, 0);
    this.aggregate.push({ t: now, inBps: wan * 0.7, outBps: wan * 0.3 });
    if (this.aggregate.length > HISTORY) this.aggregate.shift();
  }

  health() {
    const ds = [...this.devices.values()].filter((d) => this.nodes.find((n) => n.id === d.nodeId)?.role !== "endpoints");
    const live = ds.filter((d) => d.status !== "down");
    return {
      up: ds.filter((d) => d.status === "up").length,
      degraded: ds.filter((d) => d.status === "degraded").length,
      down: ds.filter((d) => d.status === "down").length,
      avgLatencyMs: live.reduce((s, d) => s + d.latencyMs, 0) / Math.max(1, live.length),
      avgLossPct: live.reduce((s, d) => s + d.lossPct, 0) / Math.max(1, live.length),
      wanBps: this.aggregate.at(-1) ? this.aggregate.at(-1)!.inBps + this.aggregate.at(-1)!.outBps : 0,
      interfaceErrors: ds.reduce((s, d) => s + d.interfaces.reduce((x, i) => x + i.errors, 0), 0),
      busiestLinkUtil: Math.max(0, ...[...this.linkStat.values()].map((l) => l.util)),
    };
  }
}

export const SAMPLE_INTERVAL_MS = SAMPLE_MS;
