/**
 * Firewall and authentication analytics over the tenant's hot event store.
 * Pure functions of (events, assets, telemetry) so they are unit-testable.
 */
import { and, term } from "../lib/query.ts";
import { compile, inCidr } from "../lib/sxql.ts";
import type { SecurityEvent, Severity } from "../lib/types.ts";
import { ACTOR_BY_IP } from "./inventory.ts";
import type { AssetRecord } from "./repo.ts";
import type { DeviceTelemetry, Telemetry } from "./telemetry.ts";

const isPrivate = (ip: string) => ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].some((c) => inCidr(ip, c));
const BLOCK = new Set(["deny", "drop", "block"]);
const C2_PORTS = new Set([4444, 6667, 31337, 1337, 5555]);

type Counter = Map<string, number>;
const inc = (m: Counter, k: string | null | undefined, n = 1) => { if (k != null) m.set(k, (m.get(k) ?? 0) + n); };
const top = (m: Counter, n = 10) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, value]) => ({ key, value }));

function window(events: SecurityEvent[], from: number, to: number, pred: (e: SecurityEvent) => boolean) {
  const out: SecurityEvent[] = [];
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.timestamp > to) continue;
    if (e.timestamp < from) break;
    if (pred(e)) out.push(e);
  }
  return out; // newest first
}

function buckets(from: number, to: number, n = 60) {
  const width = Math.max(1000, (to - from) / n);
  return { width, idx: (t: number) => Math.min(n - 1, Math.max(0, Math.floor((t - from) / width))), n };
}

export interface Pattern { kind: string; title: string; severity: Severity; entity: string; count: number; detail: string; query: string }

// ── firewall ───────────────────────────────────────────────────────────
export interface FirewallFilter { src?: string; sport?: string; dst?: string; dport?: string; proto?: string; action?: "allow" | "deny" | ""; device?: string; from: number; to: number }

export const FIREWALL_BASE = "(event.type:firewall_allow OR event.type:firewall_deny OR event.type:suspicious_port_traffic)";

/** SXQL equivalent of the firewall filter set (also used for "open in Log Explorer"). */
export function firewallQuery(f: Omit<FirewallFilter, "from" | "to">) {
  const [vendor, ...product] = (f.device ?? "").split(" / ");
  return and(
    FIREWALL_BASE,
    f.src && term("source.ip", f.src), f.sport && term("source.port", f.sport),
    f.dst && term("destination.ip", f.dst), f.dport && term("destination.port", f.dport),
    f.proto && term("network.protocol", f.proto),
    f.action === "allow" ? "event.action:allow" : f.action === "deny" ? "(event.action:deny OR event.action:drop OR event.action:block)" : "",
    f.device && term("observer.vendor", vendor), f.device && product.length > 0 && term("observer.product", product.join(" / ")),
  );
}

/** Map a firewall product to the inventory device that runs it (by OS string), for health. */
const PRODUCT_OS: Record<string, RegExp> = { "PAN-OS": /PAN-OS/i, FortiGate: /FortiOS/i, ASA: /ASA/i };

export function firewallStats(events: SecurityEvent[], f: FirewallFilter, assets: AssetRecord[], telemetry: Telemetry | null) {
  const t0 = performance.now();
  const q = firewallQuery(f);
  const evs = window(events, f.from, f.to, compile(q));
  const b = buckets(f.from, f.to);
  const series = Array.from({ length: b.n }, (_, i) => ({ t: f.from + i * b.width, allow: 0, deny: 0 }));
  let allowed = 0, blocked = 0, bytes = 0;
  const src = new Map<string, { allow: number; deny: number }>(), dst: Counter = new Map(), port = new Map<string, { allow: number; deny: number }>();
  const proto: Counter = new Map(), devices = new Map<string, { allow: number; deny: number }>();
  const deniedBySrc: Counter = new Map(), deniedPorts = new Map<string, Set<number>>(), c2: Counter = new Map(), outBlocked: Counter = new Map(), bigOut: Counter = new Map();

  for (const e of evs) {
    const deny = BLOCK.has(e.action);
    deny ? blocked++ : allowed++;
    bytes += e.bytes;
    series[b.idx(e.timestamp)][deny ? "deny" : "allow"] += e.count;
    const s = src.get(e.sourceIp) ?? { allow: 0, deny: 0 }; s[deny ? "deny" : "allow"]++; src.set(e.sourceIp, s);
    inc(dst, e.destinationIp);
    if (e.destinationPort != null) { const p = port.get(String(e.destinationPort)) ?? { allow: 0, deny: 0 }; p[deny ? "deny" : "allow"]++; port.set(String(e.destinationPort), p); }
    inc(proto, e.protocol);
    const dv = `${e.vendor} / ${e.product}`;
    const d = devices.get(dv) ?? { allow: 0, deny: 0 }; d[deny ? "deny" : "allow"]++; devices.set(dv, d);
    if (deny) {
      inc(deniedBySrc, e.sourceIp);
      if (e.destinationPort != null) { const set = deniedPorts.get(e.sourceIp) ?? new Set(); set.add(e.destinationPort); deniedPorts.set(e.sourceIp, set); }
      if (isPrivate(e.sourceIp) && !isPrivate(e.destinationIp)) inc(outBlocked, e.sourceIp);
    } else {
      if (e.destinationPort != null && C2_PORTS.has(e.destinationPort)) inc(c2, `${e.sourceIp} → ${e.destinationIp}:${e.destinationPort}`);
      if (isPrivate(e.sourceIp) && !isPrivate(e.destinationIp)) inc(bigOut, `${e.sourceIp} → ${e.destinationIp}`, e.bytes);
    }
  }

  const patterns: Pattern[] = [];
  for (const [ip, n] of deniedBySrc) if (n >= 20)
    patterns.push({ kind: "repeated_block", title: "Repeatedly blocked source", severity: n >= 100 ? "high" : "medium", entity: ip, count: n, detail: `${n} blocked connections`, query: and(FIREWALL_BASE, term("source.ip", ip), "event.action:deny") });
  for (const [ip, set] of deniedPorts) if (set.size >= 15)
    patterns.push({ kind: "port_sweep", title: "Port sweep against perimeter", severity: "high", entity: ip, count: set.size, detail: `${set.size} distinct destination ports blocked`, query: and(FIREWALL_BASE, term("source.ip", ip)) });
  for (const [k, n] of c2) {
    const [s, rest] = k.split(" → ");
    patterns.push({ kind: "c2_port", title: "Allowed traffic to a known C2 port", severity: "critical", entity: k, count: n, detail: `${n} allowed connection(s)`, query: and(FIREWALL_BASE, term("source.ip", s), term("destination.port", rest.split(":")[1]), "event.action:allow") });
  }
  for (const [ip, n] of outBlocked) if (n >= 5)
    patterns.push({ kind: "outbound_blocked", title: "Internal host repeatedly blocked outbound", severity: "medium", entity: ip, count: n, detail: "possible malware or misconfiguration", query: and(FIREWALL_BASE, term("source.ip", ip), "event.action:deny") });
  for (const [k, n] of bigOut) if (n >= 50_000_000) {
    const [s, d] = k.split(" → ");
    patterns.push({ kind: "large_outbound", title: "Large outbound flow allowed", severity: "high", entity: k, count: n, detail: `${(n / 1e6).toFixed(0)} MB sent (sampled flows)`, query: and(FIREWALL_BASE, term("source.ip", s), term("destination.ip", d)) });
  }
  const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  patterns.sort((a, b) => rank[b.severity] - rank[a.severity] || b.count - a.count);

  const fwAssets = assets.filter((a) => a.type === "firewall");
  const deviceList = [...devices.entries()].map(([name, c]) => {
    const product = name.split(" / ")[1] ?? "";
    const asset = fwAssets.find((a) => PRODUCT_OS[product]?.test(a.os ?? ""));
    const tel: DeviceTelemetry | null = asset && telemetry ? telemetry.devices.get(asset.id) ?? null : null;
    return {
      name, allow: c.allow, deny: c.deny, hostname: asset?.hostname ?? null, ip: asset?.ip ?? null,
      health: tel ? { status: tel.status, cpu: tel.cpu, mem: tel.mem, sessions: Math.round((c.allow + c.deny) * 3.2), wanUtil: tel.util, fault: tel.fault } : null,
    };
  }).sort((a, b) => b.allow + b.deny - (a.allow + a.deny));

  return {
    query: q,
    totals: { events: evs.length, allowed, blocked, bytes, blockRate: evs.length ? blocked / evs.length : 0 },
    series, bucketMs: b.width,
    topSources: [...src.entries()].sort((a, b) => b[1].allow + b[1].deny - (a[1].allow + a[1].deny)).slice(0, 10).map(([key, v]) => ({ key, ...v, external: !isPrivate(key), country: ACTOR_BY_IP.get(key)?.country ?? null })),
    topDestinations: top(dst),
    topPorts: [...port.entries()].sort((a, b) => b[1].allow + b[1].deny - (a[1].allow + a[1].deny)).slice(0, 10).map(([key, v]) => ({ key, ...v })),
    protocols: top(proto, 6),
    devices: deviceList,
    patterns: patterns.slice(0, 25),
    recent: evs.slice(0, 100),
    tookMs: Math.round((performance.now() - t0) * 10) / 10,
  };
}

// ── authentication ─────────────────────────────────────────────────────
const AUTH = compile("event.category:authentication");
const isSsh = (e: SecurityEvent) => e.destinationPort === 22 || e.type === "ssh_login_failure" || e.product === "OpenSSH";
const isRdp = (e: SecurityEvent) => e.destinationPort === 3389 || e.type === "rdp_login_failure";
const isLockout = (e: SecurityEvent) => e.action === "lockout";
const isFail = (e: SecurityEvent) => e.outcome === "failure" && !isLockout(e);
const isOk = (e: SecurityEvent) => e.outcome === "success";

export const COMPROMISE_WINDOW_MS = 10 * 60_000;

/**
 * Success-after-failures detector. A successful logon is a compromise signal when the same
 * source produced ≥ 5 failures in the preceding 10 minutes AND either ≥ 3 of them targeted the
 * same account, or the source is external. This ignores ordinary typos spread across many
 * users from busy internal workstations.
 */
export function compromiseSignals(evs: SecurityEvent[]) {
  const asc = [...evs].sort((a, b) => a.timestamp - b.timestamp);
  const fails = new Map<string, SecurityEvent[]>();
  const out: { source: string; user: string | null; target: string | null; failures: number; sameUser: number; successAt: number; country: string | null; eventId: string }[] = [];
  const seen = new Set<string>();
  for (const e of asc) {
    if (isFail(e)) { fails.set(e.sourceIp, [...(fails.get(e.sourceIp) ?? []), e]); continue; }
    if (!isOk(e)) continue;
    const recent = (fails.get(e.sourceIp) ?? []).filter((f) => f.timestamp >= e.timestamp - COMPROMISE_WINDOW_MS);
    fails.set(e.sourceIp, recent);
    const sameUser = recent.filter((f) => f.username === e.username).length;
    if (recent.length < 5 || !(sameUser >= 3 || !isPrivate(e.sourceIp))) continue;
    const key = `${e.sourceIp}|${e.username}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ source: e.sourceIp, user: e.username, target: e.destinationHost ?? e.destinationIp, failures: recent.length, sameUser, successAt: e.timestamp, country: ACTOR_BY_IP.get(e.sourceIp)?.country ?? null, eventId: e.id });
  }
  return out.sort((a, b) => b.successAt - a.successAt);
}

export function authStats(events: SecurityEvent[], from: number, to: number, now = Date.now()) {
  const t0 = performance.now();
  const evs = window(events, from, to, AUTH);
  const b = buckets(from, to);
  const series = Array.from({ length: b.n }, (_, i) => ({ t: from + i * b.width, success: 0, failure: 0 }));
  const totals = { success: 0, failure: 0, lockouts: 0, ssh: { success: 0, failure: 0 }, rdp: { success: 0, failure: 0 }, other: { success: 0, failure: 0 } };
  const failUser: Counter = new Map(), failSrc: Counter = new Map(), failTarget: Counter = new Map(), pair: Counter = new Map();
  const lockouts: SecurityEvent[] = [];

  for (const e of evs) {
    if (isLockout(e)) { totals.lockouts++; lockouts.push(e); continue; }
    const ok = isOk(e), fail = isFail(e);
    if (!ok && !fail) continue;
    const k = ok ? "success" : "failure";
    totals[k]++;
    (isSsh(e) ? totals.ssh : isRdp(e) ? totals.rdp : totals.other)[k]++;
    series[b.idx(e.timestamp)][k]++;
    if (fail) {
      inc(failUser, e.username); inc(failSrc, e.sourceIp); inc(failTarget, e.destinationHost ?? e.destinationIp);
      inc(pair, `${e.username ?? "?"}|${e.sourceIp}`);
    }
  }
  const compromise = compromiseSignals(evs);

  const repeated = [...pair.entries()].filter(([, n]) => n >= 5).sort((a, b) => b[1] - a[1]).slice(0, 15)
    .map(([k, n]) => { const [user, source] = k.split("|"); return { user, source, failures: n, external: !isPrivate(source) }; });

  // logins from outside the private address space ("unusual location")
  const extMap = new Map<string, { source: string; country: string; success: number; failure: number; users: Set<string>; last: number }>();
  for (const e of evs) {
    if (isPrivate(e.sourceIp) || isLockout(e)) continue;
    const x = extMap.get(e.sourceIp) ?? { source: e.sourceIp, country: ACTOR_BY_IP.get(e.sourceIp)?.country ?? "Unknown (external)", success: 0, failure: 0, users: new Set(), last: 0 };
    isOk(e) ? x.success++ : x.failure++;
    if (e.username) x.users.add(e.username);
    x.last = Math.max(x.last, e.timestamp);
    extMap.set(e.sourceIp, x);
  }
  const locations = [...extMap.values()].map((x) => ({ ...x, users: [...x.users].slice(0, 6) })).sort((a, b) => b.success - a.success || b.failure - a.failure).slice(0, 15);

  // sessions inferred from successful logons in the last 30 minutes (no logoff events in the feed)
  const sess = new Map<string, { user: string; host: string; source: string; since: number; method: string }>();
  for (const e of evs) {
    if (!isOk(e) || e.timestamp < now - 30 * 60_000) continue;
    const key = `${e.username}|${e.destinationHost ?? e.destinationIp}`;
    if (!sess.has(key)) sess.set(key, { user: e.username ?? "?", host: e.destinationHost ?? e.destinationIp, source: e.sourceIp, since: e.timestamp, method: isSsh(e) ? "SSH" : isRdp(e) ? "RDP" : "Windows logon" });
  }

  return {
    totals, series, bucketMs: b.width,
    topFailedUsers: top(failUser), topFailedSources: top(failSrc).map((x) => ({ ...x, external: !isPrivate(x.key), country: ACTOR_BY_IP.get(x.key)?.country ?? null })),
    topTargets: top(failTarget),
    repeated, compromise: compromise.slice(0, 20), locations,
    lockouts: lockouts.slice(0, 30).map((e) => ({ at: e.timestamp, user: e.username, host: e.destinationHost, eventId: e.eventId, id: e.id })),
    sessions: [...sess.values()].sort((a, b) => b.since - a.since).slice(0, 50),
    tookMs: Math.round((performance.now() - t0) * 10) / 10,
  };
}

/** Failed-login investigation for one account or one source address. */
export function authInvestigate(events: SecurityEvent[], kind: "user" | "source", value: string) {
  const match = kind === "user" ? (e: SecurityEvent) => e.username === value : (e: SecurityEvent) => e.sourceIp === value;
  const evs = events.filter((e) => AUTH(e) && match(e));
  const fails = evs.filter(isFail), oks = evs.filter(isOk), locks = evs.filter(isLockout);
  const distinct = (f: (e: SecurityEvent) => string | null) => [...new Set(evs.map(f).filter(Boolean) as string[])];
  const sources = distinct((e) => e.sourceIp), users = distinct((e) => e.username), targets = distinct((e) => e.destinationHost ?? e.destinationIp);
  const signals = compromiseSignals(evs);

  const findings: { severity: Severity; text: string }[] = [];
  if (fails.length >= 10) findings.push({ severity: "high", text: `${fails.length} failed authentications${kind === "user" ? ` from ${sources.length} source(s)` : ` against ${users.length} account(s)`}.` });
  else if (fails.length) findings.push({ severity: "low", text: `${fails.length} failed authentication(s) — within normal typo range.` });
  if (kind === "source" && users.length >= 5) findings.push({ severity: "high", text: `Source tried ${users.length} different accounts — password spraying / user enumeration.` });
  if (kind === "user" && sources.length >= 4) findings.push({ severity: "medium", text: `Account targeted from ${sources.length} different hosts.` });
  for (const s of signals.slice(0, 3)) findings.push({ severity: "critical", text: `Successful login as ${s.user} from ${s.source} at ${new Date(s.successAt).toLocaleTimeString("en-GB")} after ${s.failures} failures in the preceding 10 min (${s.sameUser} against that account) — treat it as compromised until verified.` });
  if (locks.length) findings.push({ severity: "medium", text: `${locks.length} account lockout event(s).` });
  const ext = sources.filter((s) => !isPrivate(s));
  if (ext.length) findings.push({ severity: "medium", text: `Activity from external address(es): ${ext.slice(0, 4).map((s) => `${s}${ACTOR_BY_IP.get(s) ? ` (${ACTOR_BY_IP.get(s)!.country}, demo GeoIP)` : ""}`).join(", ")}.` });
  if (!findings.length) findings.push({ severity: "info", text: "No authentication events for this entity in the hot window." });

  return {
    kind, value,
    summary: { events: evs.length, failures: fails.length, successes: oks.length, lockouts: locks.length, sources, users, targets, first: evs[0]?.timestamp ?? null, last: evs.at(-1)?.timestamp ?? null },
    findings,
    timeline: evs.slice(-300).reverse(),
    query: kind === "user" ? and("event.category:authentication", term("user.name", value)) : and("event.category:authentication", term("source.ip", value)),
  };
}
