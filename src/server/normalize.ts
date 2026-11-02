/**
 * Normalization pipeline: raw CEF / RFC 5424 syslog / JSON (Windows Security
 * or ECS-style) → SecurityEvent. Every ingestion path (simulator, REST,
 * future syslog listener) goes through normalize().
 */
import { EVENT_TYPES, SEVERITIES, type Direction, type EventType, type Outcome, type Protocol, type SecurityEvent, type Severity } from "../lib/types.ts";
import { ASSETS, ASSET_BY_IP } from "./inventory.ts";

export interface RawEnvelope {
  format: "cef" | "syslog" | "json";
  payload: string | Record<string, unknown>;
  receivedAt: number;
  simulated: boolean;
  scenario?: string | null;
}

export class NormalizationError extends Error {}

/** Resolves hosts against the tenant's asset inventory. Defaults to the demo inventory. */
export interface HostResolver { hostOf(ip: string): string | null; ipOf(hostname: string): string | null }
export const DEMO_RESOLVER: HostResolver = {
  hostOf: (ip) => ASSET_BY_IP.get(ip)?.hostname ?? null,
  ipOf: (h) => ASSETS.find((x) => x.hostname === h)?.ip ?? null,
};
let R: HostResolver = DEMO_RESOLVER;

const CATEGORY: Record<EventType, string> = {
  firewall_allow: "network", firewall_deny: "network", auth_success: "authentication", auth_failure: "authentication",
  ssh_login_failure: "authentication", rdp_login_failure: "authentication", dns_query: "dns", suspicious_dns: "dns",
  port_scan: "intrusion_detection", network_sweep: "intrusion_detection", brute_force: "intrusion_detection",
  ddos: "intrusion_detection", suspicious_port_traffic: "network", malware_detection: "malware", ids_alert: "intrusion_detection",
  privilege_escalation: "iam", unusual_network_activity: "network", endpoint_alert: "endpoint",
};

const DEFAULT_SEVERITY: Record<EventType, Severity> = {
  firewall_allow: "info", firewall_deny: "low", auth_success: "info", auth_failure: "low", ssh_login_failure: "medium",
  rdp_login_failure: "medium", dns_query: "info", suspicious_dns: "medium", port_scan: "high", network_sweep: "medium",
  brute_force: "high", ddos: "critical", suspicious_port_traffic: "high", malware_detection: "critical", ids_alert: "high",
  privilege_escalation: "high", unusual_network_activity: "medium", endpoint_alert: "high",
};

/** CEF severity 0-10 → SENTINEL X severity */
const cefSeverity = (n: number): Severity => (n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : n >= 2 ? "low" : "info");

const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
const direction = (src: string, dst: string): Direction =>
  isPrivate(src) && isPrivate(dst) ? "internal" : isPrivate(src) ? "outbound" : "inbound";

let seq = 0;
const newId = (ts: number) => `${ts.toString(36)}-${(++seq).toString(36).padStart(5, "0")}`;
const eventCode = () => `EVT-${(1_000_000 + (seq % 9_000_000)).toString()}`;

const asType = (v: unknown): EventType | null => {
  const s = String(v ?? "").toLowerCase().replace(/[\s/-]+/g, "_");
  return (EVENT_TYPES as readonly string[]).includes(s) ? (s as EventType) : null;
};
const asProto = (v: unknown): Protocol => {
  const s = String(v ?? "").toLowerCase();
  return s === "udp" || s === "icmp" || s === "dns" ? s : "tcp";
};
const asInt = (v: unknown): number | null => {
  const n = Number(v);
  return v === undefined || v === null || v === "" || Number.isNaN(n) ? null : Math.trunc(n);
};

interface Partial0 {
  timestamp: number; type: EventType; severity?: Severity; sourceIp: string; destinationIp: string;
  sourcePort?: number | null; destinationPort?: number | null; protocol?: Protocol; sourceHost?: string | null;
  destinationHost?: string | null; username?: string | null; application?: string | null; vendor: string; product: string;
  action?: string; outcome?: Outcome; count?: number; bytes?: number; dnsQuery?: string | null; message?: string;
}

function finish(p: Partial0, env: RawEnvelope): SecurityEvent {
  if (!p.sourceIp || !p.destinationIp) throw new NormalizationError("source and destination IP are required");
  const ts = Number.isFinite(p.timestamp) ? p.timestamp : env.receivedAt;
  return {
    id: newId(ts),
    timestamp: ts,
    eventId: eventCode(),
    type: p.type,
    category: CATEGORY[p.type],
    severity: p.severity ?? DEFAULT_SEVERITY[p.type],
    sourceIp: p.sourceIp,
    sourcePort: p.sourcePort ?? null,
    destinationIp: p.destinationIp,
    destinationPort: p.destinationPort ?? null,
    protocol: p.protocol ?? "tcp",
    direction: direction(p.sourceIp, p.destinationIp),
    sourceHost: p.sourceHost ?? R.hostOf(p.sourceIp),
    destinationHost: p.destinationHost ?? R.hostOf(p.destinationIp),
    username: p.username ?? null,
    application: p.application ?? null,
    vendor: p.vendor,
    product: p.product,
    action: p.action ?? "alert",
    outcome: p.outcome ?? "unknown",
    count: Math.max(1, p.count ?? 1),
    bytes: Math.max(0, p.bytes ?? 0),
    dnsQuery: p.dnsQuery ?? null,
    message: p.message ?? "",
    simulated: env.simulated,
    scenario: env.scenario ?? null,
    rawFormat: env.format,
    raw: env.payload,
  };
}

// ── CEF ──────────────────────────────────────────────────────────────────
export function parseCef(line: string) {
  const body = line.slice(line.indexOf("CEF:"));
  const parts: string[] = [];
  let cur = "", i = 4;
  for (; i < body.length && parts.length < 7; i++) {
    if (body[i] === "\\" && i + 1 < body.length) { cur += body[++i]; continue; }
    if (body[i] === "|") { parts.push(cur); cur = ""; continue; }
    cur += body[i];
  }
  if (parts.length < 7) throw new NormalizationError("Malformed CEF header");
  const ext: Record<string, string> = {};
  const extStr = body.slice(i);
  const re = /(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|$)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(extStr))) ext[m[1]] = m[2].replace(/\\=/g, "=").trim();
  const [version, vendor, product, deviceVersion, signatureId, name, severity] = parts;
  return { version, vendor, product, deviceVersion, signatureId, name, severity: Number(severity), ext };
}

function fromCef(env: RawEnvelope): SecurityEvent {
  const c = parseCef(String(env.payload));
  const type = asType(c.signatureId) ?? asType(c.ext.cat) ?? "unusual_network_activity";
  const act = c.ext.act?.toLowerCase();
  return finish({
    timestamp: Number(c.ext.rt) || env.receivedAt,
    type,
    severity: Number.isFinite(c.severity) ? cefSeverity(c.severity) : undefined,
    sourceIp: c.ext.src, destinationIp: c.ext.dst,
    sourcePort: asInt(c.ext.spt), destinationPort: asInt(c.ext.dpt), protocol: asProto(c.ext.proto),
    sourceHost: c.ext.shost || null, destinationHost: c.ext.dhost || null, username: c.ext.suser || c.ext.duser || null,
    application: c.ext.app || null, vendor: c.vendor, product: c.product, action: act,
    outcome: act === "deny" || act === "drop" || act === "block" ? "failure" : act === "allow" ? "success" : (c.ext.outcome as Outcome) ?? "unknown",
    count: asInt(c.ext.cnt) ?? 1, bytes: (asInt(c.ext.in) ?? 0) + (asInt(c.ext.out) ?? 0),
    dnsQuery: c.ext.cs1Label === "dnsQuery" ? c.ext.cs1 : null, message: c.ext.msg || c.name,
  }, env);
}

// ── RFC 5424 syslog (sshd / sudo) ────────────────────────────────────────
const SYSLOG_RE = /^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) \S+ \S+ (.*)$/;

function fromSyslog(env: RawEnvelope): SecurityEvent {
  const m = SYSLOG_RE.exec(String(env.payload));
  if (!m) throw new NormalizationError("Unsupported syslog line (expected RFC 5424)");
  const [, , ts, host, app, , msg] = m;
  const timestamp = Date.parse(ts);
  const hostIp = R.ipOf(host) ?? "0.0.0.0";
  let r: RegExpExecArray | null;
  if ((r = /Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)/.exec(msg)))
    return finish({ timestamp, type: "ssh_login_failure", sourceIp: r[2], sourcePort: Number(r[3]), destinationIp: hostIp, destinationPort: 22,
      destinationHost: host, username: r[1], application: app, vendor: "OpenBSD", product: "OpenSSH", action: "login", outcome: "failure", message: msg }, env);
  if ((r = /Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)/.exec(msg)))
    return finish({ timestamp, type: "auth_success", sourceIp: r[2], sourcePort: Number(r[3]), destinationIp: hostIp, destinationPort: 22,
      destinationHost: host, username: r[1], application: app, vendor: "OpenBSD", product: "OpenSSH", action: "login", outcome: "success", message: msg }, env);
  if ((r = /^\s*(\S+) : .*USER=root ; COMMAND=(.*)$/.exec(msg)))
    return finish({ timestamp, type: "privilege_escalation", sourceIp: hostIp, destinationIp: hostIp, destinationHost: host, sourceHost: host,
      username: r[1], application: app, vendor: "Linux", product: "sudo", action: "elevate", outcome: "success", message: msg }, env);
  throw new NormalizationError(`No parser matched ${app} message`);
}

// ── JSON: Windows Security events or ECS-style documents ─────────────────
function flatten(obj: Record<string, unknown>, prefix = "", out: Record<string, unknown> = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) flatten(v as Record<string, unknown>, key, out);
    else out[key] = v;
  }
  return out;
}

function fromJson(env: RawEnvelope): SecurityEvent {
  const o = (typeof env.payload === "string" ? JSON.parse(env.payload) : env.payload) as Record<string, unknown>;
  if (o.Channel === "Security" && o.EventID) {
    const id = Number(o.EventID);
    const ip = String(o.IpAddress ?? "0.0.0.0");
    const comp = String(o.Computer ?? "");
    const dst = R.ipOf(comp) ?? "0.0.0.0";
    const logonType = Number(o.LogonType);
    const base = { timestamp: Date.parse(String(o.TimeCreated)), sourceIp: ip, sourcePort: asInt(o.IpPort), destinationIp: dst,
      destinationHost: comp, username: String(o.TargetUserName ?? ""), application: "lsass.exe", vendor: "Microsoft", product: "Windows Security" };
    if (id === 4625) return finish({ ...base, type: logonType === 10 ? "rdp_login_failure" : "auth_failure", destinationPort: logonType === 10 ? 3389 : 445,
      action: "login", outcome: "failure", message: `An account failed to log on (LogonType ${logonType})` }, env);
    if (id === 4624) return finish({ ...base, type: "auth_success", destinationPort: logonType === 10 ? 3389 : 445, action: "login", outcome: "success",
      message: `An account was successfully logged on (LogonType ${logonType})` }, env);
    if (id === 4740) return finish({ ...base, type: "auth_failure", severity: "medium", destinationPort: null, action: "lockout", outcome: "failure",
      message: "A user account was locked out" }, env);
    if (id === 4672 || id === 4728 || id === 4732) return finish({ ...base, type: "privilege_escalation", severity: id === 4672 ? "medium" : "high",
      action: "elevate", outcome: "success", message: id === 4672 ? "Special privileges assigned to new logon" : "A member was added to a security-enabled group" }, env);
    throw new NormalizationError(`Unsupported Windows EventID ${id}`);
  }
  const f = flatten(o);
  const type = asType(f["event.type"]);
  if (!type) throw new NormalizationError(`event.type must be one of: ${EVENT_TYPES.join(", ")}`);
  const sev = String(f["event.severity"] ?? "").toLowerCase();
  return finish({
    timestamp: f["@timestamp"] ? Date.parse(String(f["@timestamp"])) : env.receivedAt,
    type, severity: (SEVERITIES as readonly string[]).includes(sev) ? (sev as Severity) : undefined,
    sourceIp: String(f["source.ip"] ?? ""), destinationIp: String(f["destination.ip"] ?? ""),
    sourcePort: asInt(f["source.port"]), destinationPort: asInt(f["destination.port"]), protocol: asProto(f["network.protocol"]),
    sourceHost: (f["source.host"] as string) ?? null, destinationHost: (f["destination.host"] as string) ?? null,
    username: (f["user.name"] as string) ?? null, application: (f["process.name"] as string) ?? null,
    vendor: String(f["observer.vendor"] ?? "REST API"), product: String(f["observer.product"] ?? "Ingest"),
    action: f["event.action"] as string | undefined, outcome: (f["event.outcome"] as Outcome) ?? undefined,
    count: asInt(f["event.count"]) ?? 1, bytes: asInt(f["network.bytes"]) ?? 0, dnsQuery: (f["dns.question.name"] as string) ?? null,
    message: String(f.message ?? ""),
  }, env);
}

export function normalize(env: RawEnvelope, resolver: HostResolver = DEMO_RESOLVER): SecurityEvent {
  R = resolver; // normalization is synchronous, so a module-level resolver cannot interleave
  try {
    switch (env.format) {
      case "cef": return fromCef(env);
      case "syslog": return fromSyslog(env);
      case "json": return fromJson(env);
    }
  } finally {
    R = DEMO_RESOLVER;
  }
}
