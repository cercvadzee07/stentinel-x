/**
 * Scan authorization policy — enforced server-side before any scan is queued or run.
 *
 *  - Targets: one IPv4 address or a CIDR block no larger than /22 (1,024 addresses).
 *  - Every target address must lie inside one of the organization's allowlisted CIDRs.
 *  - Public addresses are rejected unless SCAN_ALLOW_PUBLIC=1 (and they are still allowlist-bound).
 *  - Loopback, link-local, multicast, "this network" and broadcast ranges are always rejected.
 *  - Bounded work: port counts, hosts × ports, timeout and intensity are capped. There are no
 *    options for stealth, evasion, spoofing, decoys, fragmentation or intrusive scripts.
 */
import { inCidr, ipToInt } from "../../lib/sxql.ts";

export const SCAN_TYPES = ["host_discovery", "tcp", "udp", "service", "network_discovery", "vuln_basic"] as const;
export type ScanType = (typeof SCAN_TYPES)[number];

export const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  host_discovery: "Host discovery",
  tcp: "TCP port scan",
  udp: "UDP port scan",
  service: "Service detection",
  network_discovery: "Network discovery",
  vuln_basic: "Basic vulnerability assessment",
};

export const MAX_PREFIX = 22;
export const MAX_HOSTS = 1024;
export const MAX_PROBES = 65_536;
export const PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const RESERVED = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"];

export const TOP_TCP = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 593, 636, 873, 902, 993, 995,
  1025, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4443, 4444, 4848, 5000, 5060, 5432,
  5601, 5672, 5900, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7443, 8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9042, 9090, 9092,
  9200, 9300, 9418, 9443, 10000, 10250, 11211, 15672, 27017, 50000, 49152, 49153, 49154, 1194, 1883, 8883, 2222, 4369, 5353, 5671, 6001,
  7000, 7070, 8001, 8090, 8181, 31337];
export const TOP_UDP = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353, 11211];

export const isPrivate = (ip: string) => PRIVATE_RANGES.some((c) => inCidr(ip, c));
const intToIp = (n: number) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

export interface Target { input: string; network: string; prefix: number; first: number; last: number; count: number }

export function parseTarget(raw: string): Target | string {
  const input = raw.trim();
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(input);
  if (!m) return "Target must be an IPv4 address or CIDR block (e.g. 10.20.0.0/24). Hostnames are not accepted.";
  const ip = ipToInt(m[1]);
  if (ip === null) return "Invalid IPv4 address";
  const prefix = m[2] === undefined ? 32 : Number(m[2]);
  if (prefix > 32) return "Invalid prefix length";
  if (prefix < MAX_PREFIX) return `Target too large: /${prefix}. The maximum is /${MAX_PREFIX} (${MAX_HOSTS} addresses).`;
  const size = 2 ** (32 - prefix);
  const first = Math.floor(ip / size) * size;
  return { input, network: `${intToIp(first)}/${prefix}`, prefix, first, last: first + size - 1, count: size };
}

/** Every address of the target, in order (bounded by MAX_HOSTS). */
export function targetHosts(t: Target): string[] {
  const out: string[] = [];
  // skip network and broadcast addresses of multi-host blocks
  const lo = t.count > 2 ? t.first + 1 : t.first, hi = t.count > 2 ? t.last - 1 : t.last;
  for (let n = lo; n <= hi; n++) out.push(intToIp(n));
  return out;
}

const within = (t: Target, cidr: string) => inCidr(intToIp(t.first), cidr) && inCidr(intToIp(t.last), cidr);

export function parsePorts(spec: string, type: ScanType): number[] | string {
  const s = spec.trim().toLowerCase();
  if (type === "host_discovery") return [];
  if (type === "network_discovery") return TOP_TCP.slice(0, 20);
  if (s === "top" || s === "top100" || s === "") return type === "udp" ? TOP_UDP : TOP_TCP;
  const out = new Set<number>();
  for (const part of s.split(",").map((x) => x.trim()).filter(Boolean)) {
    const r = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!r) return `Invalid port token "${part}". Use e.g. 22,80,443 or 1-1024 or top100.`;
    const a = Number(r[1]), b = r[2] ? Number(r[2]) : a;
    if (a < 1 || b > 65535 || a > b) return `Port range ${part} is out of bounds (1-65535)`;
    if (b - a > 65535) return "Port range too large";
    for (let p = a; p <= b; p++) out.add(p);
  }
  if (!out.size) return "No ports given";
  return [...out].sort((x, y) => x - y);
}

/** Compact nmap-style port list: [22,80,81,82,443] → "22,80-82,443" */
export function compactPorts(ports: number[]) {
  const out: string[] = [];
  for (let i = 0; i < ports.length; i++) {
    let j = i;
    while (j + 1 < ports.length && ports[j + 1] === ports[j] + 1) j++;
    out.push(i === j ? String(ports[i]) : `${ports[i]}-${ports[j]}`);
    i = j;
  }
  return out.join(",");
}

export interface ScanRequest { target: string; ports: string; type: ScanType; intensity: number; timeoutSec: number }
export interface ScanPlan extends ScanRequest { targetInfo: Target; portList: number[]; hosts: number; probes: number; matchedAllowlist: string }

export function validateScan(req: ScanRequest, allowlist: string[], env: { allowPublic?: boolean } = {}): { ok: true; plan: ScanPlan } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const t = parseTarget(req.target);
  if (typeof t === "string") return { ok: false, errors: [t] };
  if (RESERVED.some((r) => inCidr(intToIp(t.first), r) || inCidr(intToIp(t.last), r))) errors.push("Loopback, link-local, multicast and reserved ranges cannot be scanned.");
  const allPrivate = isPrivate(intToIp(t.first)) && isPrivate(intToIp(t.last)) && PRIVATE_RANGES.some((c) => within(t, c));
  if (!allPrivate && !env.allowPublic) errors.push("Public IP addresses cannot be scanned on this deployment (only RFC 1918 private ranges).");
  const matched = allowlist.find((c) => within(t, c));
  if (!matched) errors.push(`Target ${t.network} is not inside any authorized allowlist range${allowlist.length ? ` (${allowlist.join(", ")})` : " — the allowlist is empty"}.`);
  const ports = parsePorts(req.ports, req.type);
  if (typeof ports === "string") errors.push(ports);
  const hosts = targetHosts(t).length;
  const portCount = typeof ports === "string" ? 0 : ports.length;
  if (req.type === "udp" && portCount > 100) errors.push("UDP scans are limited to 100 ports.");
  if (hosts > 1 && portCount > 1024) errors.push("Multi-host scans are limited to 1,024 ports.");
  if (hosts * Math.max(1, portCount) > MAX_PROBES) errors.push(`Scan too large: ${hosts} hosts × ${portCount} ports exceeds ${MAX_PROBES.toLocaleString("en-US")} probes.`);
  if (!Number.isInteger(req.intensity) || req.intensity < 1 || req.intensity > 4) errors.push("Intensity must be 1–4.");
  if (!(req.timeoutSec >= 30 && req.timeoutSec <= 1800)) errors.push("Timeout must be between 30 and 1800 seconds.");
  if (errors.length) return { ok: false, errors };
  return { ok: true, plan: { ...req, targetInfo: t, portList: ports as number[], hosts, probes: hosts * Math.max(1, portCount), matchedAllowlist: matched! } };
}

/** Allowlist entries must be well-formed, at most /8, and private unless public scanning is enabled. */
export function validateAllowlistCidr(cidr: string, env: { allowPublic?: boolean } = {}): { ok: true; network: string } | { ok: false; error: string } {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr.trim());
  if (!m || ipToInt(m[1]) === null || Number(m[2]) > 32) return { ok: false, error: "Use CIDR notation, e.g. 10.20.0.0/16" };
  const prefix = Number(m[2]);
  if (prefix < 8) return { ok: false, error: "Allowlist entries can be at most /8" };
  const size = 2 ** (32 - prefix);
  const first = Math.floor(ipToInt(m[1])! / size) * size;
  const network = `${intToIp(first)}/${prefix}`;
  if (RESERVED.some((r) => inCidr(intToIp(first), r))) return { ok: false, error: "Reserved ranges cannot be allowlisted" };
  const priv = PRIVATE_RANGES.some((c) => inCidr(intToIp(first), c) && inCidr(intToIp(first + size - 1), c));
  if (!priv && !env.allowPublic) return { ok: false, error: "Only private (RFC 1918) ranges can be allowlisted on this deployment" };
  return { ok: true, network };
}
