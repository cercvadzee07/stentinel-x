/**
 * Simulated scan engine. Produces results ONLY for hosts that exist in the tenant's
 * asset inventory within the target range, using a deterministic service profile per
 * asset type. Nothing here is a network observation; every job and result produced by
 * this engine is flagged `simulated: true` and labelled as such in the UI.
 */
import type { AssetRecord } from "../repo.ts";
import type { HostResult, PortResult } from "./checks.ts";
import { TOP_TCP, targetHosts, type ScanPlan } from "./policy.ts";

type Svc = Omit<PortResult, "state">;
const tcp = (port: number, service: string, product: string | null = null, version: string | null = null): Svc => ({ port, proto: "tcp", service, product, version });
const udp = (port: number, service: string, product: string | null = null, version: string | null = null): Svc => ({ port, proto: "udp", service, product, version });

const linuxSsh = (v = "9.8p1") => tcp(22, "ssh", "OpenSSH", v);
const winBase = [tcp(135, "msrpc", "Microsoft Windows RPC"), tcp(139, "netbios-ssn", "Microsoft Windows netbios-ssn"), tcp(445, "microsoft-ds", "Microsoft Windows SMB")];

const BY_TYPE: Record<string, Svc[]> = {
  firewall: [tcp(22, "ssh", "OpenSSH", "8.0"), tcp(443, "https", "nginx"), udp(161, "snmp", "net-snmp")],
  router: [tcp(22, "ssh", "Cisco SSH", "2.0"), udp(161, "snmp", "Cisco SNMP"), udp(123, "ntp")],
  switch: [tcp(22, "ssh", "Arista SSH", "2.0"), tcp(443, "https"), udp(161, "snmp")],
  domain_controller: [tcp(53, "domain", "Microsoft DNS"), tcp(88, "kerberos-sec", "Microsoft Windows Kerberos"), ...winBase, tcp(389, "ldap", "Microsoft Windows Active Directory LDAP"), tcp(636, "ldapssl"), tcp(3389, "ms-wbt-server", "Microsoft Terminal Services"), udp(53, "domain")],
  database: [linuxSsh(), tcp(5432, "postgresql", "PostgreSQL DB", "15.4")],
  web: [linuxSsh(), tcp(80, "http", "nginx", "1.24.0"), tcp(443, "https", "nginx", "1.24.0")],
  server: [linuxSsh()],
  workstation: [...winBase],
};

/** Demo-specific overrides so the assessment has realistic, verifiable findings. */
const BY_HOST: Record<string, Svc[]> = {
  "web-01": [linuxSsh("8.9p1"), tcp(80, "http", "Apache httpd", "2.4.49"), tcp(443, "https", "Apache httpd", "2.4.49")],
  "web-02": [linuxSsh(), tcp(80, "http", "Apache httpd", "2.4.58"), tcp(443, "https", "Apache httpd", "2.4.58")],
  "vpn-01": [linuxSsh("9.6p1"), tcp(443, "https", "OpenVPN"), udp(1194, "openvpn")],
  "api-gw-01": [linuxSsh(), tcp(443, "https", "Envoy"), tcp(9200, "http", "Elasticsearch REST API", "8.11.1")],
  "mail-01": [tcp(25, "smtp", "Microsoft Exchange smtpd"), tcp(443, "https", "Microsoft IIS httpd", "10.0"), ...winBase],
  "files-01": [...winBase, tcp(21, "ftp", "vsftpd", "3.0.5"), tcp(3389, "ms-wbt-server", "Microsoft Terminal Services")],
  "jump-01": [...winBase, tcp(3389, "ms-wbt-server", "Microsoft Terminal Services"), tcp(5985, "http", "Microsoft HTTPAPI httpd", "2.0")],
  "db-prod-02": [linuxSsh(), tcp(3306, "mysql", "MySQL", "8.0.36"), tcp(6379, "redis", "Redis key-value store", "7.2.4")],
  "k8s-node-01": [linuxSsh(), tcp(10250, "ssl/http", "Golang net/http server"), tcp(6443, "ssl/https", "Kubernetes API")],
  "k8s-node-02": [linuxSsh(), tcp(10250, "ssl/http", "Golang net/http server"), tcp(2375, "docker", "Docker", "24.0.7")],
  "k8s-node-03": [linuxSsh(), tcp(10250, "ssl/http", "Golang net/http server")],
  "sw-access-01": [tcp(22, "ssh", "Cisco SSH", "2.0"), tcp(23, "telnet", "Cisco telnetd"), udp(161, "snmp")],
  "dns-01": [linuxSsh(), tcp(53, "domain", "ISC BIND", "9.18.24"), udp(53, "domain", "ISC BIND", "9.18.24")],
  "siem-collector": [linuxSsh(), tcp(514, "syslog"), tcp(443, "https", "nginx", "1.24.0")],
};

const hash = (s: string) => [...s].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7);

export function simulateHost(a: AssetRecord, plan: ScanPlan): HostResult {
  let svcs = BY_HOST[a.hostname] ?? BY_TYPE[a.type] ?? BY_TYPE.server;
  // a quarter of Windows workstations have RDP enabled (deterministic per host)
  if (a.type === "workstation" && !/mac/i.test(a.os ?? "") && hash(a.hostname) % 4 === 0) svcs = [...svcs, tcp(3389, "ms-wbt-server", "Microsoft Terminal Services")];
  if (a.type === "workstation" && /mac/i.test(a.os ?? "")) svcs = [tcp(5000, "rtsp", "AirTunes rtspd"), tcp(7000, "rtsp", "AirTunes rtspd")];
  const wanted = plan.type === "udp" ? "udp" : "tcp";
  const ports = plan.type === "host_discovery" ? [] : svcs
    .filter((s) => s.proto === wanted || (plan.type === "vuln_basic" && s.proto === "udp" && s.port === 161))
    .filter((s) => plan.portList.includes(s.port) || (plan.type === "network_discovery" && TOP_TCP.slice(0, 20).includes(s.port)))
    .map((s) => ({ ...s, state: "open" as const, ...(plan.type === "tcp" || plan.type === "udp" || plan.type === "network_discovery" ? { product: null, version: null } : {}) }));
  return { ip: a.ip, hostname: a.hostname, state: "up", os: a.os, ports, location: a.location };
}

export async function runSimulated(plan: ScanPlan, assets: AssetRecord[], onProgress: (pct: number) => void, signal: AbortSignal): Promise<HostResult[]> {
  const inRange = new Set(targetHosts(plan.targetInfo));
  const targets = assets.filter((a) => inRange.has(a.ip));
  const results: HostResult[] = [];
  // pacing: ~0.25–1.5 s per inventory host depending on intensity and port count, capped at 45 s total
  const perHost = Math.min(1500, (250 + plan.portList.length * 2) * (5 - plan.intensity) * 0.5);
  const total = Math.min(45_000, Math.max(1500, perHost * Math.max(1, targets.length)));
  const step = total / Math.max(1, targets.length);
  for (let i = 0; i < targets.length; i++) {
    if (signal.aborted) throw new Error("cancelled");
    await new Promise((r) => setTimeout(r, step));
    const a = targets[i];
    // offline or unmonitored-and-offline hosts do not answer
    results.push(a.online ? simulateHost(a, plan) : { ip: a.ip, hostname: a.hostname, state: "down", os: a.os, ports: [], location: a.location });
    onProgress(Math.round(((i + 1) / targets.length) * 99));
  }
  if (!targets.length) await new Promise((r) => setTimeout(r, 1200));
  return results;
}
