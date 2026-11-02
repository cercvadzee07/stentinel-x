/**
 * Basic vulnerability assessment: NON-intrusive checks over discovered services
 * (port exposure + version banners). No exploit code, no NSE vuln scripts, no
 * authentication attempts. Version matches are "potential" findings that need
 * confirmation; banners can be backported or spoofed.
 */
import type { Severity } from "../../lib/types.ts";

export interface PortResult { port: number; proto: "tcp" | "udp"; state: "open" | "closed" | "filtered"; service: string | null; product: string | null; version: string | null }
export interface HostResult { ip: string; hostname: string | null; state: "up" | "down"; os: string | null; ports: PortResult[]; location?: string | null }

export interface Finding {
  checkId: string; title: string; severity: Severity; cvss: number | null; cve: string | null;
  port: number; proto: "tcp" | "udp"; service: string | null; evidence: string; remediation: string; references: string[];
}

/** "9.6p1" → [9, 6, 1]; "2.4.49" → [2, 4, 49] */
export function versionTuple(v: string | null): number[] | null {
  if (!v) return null;
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? m[4] ?? 0)] : null;
}
const cmp = (a: number[], b: number[]) => { for (let i = 0; i < 3; i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) - (b[i] ?? 0); return 0; };

interface Check { id: string; match: (p: PortResult, h: HostResult) => boolean; finding: (p: PortResult, h: HostResult) => Omit<Finding, "checkId" | "port" | "proto" | "service"> }

const NVD = (cve: string) => `https://nvd.nist.gov/vuln/detail/${cve}`;
const banner = (p: PortResult) => [p.product, p.version].filter(Boolean).join(" ") || p.service || "unknown service";

export const CHECKS: Check[] = [
  {
    id: "openssh-regresshion",
    match: (p) => /openssh/i.test(p.product ?? "") && (() => { const v = versionTuple(p.version); return !!v && cmp(v, [8, 5, 1]) >= 0 && cmp(v, [9, 8, 1]) < 0; })(),
    finding: (p, h) => ({
      title: "OpenSSH signal-handler race condition (regreSSHion)", severity: "high", cvss: 8.1, cve: "CVE-2024-6387",
      evidence: `Banner ${banner(p)} is in the affected range 8.5p1 – 9.8p1 (exclusive)${h.os && !/linux|ubuntu|debian|rhel|centos|flatcar/i.test(h.os) ? `; host OS "${h.os}" may not be glibc-based — confirm exposure` : ""}.`,
      remediation: "Upgrade OpenSSH to 9.8p1 or a vendor-patched build; as a stopgap set LoginGraceTime 0 (trades RCE risk for DoS risk).",
      references: [NVD("CVE-2024-6387")],
    }),
  },
  {
    id: "apache-path-traversal-41773",
    match: (p) => /apache httpd/i.test(p.product ?? "") && p.version?.trim() === "2.4.49",
    finding: (p) => ({
      title: "Apache HTTP Server 2.4.49 path traversal", severity: "high", cvss: 7.5, cve: "CVE-2021-41773",
      evidence: `Banner ${banner(p)}. Exploitable when require-all-denied is not set; leads to RCE if mod_cgi is enabled.`,
      remediation: "Upgrade Apache httpd to 2.4.51 or later.", references: [NVD("CVE-2021-41773")],
    }),
  },
  {
    id: "apache-path-traversal-42013",
    match: (p) => /apache httpd/i.test(p.product ?? "") && p.version?.trim() === "2.4.50",
    finding: (p) => ({
      title: "Apache HTTP Server 2.4.50 path traversal (incomplete fix)", severity: "critical", cvss: 9.8, cve: "CVE-2021-42013",
      evidence: `Banner ${banner(p)}.`, remediation: "Upgrade Apache httpd to 2.4.51 or later.", references: [NVD("CVE-2021-42013")],
    }),
  },
  {
    id: "vsftpd-234-backdoor",
    match: (p) => /vsftpd/i.test(p.product ?? "") && p.version?.trim() === "2.3.4",
    finding: (p) => ({
      title: "vsftpd 2.3.4 backdoored release", severity: "critical", cvss: 9.8, cve: "CVE-2011-2523",
      evidence: `Banner ${banner(p)}.`, remediation: "Replace with a current vsftpd build from a trusted source and investigate the host.", references: [NVD("CVE-2011-2523")],
    }),
  },
  {
    id: "docker-api-unauthenticated",
    match: (p) => p.port === 2375 && p.proto === "tcp",
    finding: (p) => ({
      title: "Docker Engine API exposed without TLS", severity: "critical", cvss: null, cve: null,
      evidence: `tcp/2375 open (${banner(p)}). The plaintext Docker API grants root-equivalent control of the host.`,
      remediation: "Bind the daemon to a Unix socket, or require mutual TLS on tcp/2376; firewall the port.", references: ["https://docs.docker.com/engine/security/protect-access/"],
    }),
  },
  {
    id: "telnet-exposed",
    match: (p) => p.port === 23 && p.proto === "tcp",
    finding: (p) => ({
      title: "Telnet management service enabled", severity: "high", cvss: null, cve: null,
      evidence: `tcp/23 open (${banner(p)}); credentials cross the network in cleartext.`, remediation: "Disable Telnet and use SSH for device management.", references: [],
    }),
  },
  {
    id: "ftp-cleartext",
    // the backdoored vsftpd build is reported by its own check instead
    match: (p) => p.port === 21 && p.proto === "tcp" && !(/vsftpd/i.test(p.product ?? "") && p.version?.trim() === "2.3.4"),
    finding: (p) => ({
      title: "Cleartext FTP service", severity: "medium", cvss: null, cve: null,
      evidence: `tcp/21 open (${banner(p)}).`, remediation: "Replace FTP with SFTP/FTPS or restrict it to a management network.", references: [],
    }),
  },
  {
    id: "redis-exposed",
    match: (p) => p.port === 6379 && p.proto === "tcp",
    finding: (p) => ({
      title: "Redis reachable on the network", severity: "high", cvss: null, cve: null,
      evidence: `tcp/6379 open (${banner(p)}). Redis is frequently deployed without authentication.`, remediation: "Bind to localhost or a private interface, enable ACLs/requirepass, enable protected-mode.", references: [],
    }),
  },
  {
    id: "datastore-exposed",
    match: (p) => (p.port === 9200 || p.port === 27017) && p.proto === "tcp",
    finding: (p) => ({
      title: p.port === 9200 ? "Elasticsearch HTTP API reachable" : "MongoDB reachable", severity: "high", cvss: null, cve: null,
      evidence: `tcp/${p.port} open (${banner(p)}).`, remediation: "Require authentication and restrict network access to application hosts.", references: [],
    }),
  },
  {
    id: "rdp-exposed",
    match: (p) => p.port === 3389 && p.proto === "tcp",
    finding: (p) => ({
      title: "Remote Desktop reachable", severity: "medium", cvss: null, cve: null,
      evidence: `tcp/3389 open (${banner(p)}). RDP is a top brute-force and ransomware entry point.`, remediation: "Require NLA and MFA, restrict to a jump host or VPN, monitor failed logons.", references: [],
    }),
  },
  {
    id: "smb-dmz",
    match: (p, h) => p.port === 445 && /dmz/i.test(h.location ?? ""),
    finding: (p) => ({
      title: "SMB exposed on a DMZ host", severity: "high", cvss: null, cve: null,
      evidence: `tcp/445 open (${banner(p)}) on a perimeter host.`, remediation: "Block SMB at the DMZ boundary.", references: [],
    }),
  },
  {
    id: "snmp-exposed",
    match: (p) => p.port === 161 && p.proto === "udp",
    finding: (p) => ({
      title: "SNMP service reachable", severity: "low", cvss: null, cve: null,
      evidence: `udp/161 open (${banner(p)}).`, remediation: "Use SNMPv3 with authPriv; remove default community strings; restrict to the NMS.", references: [],
    }),
  },
];

export function assess(hosts: HostResult[]): (Finding & { ip: string; hostname: string | null })[] {
  const out: (Finding & { ip: string; hostname: string | null })[] = [];
  for (const h of hosts) {
    if (h.state !== "up") continue;
    for (const p of h.ports) {
      if (p.state !== "open") continue;
      for (const c of CHECKS) if (c.match(p, h)) out.push({ ...c.finding(p, h), checkId: c.id, port: p.port, proto: p.proto, service: p.service, ip: h.ip, hostname: h.hostname });
    }
  }
  return out;
}
