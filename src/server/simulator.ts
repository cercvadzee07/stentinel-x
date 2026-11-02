/**
 * Event simulator. Produces RAW vendor payloads (CEF, RFC 5424 syslog,
 * Windows Security JSON) — never pre-normalized events — so simulated data
 * exercises the real normalization and correlation pipeline.
 * All output is flagged simulated=true.
 */
import type { RawEnvelope } from "./normalize.ts";
import { ASSETS, DOMAINS, EXTERNAL_ACTORS, SERVERS, USERS, WORKSTATIONS } from "./inventory.ts";

const rnd = (n: number) => Math.floor(Math.random() * n);
const pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)];
const eph = () => 49152 + rnd(16383);
const host = (name: string) => ASSETS.find((x) => x.hostname === name)!;
const DMZ = ASSETS.filter((x) => x.location === "DMZ");

const esc = (v: string | number) => String(v).replace(/\\/g, "\\\\").replace(/=/g, "\\=");
function cef(vendor: string, product: string, ver: string, sig: string, name: string, sev: number, ext: Record<string, string | number | null | undefined>) {
  const e = Object.entries(ext).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => `${k}=${esc(v!)}`).join(" ");
  return `CEF:0|${vendor}|${product}|${ver}|${sig}|${name}|${sev}|${e}`;
}
const PAN = ["Palo Alto Networks", "PAN-OS", "11.1"] as const;
const FORTI = ["Fortinet", "FortiGate", "7.4"] as const;
const SURICATA = ["OISF", "Suricata", "7.0"] as const;
const FALCON = ["CrowdStrike", "Falcon", "7.10"] as const;
const ZEEK = ["Zeek", "Zeek", "6.2"] as const;
const BIND = ["ISC", "BIND", "9.18"] as const;

type Mk = (t: number) => RawEnvelope;
const env = (t: number, format: RawEnvelope["format"], payload: RawEnvelope["payload"], scenario: string | null = null): RawEnvelope =>
  ({ format, payload, receivedAt: t, simulated: true, scenario });

const sshLine = (t: number, hostname: string, msg: string) =>
  `<38>1 ${new Date(t).toISOString()} ${hostname} sshd ${1000 + rnd(30000)} - - ${msg}`;
const winEvent = (t: number, o: Record<string, unknown>) => ({ Channel: "Security", TimeCreated: new Date(t).toISOString(), ...o });

/** Each workstation belongs to one employee: routine logons and typos come from the owner's own machine. */
const ownerOf = (ws: { ip: string }) => USERS[Number(ws.ip.split(".")[3]) % 10];

// ── background traffic ───────────────────────────────────────────────────
const WEB_APPS = ["ssl", "web-browsing", "office365", "github", "slack", "zoom", "ms-update", "dns-over-https"];
const DENY_PORTS = [21, 23, 25, 110, 135, 139, 161, 445, 1433, 1521, 2375, 3306, 5060, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017];

const background: [number, Mk][] = [
  [38, (t) => { // outbound web
    const src = pick([...WORKSTATIONS, ...SERVERS]); const dst = pick(EXTERNAL_ACTORS);
    const [v, p, ver] = pick([PAN, FORTI]);
    return env(t, "cef", cef(v, p, ver, "firewall_allow", "TRAFFIC allow", 1, { rt: t, src: src.ip, spt: eph(), dst: dst.ip, dpt: pick([443, 443, 443, 80]),
      proto: "TCP", act: "allow", app: pick(WEB_APPS), shost: src.hostname, cnt: 1, in: 400 + rnd(9000), out: 2000 + rnd(120000) }));
  }],
  [10, (t) => { // inbound to DMZ
    const src = pick(EXTERNAL_ACTORS); const dst = pick(DMZ);
    return env(t, "cef", cef(...PAN, "firewall_allow", "TRAFFIC allow", 1, { rt: t, src: src.ip, spt: eph(), dst: dst.ip, dpt: 443, proto: "TCP",
      act: "allow", app: "ssl", dhost: dst.hostname, cnt: 1, in: 800 + rnd(4000), out: 2000 + rnd(40000) }));
  }],
  [14, (t) => { // inbound denies
    const src = pick(EXTERNAL_ACTORS); const dst = pick(DMZ);
    const [v, p, ver] = pick([PAN, FORTI]);
    return env(t, "cef", cef(v, p, ver, "firewall_deny", "TRAFFIC deny", 3, { rt: t, src: src.ip, spt: eph(), dst: dst.ip, dpt: pick(DENY_PORTS),
      proto: pick(["TCP", "TCP", "UDP"]), act: "deny", dhost: dst.hostname, cnt: 1, in: 60, out: 0 }));
  }],
  [18, (t) => { // dns
    const src = pick(WORKSTATIONS); const dns = host("dns-01");
    return env(t, "cef", cef(...BIND, "dns_query", "DNS query", 0, { rt: t, src: src.ip, spt: eph(), dst: dns.ip, dpt: 53, proto: "DNS", act: "query",
      shost: src.hostname, cs1Label: "dnsQuery", cs1: pick(DOMAINS), in: 64, out: 180 }));
  }],
  [5, (t) => { // windows logon success
    const ws = pick(WORKSTATIONS);
    return env(t, "json", winEvent(t, { EventID: 4624, Computer: pick(["dc-01", "dc-02", "files-01"]), TargetUserName: ownerOf(ws),
      IpAddress: ws.ip, IpPort: eph(), LogonType: 3 }));
  }],
  [2, (t) => { // ssh success
    const s = pick(SERVERS.filter((x) => !x.os.startsWith("Windows")));
    return env(t, "syslog", sshLine(t, s.hostname, `Accepted publickey for ${pick(["svc_deploy", "j.chen", "t.berg"])} from ${pick(WORKSTATIONS).ip} port ${eph()} ssh2`));
  }],
  [0.08, (t) => { // occasional typo'd password (~1 per user per 10 min)
    const ws = pick(WORKSTATIONS);
    return env(t, "json", winEvent(t, { EventID: 4625, Computer: pick(["dc-01", "dc-02"]), TargetUserName: ownerOf(ws), IpAddress: ws.ip, IpPort: eph(), LogonType: 3 }));
  }],
  [0.5, (t) => env(t, "syslog", sshLine(t, pick(["web-01", "web-02", "vpn-01"]), `Failed password for invalid user ${pick(USERS)} from ${pick(EXTERNAL_ACTORS).ip} port ${eph()} ssh2`))],
  [1.5, (t) => { // IDS
    const src = pick(EXTERNAL_ACTORS); const dst = pick(DMZ);
    const sig = pick(["ET SCAN Suspicious inbound to MSSQL port 1433", "ET WEB_SERVER Possible SQL Injection Attempt", "ET POLICY curl User-Agent Outbound", "GPL ATTACK_RESPONSE id check returned root"]);
    return env(t, "cef", cef(...SURICATA, "ids_alert", sig, 6 + rnd(3), { rt: t, src: src.ip, spt: eph(), dst: dst.ip, dpt: pick([80, 443, 1433]), proto: "TCP", act: "alert", msg: sig }));
  }],
  [0.4, (t) => {
    const ws = pick(WORKSTATIONS);
    const what = pick(["Suspicious PowerShell command line", "Credential dumping tool pattern blocked", "Unsigned driver load attempt"]);
    return env(t, "cef", cef(...FALCON, "endpoint_alert", what, 7, { rt: t, src: ws.ip, dst: ws.ip, shost: ws.hostname, suser: pick(USERS.slice(0, 10)),
      app: pick(["powershell.exe", "rundll32.exe", "wmic.exe"]), act: "block", msg: what }));
  }],
  [0.15, (t) => {
    const ws = pick(WORKSTATIONS);
    return env(t, "cef", cef(...FALCON, "malware_detection", "Malware quarantined", 9, { rt: t, src: ws.ip, dst: ws.ip, shost: ws.hostname, suser: pick(USERS.slice(0, 10)),
      app: pick(["invoice_2026.pdf.exe", "setup_crack.exe", "update.js"]), act: "quarantine", msg: "Trojan:Win32/AgentTesla quarantined" }));
  }],
  [0.5, (t) => {
    const s = pick(SERVERS);
    return env(t, "cef", cef(...ZEEK, "unusual_network_activity", "Long-lived connection", 4, { rt: t, src: s.ip, spt: eph(), dst: pick(EXTERNAL_ACTORS).ip, dpt: pick([443, 8443, 22]),
      proto: "TCP", act: "alert", in: 2000, out: 9000 + rnd(30000), msg: "Connection open > 6h with periodic beacons" }));
  }],
  [0.6, (t) => env(t, "json", winEvent(t, { EventID: 4672, Computer: pick(["dc-01", "jump-01"]), TargetUserName: pick(["svc_backup", "administrator"]), IpAddress: "10.20.0.50", LogonType: 3 }))],
];
const BG_TOTAL = background.reduce((s, [w]) => s + w, 0);

export function backgroundEvent(t: number): RawEnvelope {
  let r = Math.random() * BG_TOTAL;
  for (const [w, mk] of background) { if ((r -= w) <= 0) return mk(t); }
  return background[0][1](t);
}

// ── attack scenarios ─────────────────────────────────────────────────────
export interface ScenarioDef {
  id: string;
  name: string;
  description: string;
  duration: number;
  /** events per second while active */
  rate: number;
  /** progress 0..1 → raw event; ctx is fixed for one run */
  make: (t: number, progress: number, ctx: Record<string, any>) => RawEnvelope | RawEnvelope[];
  init: () => Record<string, any>;
}

export const SCENARIOS: ScenarioDef[] = [
  {
    id: "ssh_bruteforce", name: "SSH brute force", description: "External actor guesses SSH passwords on a DMZ host, then succeeds.",
    duration: 25, rate: 6,
    init: () => ({ attacker: pick(EXTERNAL_ACTORS).ip, target: pick(["web-01", "vpn-01", "web-02"]), done: false }),
    make: (t, p, c) => {
      if (p > 0.95 && !c.done) { c.done = true; return env(t, "syslog", sshLine(t, c.target, `Accepted password for root from ${c.attacker} port ${eph()} ssh2`), "ssh_bruteforce"); }
      return env(t, "syslog", sshLine(t, c.target, `Failed password for ${p > 0.5 ? "root" : `invalid user ${pick(USERS)}`} from ${c.attacker} port ${eph()} ssh2`), "ssh_bruteforce");
    },
  },
  {
    id: "rdp_bruteforce", name: "RDP brute force", description: "Repeated RDP (LogonType 10) failures against the jump host.",
    duration: 25, rate: 4,
    init: () => ({ attacker: pick(EXTERNAL_ACTORS).ip }),
    make: (t, _p, c) => env(t, "json", winEvent(t, { EventID: 4625, Computer: "jump-01", TargetUserName: pick(["administrator", "admin", "svc_backup", "m.rossi"]),
      IpAddress: c.attacker, IpPort: eph(), LogonType: 10 }), "rdp_bruteforce"),
  },
  {
    id: "port_scan", name: "Port scan", description: "Single source walks the port range of a DMZ server.",
    duration: 10, rate: 40,
    init: () => ({ attacker: pick(EXTERNAL_ACTORS).ip, target: pick(DMZ), port: 1 }),
    make: (t, _p, c) => {
      const port = c.port++;
      const out: RawEnvelope[] = [env(t, "cef", cef(...PAN, "firewall_deny", "TRAFFIC deny", 3, { rt: t, src: c.attacker, spt: 40000 + (port % 1000), dst: c.target.ip,
        dpt: port, proto: "TCP", act: "deny", dhost: c.target.hostname, cnt: 1, in: 44, out: 0 }), "port_scan")];
      if (port === 30) out.push(env(t, "cef", cef(...SURICATA, "port_scan", "ET SCAN Nmap -sS SYN scan", 7, { rt: t, src: c.attacker, dst: c.target.ip, proto: "TCP", act: "alert", msg: "ET SCAN Nmap -sS SYN scan" }), "port_scan"));
      return out;
    },
  },
  {
    id: "ping_sweep", name: "Ping sweep", description: "Compromised workstation ICMP-sweeps the server subnet.",
    duration: 12, rate: 15,
    init: () => ({ src: pick(WORKSTATIONS), i: 1 }),
    make: (t, _p, c) => {
      const ip = `10.20.0.${c.i++ % 254 + 1}`;
      return env(t, "cef", cef(...FORTI, "firewall_allow", "ICMP echo", 1, { rt: t, src: c.src.ip, dst: ip, proto: "ICMP", act: "allow", shost: c.src.hostname, cnt: 1, in: 84, out: 84 }), "ping_sweep");
    },
  },
  {
    id: "ddos", name: "DDoS (volumetric)", description: "Many sources flood the public API gateway with aggregated flows.",
    duration: 20, rate: 30,
    init: () => ({ target: host("api-gw-01"), flagged: false }),
    make: (t, p, c) => {
      const src = pick(EXTERNAL_ACTORS);
      const out = [env(t, "cef", cef(...PAN, "firewall_allow", "TRAFFIC allow", 2, { rt: t, src: src.ip, spt: eph(), dst: c.target.ip, dpt: 443, proto: pick(["TCP", "UDP"]),
        act: "allow", dhost: c.target.hostname, cnt: 60 + rnd(140), in: 250000 + rnd(450000), out: 1000 }), "ddos")];
      if (p > 0.3 && !c.flagged) { c.flagged = true; out.push(env(t, "cef", cef(...SURICATA, "ddos", "Volumetric flood detected", 10, { rt: t, src: src.ip, dst: c.target.ip, dpt: 443, proto: "UDP", act: "alert", msg: "SYN/UDP flood threshold exceeded" }), "ddos")); }
      return out;
    },
  },
  {
    id: "suspicious_port", name: "C2 on suspicious port", description: "Workstation beacons to a known-bad port (4444).",
    duration: 20, rate: 4,
    init: () => ({ src: pick(WORKSTATIONS), dst: pick(EXTERNAL_ACTORS).ip, port: pick([4444, 6667, 31337]) }),
    make: (t, _p, c) => env(t, "cef", cef(...PAN, "suspicious_port_traffic", "TRAFFIC allow", 6, { rt: t, src: c.src.ip, spt: eph(), dst: c.dst, dpt: c.port, proto: "TCP",
      act: "allow", shost: c.src.hostname, app: "unknown-tcp", cnt: 1, in: 2000, out: 200000 + rnd(400000) }), "suspicious_port"),
  },
  {
    id: "exfiltration", name: "Data exfiltration", description: "Database server pushes large volumes to an external host.",
    duration: 25, rate: 3,
    init: () => ({ src: host("db-prod-02"), dst: pick(EXTERNAL_ACTORS).ip }),
    make: (t, _p, c) => env(t, "cef", cef(...FORTI, "unusual_network_activity", "Large outbound transfer", 5, { rt: t, src: c.src.ip, spt: eph(), dst: c.dst, dpt: 443, proto: "TCP",
      act: "allow", shost: c.src.hostname, app: "ssl", cnt: 1, in: 20000, out: 3_000_000 + rnd(5_000_000), msg: "Outbound session exceeds byte baseline" }), "exfiltration"),
  },
  {
    id: "dns_tunnel", name: "DNS tunneling", description: "High-entropy subdomain queries to one domain.",
    duration: 15, rate: 12,
    init: () => ({ src: pick(WORKSTATIONS), flagged: false }),
    make: (t, p, c) => {
      const label = Array.from({ length: 24 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[rnd(36)]).join("");
      const out = [env(t, "cef", cef(...BIND, "dns_query", "DNS query", 1, { rt: t, src: c.src.ip, spt: eph(), dst: host("dns-01").ip, dpt: 53, proto: "DNS", act: "query",
        shost: c.src.hostname, cs1Label: "dnsQuery", cs1: `${label}.x7f3k.tunnel.example`, in: 64, out: 220 }), "dns_tunnel")];
      if (p > 0.5 && !c.flagged) { c.flagged = true; out.push(env(t, "cef", cef(...ZEEK, "suspicious_dns", "High-entropy DNS labels", 6, { rt: t, src: c.src.ip, dst: host("dns-01").ip, dpt: 53, proto: "DNS", act: "alert", cs1Label: "dnsQuery", cs1: "x7f3k.tunnel.example", msg: "Entropy 4.6 bits/char over 50 queries" }), "dns_tunnel")); }
      return out;
    },
  },
  {
    id: "priv_esc", name: "Privilege escalation", description: "User added to Domain Admins, root shell via sudo.",
    duration: 6, rate: 0.5,
    init: () => ({ i: 0, user: pick(USERS.slice(0, 10)) }),
    make: (t, _p, c) => (c.i++ % 2 === 0
      ? env(t, "json", winEvent(t, { EventID: 4728, Computer: "dc-01", TargetUserName: c.user, IpAddress: "10.20.0.50", LogonType: 3 }), "priv_esc")
      : env(t, "syslog", `<86>1 ${new Date(t).toISOString()} web-01 sudo - - - ${c.user} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i`, "priv_esc")),
  },
  {
    id: "password_spray", name: "Account lockout storm", description: "Repeated failures against one privileged account from several hosts.",
    duration: 15, rate: 2,
    init: () => ({ user: pick(["administrator", "svc_backup"]), locked: false }),
    make: (t, p, c) => {
      const fail = env(t, "json", winEvent(t, { EventID: 4625, Computer: "dc-01", TargetUserName: c.user, IpAddress: pick(WORKSTATIONS).ip, IpPort: eph(), LogonType: 3 }), "password_spray");
      if (p < 0.8 || c.locked) return fail;
      c.locked = true;
      return [fail, env(t, "json", winEvent(t, { EventID: 4740, Computer: "dc-01", TargetUserName: c.user, IpAddress: "10.20.0.10" }), "password_spray")];
    },
  },
];
export const SCENARIO_BY_ID = new Map(SCENARIOS.map((s) => [s.id, s]));
