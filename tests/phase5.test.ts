import { test } from "node:test";
import assert from "node:assert/strict";
import { compactPorts, parsePorts, parseTarget, targetHosts, validateAllowlistCidr, validateScan, type ScanRequest } from "../src/server/scan/policy.ts";
import { nmapArgs, parseNmapXml } from "../src/server/scan/nmap.ts";
import { assess, versionTuple, type HostResult } from "../src/server/scan/checks.ts";
import { runSimulated, simulateHost } from "../src/server/scan/simulated.ts";
import { Telemetry, buildTopology } from "../src/server/telemetry.ts";
import { authInvestigate, authStats, firewallStats } from "../src/server/analytics.ts";
import { normalize } from "../src/server/normalize.ts";
import { ASSETS } from "../src/server/inventory.ts";
import type { AssetRecord } from "../src/server/repo.ts";
import type { SecurityEvent } from "../src/lib/types.ts";

const ALLOW = ["10.0.0.0/8"];
const req = (p: Partial<ScanRequest>): ScanRequest => ({ target: "10.20.0.0/24", ports: "top100", type: "tcp", intensity: 3, timeoutSec: 300, ...p });
const errs = (r: ReturnType<typeof validateScan>) => (r.ok ? [] : r.errors).join(" | ");

const assets: AssetRecord[] = ASSETS.map((a) => ({ ...a, mac: a.mac, os: a.os, location: a.location, owner: a.owner, notes: null, lastSeen: null, createdAt: 0, updatedAt: 0 }));

// ── scan policy ────────────────────────────────────────────────────────
test("policy accepts an allowlisted private /24", () => {
  const r = validateScan(req({}), ALLOW);
  assert.ok(r.ok, errs(r));
  if (r.ok) { assert.equal(r.plan.hosts, 254); assert.equal(r.plan.matchedAllowlist, "10.0.0.0/8"); }
});

test("policy rejects public, out-of-allowlist, reserved and oversized targets", () => {
  assert.match(errs(validateScan(req({ target: "8.8.8.8" }), ALLOW)), /Public IP/);
  assert.match(errs(validateScan(req({ target: "8.8.8.8" }), ["8.8.8.0/24"])), /Public IP/);
  assert.match(errs(validateScan(req({ target: "192.168.1.10" }), ALLOW)), /not inside any authorized allowlist/);
  assert.match(errs(validateScan(req({ target: "10.20.0.0/16" }), ALLOW)), /too large/);
  assert.match(errs(validateScan(req({ target: "127.0.0.1" }), ["127.0.0.0/8"])), /Loopback/);
  assert.match(errs(validateScan(req({ target: "scanme.example.org" }), ALLOW)), /IPv4 address or CIDR/);
  assert.match(errs(validateScan(req({}), [])), /allowlist is empty/);
  // a range straddling the allowlist boundary is rejected
  assert.match(errs(validateScan(req({ target: "10.20.0.0/23" }), ["10.20.0.0/24"])), /not inside/);
});

test("policy bounds work: ports, UDP, intensity, timeout", () => {
  assert.match(errs(validateScan(req({ ports: "1-65535" }), ALLOW)), /limited to 1,024 ports/);
  assert.ok(validateScan(req({ target: "10.20.0.30", ports: "1-65535" }), ALLOW).ok);
  assert.match(errs(validateScan(req({ type: "udp", ports: "1-200", target: "10.20.0.30" }), ALLOW)), /UDP scans are limited/);
  assert.match(errs(validateScan(req({ intensity: 5 }), ALLOW)), /Intensity/);
  assert.match(errs(validateScan(req({ timeoutSec: 5 }), ALLOW)), /Timeout/);
  assert.match(errs(validateScan(req({ ports: "22,abc" }), ALLOW)), /Invalid port token/);
});

test("allowlist entries must be private and at most /8", () => {
  assert.deepEqual(validateAllowlistCidr("10.20.0.7/16"), { ok: true, network: "10.20.0.0/16" });
  assert.equal(validateAllowlistCidr("0.0.0.0/0").ok, false);
  assert.equal(validateAllowlistCidr("52.0.0.0/8").ok, false);
  assert.equal(validateAllowlistCidr("52.0.0.0/8", { allowPublic: true }).ok, true);
});

test("target helpers", () => {
  const t = parseTarget("10.20.0.77/30");
  assert.ok(typeof t !== "string");
  if (typeof t !== "string") { assert.equal(t.network, "10.20.0.76/30"); assert.deepEqual(targetHosts(t), ["10.20.0.77", "10.20.0.78"]); }
  assert.equal(compactPorts([22, 80, 81, 82, 443]), "22,80-82,443");
  assert.deepEqual(parsePorts("443, 22,80-81", "tcp"), [22, 80, 81, 443]);
});

// ── nmap adapter ───────────────────────────────────────────────────────
test("nmap arguments are a fixed, non-intrusive set", () => {
  for (const type of ["host_discovery", "tcp", "udp", "service", "network_discovery", "vuln_basic"] as const) {
    const v = validateScan(req({ type, target: "10.20.0.30", ports: type === "udp" ? "53,161" : "22,80" }), ALLOW);
    assert.ok(v.ok, errs(v));
    if (!v.ok) continue;
    const args = nmapArgs(v.plan);
    const joined = args.join(" ");
    for (const banned of ["-sS", "-sI", "-D", "-S ", "-f", "--script", "-O", "-T5", "--spoof-mac", "--data-length", "-g "]) assert.ok(!joined.includes(banned), `${type}: ${banned} in ${joined}`);
    assert.equal(args.at(-1), "10.20.0.30/32");
    assert.ok(args.includes("-oX"));
  }
});

test("nmap XML parser extracts hosts, ports and services", () => {
  const xml = `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="10.20.0.30" addrtype="ipv4"/>
    <hostnames><hostname name="db-prod-01" type="PTR"/></hostnames><ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
    <port protocol="tcp" portid="5432"><state state="open"/><service name="postgresql" product="PostgreSQL DB" version="15.4"/></port></ports></host>
    <host><status state="down"/><address addr="10.20.0.31" addrtype="ipv4"/></host></nmaprun>`;
  const hosts = parseNmapXml(xml);
  assert.equal(hosts.length, 2);
  assert.equal(hosts[0].hostname, "db-prod-01");
  assert.deepEqual(hosts[0].ports[0], { port: 22, proto: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.6p1" });
  assert.equal(hosts[1].state, "down");
});

// ── vulnerability checks ───────────────────────────────────────────────
const host = (ports: HostResult["ports"], extra: Partial<HostResult> = {}): HostResult => ({ ip: "10.10.1.10", hostname: "h", state: "up", os: "Ubuntu 24.04", ports, ...extra });
const ssh = (version: string) => ({ port: 22, proto: "tcp" as const, state: "open" as const, service: "ssh", product: "OpenSSH", version });

test("version-based checks match only affected versions", () => {
  assert.deepEqual(versionTuple("9.6p1"), [9, 6, 1]);
  const ids = (h: HostResult) => assess([h]).map((f) => f.cve ?? f.checkId);
  assert.deepEqual(ids(host([ssh("9.6p1")])), ["CVE-2024-6387"]);
  assert.deepEqual(ids(host([ssh("8.5p1")])), ["CVE-2024-6387"]);
  assert.deepEqual(ids(host([ssh("9.8p1")])), []);
  assert.deepEqual(ids(host([ssh("8.4p1")])), []);
  const apache = (v: string) => host([{ port: 443, proto: "tcp", state: "open", service: "https", product: "Apache httpd", version: v }]);
  assert.deepEqual(ids(apache("2.4.49")), ["CVE-2021-41773"]);
  assert.deepEqual(ids(apache("2.4.50")), ["CVE-2021-42013"]);
  assert.deepEqual(ids(apache("2.4.58")), []);
  const ftp = (v: string) => host([{ port: 21, proto: "tcp", state: "open", service: "ftp", product: "vsftpd", version: v }]);
  assert.deepEqual(ids(ftp("2.3.4")), ["CVE-2011-2523"]);
  assert.deepEqual(ids(ftp("3.0.5")), ["ftp-cleartext"]);
  assert.deepEqual(ids(host([{ port: 445, proto: "tcp", state: "open", service: "microsoft-ds", product: null, version: null }], { location: "DMZ" })), ["smb-dmz"]);
  assert.deepEqual(ids(host([{ port: 445, proto: "tcp", state: "open", service: "microsoft-ds", product: null, version: null }], { location: "DC-East" })), []);
  assert.equal(assess([{ ...host([ssh("9.6p1")]), state: "down" }]).length, 0);
});

test("simulated engine reports only inventory hosts inside the target, honours ports and offline state", async () => {
  const v = validateScan(req({ target: "10.10.1.0/24", type: "vuln_basic" }), ALLOW);
  assert.ok(v.ok);
  if (!v.ok) return;
  const hosts = await runSimulated({ ...v.plan, intensity: 4 }, assets, () => {}, new AbortController().signal);
  const ips = hosts.map((h) => h.ip).sort();
  assert.deepEqual(ips, assets.filter((a) => a.ip.startsWith("10.10.1.")).map((a) => a.ip).sort());
  const findings = assess(hosts).map((f) => `${f.hostname}:${f.cve ?? f.checkId}`);
  assert.ok(findings.includes("web-01:CVE-2021-41773"));
  assert.ok(findings.includes("vpn-01:CVE-2024-6387"));
  assert.ok(findings.includes("mail-01:smb-dmz"));
  const onlyTcp22 = validateScan(req({ target: "10.10.1.10", ports: "22" }), ALLOW);
  if (onlyTcp22.ok) assert.deepEqual(simulateHost(assets.find((a) => a.hostname === "web-01")!, onlyTcp22.plan).ports.map((p) => p.port), [22]);
  const off = assets.find((a) => !a.online)!;
  const vOff = validateScan(req({ target: off.ip }), ALLOW);
  if (vOff.ok) assert.equal((await runSimulated(vOff.plan, assets, () => {}, new AbortController().signal))[0].state, "down");
});

// ── telemetry ──────────────────────────────────────────────────────────
test("topology is inferred from inventory and every device is connected", () => {
  const { nodes, links } = buildTopology(assets);
  assert.ok(nodes.find((n) => n.id === "internet"));
  const linked = new Set(links.flatMap((l) => [l.a, l.b]));
  for (const n of nodes) assert.ok(linked.has(n.id), `${n.label} not linked`);
  assert.ok(nodes.some((n) => n.role === "endpoints" && n.memberIps.length > 1));
});

test("link utilisation follows the flow bytes fed in", () => {
  const t = new Telemetry(assets);
  const now = Date.now();
  t.sample(now, new Map(), 0);
  t.sample(now + 5000, new Map(), 1_000);
  const quiet = t.health().busiestLinkUtil;
  // 80 MB external in 5 s × FLOW_SCALE ≈ 2.6 Gbit/s; the primary firewall carries 65 % → saturates its 1 Gbit WAN
  t.sample(now + 10_000, new Map(), 80_000_000);
  const h = t.health();
  assert.ok(quiet < 0.05, `quiet util ${quiet}`);
  assert.equal(h.busiestLinkUtil, 1);
  const fw = [...t.devices.values()].find((d) => t.nodes.find((n) => n.id === d.nodeId)?.role === "edge")!;
  assert.ok(fw.lossPct > 0, "saturated WAN should drop packets");
  const down = t.nodes.find((n) => n.assetIds.includes(assets.find((a) => !a.online && a.type !== "workstation")!.id))!;
  assert.equal(t.devices.get(down.id)!.status, "down");
});

// ── analytics ──────────────────────────────────────────────────────────
const T = Date.parse("2026-11-02T12:00:00Z");
const win = (o: Record<string, unknown>, i: number) => normalize({ format: "json", receivedAt: T, simulated: true, payload: { Channel: "Security", TimeCreated: new Date(T + i * 1000).toISOString(), Computer: "dc-01", ...o } });

test("auth analytics: success after failures, lockouts, external logins, investigation", () => {
  const evs: SecurityEvent[] = [];
  for (let i = 0; i < 8; i++) evs.push(win({ EventID: 4625, TargetUserName: "administrator", IpAddress: "203.0.113.17", LogonType: 10 }, i));
  evs.push(win({ EventID: 4624, TargetUserName: "administrator", IpAddress: "203.0.113.17", LogonType: 10 }, 9));
  evs.push(win({ EventID: 4740, TargetUserName: "svc_backup", IpAddress: "10.20.0.10" }, 10));
  evs.push(win({ EventID: 4624, TargetUserName: "j.chen", IpAddress: "10.30.0.101", LogonType: 3 }, 11));
  const s = authStats(evs, T - 1000, T + 60_000, T + 60_000);
  assert.equal(s.totals.failure, 8);
  assert.equal(s.totals.success, 2);
  assert.equal(s.totals.lockouts, 1);
  assert.equal(s.totals.rdp.failure, 8);
  assert.equal(s.compromise.length, 1);
  assert.equal(s.compromise[0].country, "Russia");
  assert.equal(s.locations[0].source, "203.0.113.17");
  assert.equal(s.sessions.length, 2);
  const inv = authInvestigate(evs, "user", "administrator");
  assert.equal(inv.summary.failures, 8);
  assert.ok(inv.findings.some((f) => f.severity === "critical"));
});

test("compromise detector ignores typo noise spread across accounts", () => {
  const evs: SecurityEvent[] = [];
  const users = ["a.morgan", "j.chen", "s.patel", "m.rossi", "k.nakamura", "l.garcia"];
  // internal workstation: 6 single typos for 6 different users, then a normal logon
  users.forEach((u, i) => evs.push(win({ EventID: 4625, TargetUserName: u, IpAddress: "10.30.0.109", LogonType: 3 }, i)));
  evs.push(win({ EventID: 4624, TargetUserName: "j.chen", IpAddress: "10.30.0.109", LogonType: 3 }, 10));
  assert.equal(authStats(evs, T - 1000, T + 60_000, T + 60_000).compromise.length, 0);
  // same workstation guessing one account five times, then getting in → flagged
  for (let i = 0; i < 5; i++) evs.push(win({ EventID: 4625, TargetUserName: "svc_backup", IpAddress: "10.30.0.109", LogonType: 3 }, 20 + i));
  evs.push(win({ EventID: 4624, TargetUserName: "svc_backup", IpAddress: "10.30.0.109", LogonType: 3 }, 30));
  const c = authStats(evs, T - 1000, T + 60_000, T + 60_000).compromise;
  assert.equal(c.length, 1);
  assert.equal(c[0].user, "svc_backup");
  // failures older than the 10-minute window do not count
  const old = [...Array.from({ length: 6 }, (_, i) => win({ EventID: 4625, TargetUserName: "root", IpAddress: "203.0.113.17", LogonType: 10 }, i)),
    win({ EventID: 4624, TargetUserName: "root", IpAddress: "203.0.113.17", LogonType: 10 }, 900)];
  assert.equal(authStats(old, T - 1000, T + 1_000_000, T + 1_000_000).compromise.length, 0);
});

test("firewall analytics: totals, filters and suspicious patterns", () => {
  const cef = (src: string, dpt: number, act: string, i: number, bytes = 60) => normalize({ format: "cef", receivedAt: T, simulated: true,
    payload: `CEF:0|Palo Alto Networks|PAN-OS|11.1|firewall_${act}|TRAFFIC ${act}|3|rt=${T + i * 100} src=${src} spt=40000 dst=10.10.1.10 dpt=${dpt} proto=TCP act=${act} cnt=1 in=${bytes} out=0` });
  const evs = [
    ...Array.from({ length: 30 }, (_, i) => cef("203.0.113.44", 1 + i, "deny", i)),
    ...Array.from({ length: 5 }, (_, i) => cef("10.30.0.110", 4444, "allow", 40 + i)),
  ].sort((a, b) => a.timestamp - b.timestamp);
  const all = firewallStats(evs, { from: T - 1000, to: T + 60_000 }, assets, null);
  assert.equal(all.totals.blocked, 30);
  assert.equal(all.totals.allowed, 5);
  const kinds = all.patterns.map((p) => p.kind);
  assert.ok(kinds.includes("repeated_block") && kinds.includes("port_sweep") && kinds.includes("c2_port"));
  assert.equal(all.patterns[0].kind, "c2_port"); // critical first
  const onlyAllowed = firewallStats(evs, { from: T - 1000, to: T + 60_000, action: "allow" }, assets, null);
  assert.equal(onlyAllowed.totals.events, 5);
  const byPort = firewallStats(evs, { from: T - 1000, to: T + 60_000, dport: "1..10" }, assets, null);
  assert.equal(byPort.totals.events, 10);
  assert.equal(all.devices[0].hostname, "fw-edge-01");
});
