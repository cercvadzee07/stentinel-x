import { test } from "node:test";
import assert from "node:assert/strict";
import { normalize, parseCef } from "../src/server/normalize.ts";
import { DEFAULT_RULES, RuleRuntime, backtest } from "../src/server/correlator.ts";
import { SCENARIOS } from "../src/server/simulator.ts";
import type { SecurityEvent } from "../src/lib/types.ts";

const T = Date.parse("2026-11-02T12:00:00Z");

test("CEF parsing handles escaped values", () => {
  const c = parseCef("CEF:0|Palo Alto Networks|PAN-OS|11.1|firewall_deny|TRAFFIC deny|3|src=203.0.113.17 dst=10.10.1.10 dpt=445 act=deny msg=a\\=b c");
  assert.equal(c.vendor, "Palo Alto Networks");
  assert.equal(c.ext.dpt, "445");
  assert.equal(c.ext.msg, "a=b c");
});

test("normalizes sshd syslog, Windows 4625 and ECS JSON", () => {
  const ssh = normalize({ format: "syslog", receivedAt: T, simulated: true,
    payload: `<38>1 2026-11-02T12:00:00.000Z web-01 sshd 2211 - - Failed password for invalid user admin from 203.0.113.17 port 52211 ssh2` });
  assert.equal(ssh.type, "ssh_login_failure");
  assert.equal(ssh.destinationIp, "10.10.1.10");
  assert.equal(ssh.direction, "inbound");
  assert.equal(ssh.username, "admin");

  const rdp = normalize({ format: "json", receivedAt: T, simulated: true,
    payload: { Channel: "Security", EventID: 4625, LogonType: 10, Computer: "jump-01", TargetUserName: "administrator", IpAddress: "198.51.100.23", TimeCreated: new Date(T).toISOString() } });
  assert.equal(rdp.type, "rdp_login_failure");
  assert.equal(rdp.destinationPort, 3389);

  const ecs = normalize({ format: "json", receivedAt: T, simulated: false,
    payload: { "@timestamp": new Date(T).toISOString(), event: { type: "dns_query", severity: "low" }, source: { ip: "10.30.0.101" }, destination: { ip: "10.20.0.53", port: 53 }, network: { protocol: "dns" }, dns: { question: { name: "example.org" } } } });
  assert.equal(ecs.type, "dns_query");
  assert.equal(ecs.dnsQuery, "example.org");
  assert.equal(ecs.simulated, false);

  assert.throws(() => normalize({ format: "json", receivedAt: T, simulated: false, payload: { event: { type: "nope" } } }));
});

function runScenario(id: string): SecurityEvent[] {
  const def = SCENARIOS.find((s) => s.id === id)!;
  const ctx = def.init();
  const out: SecurityEvent[] = [];
  const n = Math.ceil(def.duration * def.rate);
  for (let i = 0; i < n; i++) {
    const t = T + (i / def.rate) * 1000;
    const r = def.make(t, i / n, ctx);
    for (const env of Array.isArray(r) ? r : [r]) out.push(normalize(env));
  }
  return out;
}

const expectations: [string, string][] = [
  ["ssh_bruteforce", "R-001"], ["rdp_bruteforce", "R-002"], ["port_scan", "R-003"], ["ping_sweep", "R-004"],
  ["ddos", "R-005"], ["suspicious_port", "R-006"], ["password_spray", "R-007"], ["priv_esc", "R-008"],
  ["exfiltration", "R-009"], ["dns_tunnel", "R-010"],
];

for (const [scenario, ruleId] of expectations) {
  test(`scenario ${scenario} triggers ${ruleId}`, () => {
    const rule = DEFAULT_RULES.find((r) => r.id === ruleId)!;
    const res = backtest(rule, runScenario(scenario));
    assert.ok(res.hits.length >= 1, `${ruleId} produced no hit (matched ${res.matched}/${res.scanned})`);
  });
}

test("backtest merges a repeated attack from one source into one hit per burst", () => {
  const rule = DEFAULT_RULES.find((r) => r.id === "R-004")!;
  const first = runScenario("ping_sweep");
  const src = first[0].sourceIp;
  // same source sweeps again 10 minutes later
  const second = runScenario("ping_sweep").map((e) => ({ ...e, sourceIp: src, timestamp: e.timestamp + 600_000 }));
  const res = backtest(rule, [...first, ...second]);
  assert.equal(res.hits.length, 2);
});

test("rule runtime respects time window", () => {
  const rule = DEFAULT_RULES.find((r) => r.id === "R-001")!;
  const rt = new RuleRuntime(rule);
  const evs = runScenario("ssh_bruteforce");
  // spread the same events across 10 minutes → never 8 within 60s
  let hits = 0;
  evs.forEach((e, i) => { if (rt.push({ ...e, timestamp: T + i * 20_000 })) hits++; });
  assert.equal(hits, 0);
});
