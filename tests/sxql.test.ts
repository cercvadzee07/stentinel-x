import { test } from "node:test";
import assert from "node:assert/strict";
import { check, compile, inCidr, parse } from "../src/lib/sxql.ts";
import type { SecurityEvent } from "../src/lib/types.ts";

const ev = (p: Partial<SecurityEvent>): SecurityEvent => ({
  id: "x", timestamp: 0, eventId: "EVT-1", type: "firewall_deny", category: "network", severity: "low",
  sourceIp: "192.168.1.10", sourcePort: 5000, destinationIp: "10.10.1.10", destinationPort: 22, protocol: "tcp",
  direction: "internal", sourceHost: null, destinationHost: "web-01", username: null, application: null,
  vendor: "Palo Alto Networks", product: "PAN-OS", action: "deny", outcome: "failure", count: 1, bytes: 60,
  dnsQuery: null, message: "TRAFFIC deny", simulated: true, scenario: null, rawFormat: "cef", raw: "", ...p,
});

test("field equality and AND/OR", () => {
  assert.ok(compile("source.ip:192.168.1.10")(ev({})));
  assert.ok(!compile("source.ip:192.168.1.11")(ev({})));
  assert.ok(compile("destination.port:22 AND event.outcome:failure")(ev({})));
  assert.ok(compile("destination.port:3389 OR destination.port:22")(ev({})));
  assert.ok(!compile("destination.port:3389 AND event.outcome")(ev({})));
});

test("bare fields mean exists", () => {
  assert.ok(compile("event.category AND event.severity")(ev({})));
  assert.ok(!compile("user.name")(ev({})));
  assert.ok(compile("network.protocol")(ev({})));
});

test("severity comparison, CIDR, ranges, wildcard, NOT, groups", () => {
  assert.ok(compile("event.severity>=low")(ev({})));
  assert.ok(!compile("event.severity>=high")(ev({})));
  assert.ok(compile("source.ip:192.168.0.0/16")(ev({})));
  assert.ok(!compile("source.ip:10.0.0.0/8")(ev({})));
  assert.ok(compile("destination.port:1..1024")(ev({})));
  assert.ok(compile("observer.vendor:palo*")(ev({})));
  assert.ok(compile("NOT network.protocol:udp")(ev({})));
  assert.ok(compile("-network.protocol:udp")(ev({})));
  assert.ok(compile('(destination.port:80 OR destination.port:22) AND message:"traffic deny"')(ev({})));
  assert.ok(compile("web-01")(ev({})));
});

test("errors are positioned", () => {
  const r = check("source.ip:1.2.3.4 AND (destination.port:22");
  assert.equal(r.ok, false);
  assert.equal(check("bogus.field:1").ok, false);
  assert.equal(check("source.ip>5").ok, false);
  assert.deepEqual(parse(""), { kind: "all" });
});

test("cidr helper", () => {
  assert.ok(inCidr("10.20.0.30", "10.20.0.0/24"));
  assert.ok(!inCidr("10.20.1.30", "10.20.0.0/24"));
  assert.ok(inCidr("8.8.8.8", "0.0.0.0/0"));
});
