/**
 * Sliding-window correlation engine.
 *
 * For every enabled rule: events matching rule.logic.filter are bucketed by
 * the groupBy key; each bucket keeps the events inside windowSec. When the
 * aggregate (count of event.count, distinct field values, or summed bytes)
 * reaches the threshold, a Detection is emitted. Windows use event
 * timestamps, so the same code powers live detection and historical backtests.
 */
import { readField } from "../lib/fields.ts";
import { compile } from "../lib/sxql.ts";
import type { DetectionRule, RuleLogic, SecurityEvent } from "../lib/types.ts";

export interface Detection {
  rule: DetectionRule;
  groupKey: string;
  value: number;
  events: SecurityEvent[];
  trigger: SecurityEvent;
}

interface Bucket { items: SecurityEvent[] }

export class RuleRuntime {
  readonly pred: (e: SecurityEvent) => boolean;
  readonly rule: DetectionRule;
  private buckets = new Map<string, Bucket>();

  constructor(rule: DetectionRule) {
    this.rule = rule;
    this.pred = compile(rule.logic.filter);
  }

  key(e: SecurityEvent) {
    return this.rule.logic.groupBy.map((f) => String(readField(e, f) ?? "∅")).join(" | ");
  }

  /** Feed one event; returns a detection when the bucket is at/over threshold. */
  push(e: SecurityEvent): Detection | null {
    if (!this.pred(e)) return null;
    const L = this.rule.logic;
    const k = this.key(e);
    let b = this.buckets.get(k);
    if (!b) this.buckets.set(k, (b = { items: [] }));
    b.items.push(e);
    const cutoff = e.timestamp - L.windowSec * 1000;
    let drop = 0;
    while (drop < b.items.length && b.items[drop].timestamp < cutoff) drop++;
    if (drop) b.items.splice(0, drop);
    if (b.items.length > 2000) b.items.splice(0, b.items.length - 2000);
    const value = aggregate(L, b.items);
    if (value < L.threshold) return null;
    return { rule: this.rule, groupKey: k, value, events: b.items.slice(), trigger: e };
  }

  /** Garbage-collect buckets idle for longer than the window. */
  sweep(now: number) {
    const cutoff = now - this.rule.logic.windowSec * 1000;
    for (const [k, b] of this.buckets) if (!b.items.length || b.items[b.items.length - 1].timestamp < cutoff) this.buckets.delete(k);
  }
}

export function aggregate(L: RuleLogic, items: SecurityEvent[]): number {
  switch (L.aggregate) {
    case "distinct": {
      const s = new Set<unknown>();
      for (const e of items) s.add(readField(e, L.distinctField ?? "destination.port"));
      return s.size;
    }
    case "sum_bytes": return items.reduce((n, e) => n + e.bytes, 0);
    default: return items.reduce((n, e) => n + e.count, 0);
  }
}

export interface BacktestHit { groupKey: string; firstSeen: number; lastSeen: number; value: number; eventCount: number; sampleIds: string[] }

/** Replay a rule over historical events (ascending time) with fresh state. */
export function backtest(rule: DetectionRule, events: SecurityEvent[]) {
  const t0 = performance.now();
  const rt = new RuleRuntime(rule);
  const latest = new Map<string, BacktestHit>();
  const hits: BacktestHit[] = [];
  let matched = 0;
  for (const e of events) {
    if (rt.pred(e)) matched++;
    const d = rt.push(e);
    if (!d) continue;
    const h = latest.get(d.groupKey);
    // A new hit starts when the previous one for this key went quiet for a full window
    if (h && e.timestamp - h.lastSeen <= rule.logic.windowSec * 1000) {
      h.lastSeen = e.timestamp; h.value = Math.max(h.value, d.value); h.eventCount++;
      if (h.sampleIds.length < 20) h.sampleIds.push(e.id);
    } else {
      const hit = {
        groupKey: d.groupKey, firstSeen: d.events[0].timestamp, lastSeen: e.timestamp, value: d.value,
        eventCount: d.events.length, sampleIds: d.events.slice(-20).map((x) => x.id),
      };
      latest.set(d.groupKey, hit);
      hits.push(hit);
    }
  }
  return { scanned: events.length, matched, hits: hits.sort((a, b) => b.lastSeen - a.lastSeen), tookMs: performance.now() - t0 };
}

const now = Date.now();
const r = (id: string, name: string, description: string, logic: RuleLogic, severity: DetectionRule["severity"], mitre: string[]): DetectionRule =>
  ({ id, name, description, logic, severity, mitre, enabled: true, builtin: true, triggerCount: 0, lastTriggered: null, createdAt: now, updatedAt: now });

export const DEFAULT_RULES: DetectionRule[] = [
  r("R-001", "SSH Brute Force", "Multiple failed SSH logins from the same source IP.",
    { filter: "event.type:ssh_login_failure", groupBy: ["source.ip"], aggregate: "count", threshold: 8, windowSec: 60 }, "high", ["T1110.001 Password Guessing"]),
  r("R-002", "RDP Brute Force", "Repeated failed RDP (LogonType 10) authentications from one source.",
    { filter: "event.type:rdp_login_failure", groupBy: ["source.ip"], aggregate: "count", threshold: 6, windowSec: 60 }, "high", ["T1110.001 Password Guessing", "T1021.001 Remote Desktop Protocol"]),
  r("R-003", "Port Scan", "One source contacting many distinct destination ports on a host.",
    { filter: "network.protocol:tcp", groupBy: ["source.ip", "destination.ip"], aggregate: "distinct", distinctField: "destination.port", threshold: 25, windowSec: 30 }, "medium", ["T1046 Network Service Discovery"]),
  r("R-004", "Ping Sweep", "One source sending ICMP to many internal addresses.",
    { filter: "network.protocol:icmp AND destination.ip:10.0.0.0/8", groupBy: ["source.ip"], aggregate: "distinct", distinctField: "destination.ip", threshold: 15, windowSec: 30 }, "medium", ["T1018 Remote System Discovery"]),
  r("R-005", "DDoS Detection", "Unusually high inbound flow rate targeting one destination.",
    { filter: "network.direction:inbound", groupBy: ["destination.ip"], aggregate: "count", threshold: 2000, windowSec: 10 }, "critical", ["T1498 Network Denial of Service"]),
  r("R-006", "Suspicious Port Traffic", "High traffic volume towards ports associated with C2 / backdoors.",
    { filter: "destination.port:4444 OR destination.port:6667 OR destination.port:31337 OR destination.port:1337 OR destination.port:5555", groupBy: ["source.ip"], aggregate: "sum_bytes", threshold: 5_000_000, windowSec: 60 }, "high", ["T1571 Non-Standard Port"]),
  r("R-007", "Multiple Failed Logins", "Repeated authentication failures against one account.",
    { filter: "event.category:authentication AND event.outcome:failure", groupBy: ["user.name"], aggregate: "count", threshold: 10, windowSec: 120 }, "medium", ["T1110 Brute Force"]),
  r("R-008", "Privilege Escalation", "High-severity privilege change: privileged group membership or root shell.",
    { filter: "event.type:privilege_escalation AND event.severity>=high", groupBy: ["destination.host", "user.name"], aggregate: "count", threshold: 1, windowSec: 300 }, "high", ["T1068 Exploitation for Privilege Escalation", "T1098 Account Manipulation"]),
  r("R-009", "Unusual Data Transfer", "Abnormal outbound byte volume from a single host.",
    { filter: "network.direction:outbound", groupBy: ["source.ip"], aggregate: "sum_bytes", threshold: 50_000_000, windowSec: 60 }, "critical", ["T1048 Exfiltration Over Alternative Protocol"]),
  r("R-010", "Suspicious DNS Activity", "Many distinct DNS names requested by one host (tunneling / DGA).",
    { filter: "network.protocol:dns", groupBy: ["source.ip"], aggregate: "distinct", distinctField: "dns.question.name", threshold: 30, windowSec: 60 }, "high", ["T1071.004 DNS", "T1568.002 Domain Generation Algorithms"]),
];
