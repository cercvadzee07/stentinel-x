import { EVENT_TYPES, SEVERITIES, type SecurityEvent } from "./types.ts";

export type FieldKind = "ip" | "number" | "keyword" | "text" | "severity" | "time";

export interface FieldDef {
  path: string;
  key: keyof SecurityEvent;
  kind: FieldKind;
  label: string;
  values?: readonly string[];
}

/** SXQL field catalogue: ECS-style dotted paths mapped onto normalized event keys. */
export const FIELDS: FieldDef[] = [
  { path: "@timestamp", key: "timestamp", kind: "time", label: "Timestamp" },
  { path: "event.id", key: "eventId", kind: "keyword", label: "Event ID" },
  { path: "event.type", key: "type", kind: "keyword", label: "Event Type", values: EVENT_TYPES },
  {
    path: "event.category",
    key: "category",
    kind: "keyword",
    label: "Category",
    values: ["network", "authentication", "dns", "intrusion_detection", "malware", "iam", "endpoint"],
  },
  { path: "event.severity", key: "severity", kind: "severity", label: "Severity", values: SEVERITIES },
  { path: "event.action", key: "action", kind: "keyword", label: "Action", values: ["allow", "deny", "drop", "alert", "login", "query", "quarantine"] },
  { path: "event.outcome", key: "outcome", kind: "keyword", label: "Outcome", values: ["success", "failure", "unknown"] },
  { path: "event.count", key: "count", kind: "number", label: "Event Count" },
  { path: "event.simulated", key: "simulated", kind: "keyword", label: "Simulated", values: ["true", "false"] },
  { path: "event.scenario", key: "scenario", kind: "keyword", label: "Scenario" },
  { path: "source.ip", key: "sourceIp", kind: "ip", label: "Source IP" },
  { path: "source.port", key: "sourcePort", kind: "number", label: "Source Port" },
  { path: "source.host", key: "sourceHost", kind: "keyword", label: "Source Host" },
  { path: "destination.ip", key: "destinationIp", kind: "ip", label: "Destination IP" },
  { path: "destination.port", key: "destinationPort", kind: "number", label: "Destination Port" },
  { path: "destination.host", key: "destinationHost", kind: "keyword", label: "Destination Host" },
  { path: "network.protocol", key: "protocol", kind: "keyword", label: "Protocol", values: ["tcp", "udp", "icmp", "dns"] },
  { path: "network.direction", key: "direction", kind: "keyword", label: "Direction", values: ["inbound", "outbound", "internal"] },
  { path: "network.bytes", key: "bytes", kind: "number", label: "Bytes" },
  { path: "user.name", key: "username", kind: "keyword", label: "Username" },
  { path: "process.name", key: "application", kind: "keyword", label: "Application" },
  { path: "observer.vendor", key: "vendor", kind: "keyword", label: "Device Vendor" },
  { path: "observer.product", key: "product", kind: "keyword", label: "Device Product" },
  { path: "dns.question.name", key: "dnsQuery", kind: "keyword", label: "DNS Query" },
  { path: "message", key: "message", kind: "text", label: "Message" },
];

const BY_PATH = new Map<string, FieldDef>();
for (const f of FIELDS) {
  BY_PATH.set(f.path.toLowerCase(), f);
  BY_PATH.set(String(f.key).toLowerCase(), f);
}
// Common aliases analysts type
const ALIASES: Record<string, string> = {
  src: "source.ip", dst: "destination.ip", sport: "source.port", dport: "destination.port",
  "src.ip": "source.ip", "dst.ip": "destination.ip", "dst.port": "destination.port", proto: "network.protocol",
  severity: "event.severity", type: "event.type", user: "user.name", action: "event.action", outcome: "event.outcome",
};
for (const [a, p] of Object.entries(ALIASES)) BY_PATH.set(a, BY_PATH.get(p)!);

export function getField(path: string): FieldDef | undefined {
  return BY_PATH.get(path.toLowerCase());
}

export function readField(e: SecurityEvent, path: string): unknown {
  const f = getField(path);
  return f ? e[f.key] : undefined;
}
