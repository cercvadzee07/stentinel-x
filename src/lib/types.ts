export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const severityRank = (s: Severity) => SEVERITIES.indexOf(s);

export const EVENT_TYPES = [
  "firewall_allow",
  "firewall_deny",
  "auth_success",
  "auth_failure",
  "ssh_login_failure",
  "rdp_login_failure",
  "dns_query",
  "suspicious_dns",
  "port_scan",
  "network_sweep",
  "brute_force",
  "ddos",
  "suspicious_port_traffic",
  "malware_detection",
  "ids_alert",
  "privilege_escalation",
  "unusual_network_activity",
  "endpoint_alert",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export const EVENT_TYPE_LABEL: Record<EventType, string> = {
  firewall_allow: "Firewall Allow",
  firewall_deny: "Firewall Deny",
  auth_success: "Authentication Success",
  auth_failure: "Authentication Failure",
  ssh_login_failure: "SSH Login Failure",
  rdp_login_failure: "RDP Login Failure",
  dns_query: "DNS Query",
  suspicious_dns: "Suspicious DNS Activity",
  port_scan: "Port Scan Detection",
  network_sweep: "Network Sweep",
  brute_force: "Brute Force Detection",
  ddos: "DDoS Detection",
  suspicious_port_traffic: "High Traffic to Suspicious Port",
  malware_detection: "Malware Detection",
  ids_alert: "IDS/IPS Alert",
  privilege_escalation: "Privilege Escalation",
  unusual_network_activity: "Unusual Network Activity",
  endpoint_alert: "Endpoint Security Alert",
};

export type Protocol = "tcp" | "udp" | "icmp" | "dns";
export type Direction = "inbound" | "outbound" | "internal";
export type Outcome = "success" | "failure" | "unknown";

/** Normalized event (ECS-inspired). Field paths for SXQL live in lib/fields.ts. */
export interface SecurityEvent {
  id: string;
  timestamp: number;
  eventId: string;
  type: EventType;
  category: string;
  severity: Severity;
  sourceIp: string;
  sourcePort: number | null;
  destinationIp: string;
  destinationPort: number | null;
  protocol: Protocol;
  direction: Direction;
  sourceHost: string | null;
  destinationHost: string | null;
  username: string | null;
  application: string | null;
  vendor: string;
  product: string;
  action: string;
  outcome: Outcome;
  count: number;
  bytes: number;
  dnsQuery: string | null;
  message: string;
  simulated: boolean;
  scenario: string | null;
  rawFormat: "cef" | "syslog" | "json";
  raw: unknown;
}

export interface RuleLogic {
  /** SXQL filter selecting candidate events */
  filter: string;
  /** Field paths forming the correlation key */
  groupBy: string[];
  aggregate: "count" | "distinct" | "sum_bytes";
  /** Field path counted distinctly when aggregate = distinct */
  distinctField?: string;
  threshold: number;
  windowSec: number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  logic: RuleLogic;
  severity: Severity;
  mitre: string[];
  enabled: boolean;
  builtin: boolean;
  triggerCount: number;
  lastTriggered: number | null;
  createdAt: number;
  updatedAt: number;
}

export const ALERT_STATUSES = ["new", "investigating", "escalated", "resolved", "false_positive"] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];
export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  new: "New",
  investigating: "Investigating",
  escalated: "Escalated",
  resolved: "Resolved",
  false_positive: "False Positive",
};

export interface HistoryEntry {
  at: number;
  actor: string;
  action: string;
  detail?: string;
}

export interface Comment {
  id: string;
  at: number;
  author: string;
  text: string;
}

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  sourceIp: string | null;
  targetIp: string | null;
  asset: string | null;
  ruleId: string;
  ruleName: string;
  groupKey: string;
  firstSeen: number;
  lastSeen: number;
  eventCount: number;
  mitre: string[];
  status: AlertStatus;
  assignee: string | null;
  suppressed: boolean;
  eventIds: string[];
  comments: Comment[];
  history: HistoryEntry[];
  incidentId: string | null;
}

export const INCIDENT_STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export interface TimelineEntry {
  at: number;
  kind: "event" | "alert" | "note" | "status" | "created";
  title: string;
  detail?: string;
  severity?: Severity;
  ref?: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: string | null;
  alertIds: string[];
  assets: string[];
  sourceIps: string[];
  timeline: TimelineEntry[];
  notes: Comment[];
  history: HistoryEntry[];
  resolution: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface SimulatorState {
  running: boolean;
  rate: number;
  autoScenarios: boolean;
  activeScenarios: { id: string; name: string; endsAt: number }[];
  generated: number;
}

export interface MetricsSnapshot {
  at: number;
  eps: number;
  epsSeries: { t: number; v: number }[];
  eventsToday: number;
  alertsBySeverity: Record<Severity, number>;
  openAlerts: number;
  activeIncidents: number;
  devices: { total: number; online: number; offline: number };
  suspiciousIps: number;
  failedAuth: number;
  blocked: number;
  bytesTotal: number;
  timeline: { t: number; info: number; low: number; medium: number; high: number; critical: number }[];
  traffic: { t: number; inbound: number; outbound: number; internal: number }[];
  severityDist: Record<Severity, number>;
  categories: { name: string; value: number }[];
  topSources: { key: string; value: number }[];
  topDestinations: { key: string; value: number }[];
  topPorts: { key: string; value: number }[];
  topAssets: { key: string; value: number }[];
  geo: { country: string; code: string; lat: number; lon: number; value: number }[];
  simulator: SimulatorState;
}

export interface StreamPayload {
  metrics: MetricsSnapshot;
  events: SecurityEvent[];
  alerts: Alert[];
}
