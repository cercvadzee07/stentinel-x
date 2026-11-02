import type { Permission } from "./rbac";
import {
  Activity, BarChart3, Bell, Boxes, FileBarChart, Flame, Gauge, Globe2, KeyRound, Network, Plug, Radar,
  ScanSearch, Settings, ShieldAlert, ShieldCheck, Siren, Workflow, type LucideIcon,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  group: "Operations" | "Detection" | "Infrastructure" | "Intelligence" | "Platform";
  /** roadmap phase in which the module ships */
  phase: number;
  ready: boolean;
  shortcut?: string;
  summary: string;
  /** hidden from roles without this permission (the API enforces it regardless) */
  perm?: Permission;
}

export const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: Gauge, group: "Operations", phase: 1, ready: true, shortcut: "g o", summary: "SOC command-center dashboard" },
  { href: "/live-events", label: "Live Events", icon: Activity, group: "Operations", phase: 3, ready: true, shortcut: "g l", summary: "Real-time normalized event stream" },
  { href: "/log-explorer", label: "Log Explorer", icon: ScanSearch, group: "Operations", phase: 3, ready: true, shortcut: "g e", summary: "SXQL search & investigation" },
  { href: "/analytics", label: "SIEM Analytics", icon: BarChart3, group: "Operations", phase: 6, ready: false, summary: "Long-range trends, baselines and anomaly scoring" },
  { href: "/rules", label: "Correlation Rules", icon: Workflow, group: "Detection", phase: 4, ready: true, shortcut: "g r", summary: "Detection engineering & backtesting" },
  { href: "/alerts", label: "Security Alerts", icon: Bell, group: "Detection", phase: 4, ready: true, shortcut: "g a", summary: "Alert triage center" },
  { href: "/incidents", label: "Incident Management", icon: Siren, group: "Detection", phase: 4, ready: true, shortcut: "g i", summary: "Cases, timelines and response" },
  { href: "/threat-intel", label: "Threat Intelligence", icon: Radar, group: "Intelligence", phase: 6, ready: false, summary: "IOC management, reputation lookups via configured feed adapters" },
  { href: "/network", label: "Network Monitoring", icon: Network, group: "Infrastructure", phase: 5, ready: true, shortcut: "g n", summary: "Topology, interfaces, bandwidth, latency and availability" },
  { href: "/vulnerabilities", label: "Vulnerability Mgmt", icon: ShieldAlert, group: "Infrastructure", phase: 5, ready: true, summary: "Findings from scans, CVSS prioritization, remediation tracking" },
  { href: "/assets", label: "Asset Inventory", icon: Boxes, group: "Infrastructure", phase: 2, ready: true, shortcut: "g s", summary: "Hosts, owners, criticality and associated events" },
  { href: "/scan-center", label: "Scan Center", icon: Globe2, group: "Infrastructure", phase: 5, ready: true, summary: "Allowlist-restricted discovery & port scans (nmap adapter / labelled simulator)" },
  { href: "/firewall", label: "Firewall Monitoring", icon: Flame, group: "Infrastructure", phase: 5, ready: true, summary: "Allow/deny analytics, device health and suspicious patterns" },
  { href: "/authentication", label: "Authentication", icon: KeyRound, group: "Infrastructure", phase: 5, ready: true, shortcut: "g u", summary: "Logins, sessions, lockouts and failed-login investigation" },
  { href: "/reports", label: "Reports", icon: FileBarChart, group: "Intelligence", phase: 6, ready: false, summary: "Daily / weekly / monthly reports with PDF and CSV export" },
  { href: "/integrations", label: "Integrations", icon: Plug, group: "Platform", phase: 6, ready: false, summary: "Syslog, Windows, SNMP, Suricata, Zeek, Wazuh, Elastic, REST, WebSocket" },
  { href: "/admin", label: "System Admin", icon: ShieldCheck, group: "Platform", phase: 2, ready: true, perm: "users:manage", summary: "Users, roles, tenants, audit log, retention" },
  { href: "/settings", label: "Settings", icon: Settings, group: "Platform", phase: 2, ready: true, summary: "Profile, password, sessions and simulator" },
];

export const NAV_GROUPS = ["Operations", "Detection", "Infrastructure", "Intelligence", "Platform"] as const;
