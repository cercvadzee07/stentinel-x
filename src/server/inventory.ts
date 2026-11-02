/**
 * Simulated infrastructure for demo mode. Internal hosts use RFC 1918 ranges;
 * "external" actors use RFC 5737 documentation ranges (192.0.2.0/24,
 * 198.51.100.0/24, 203.0.113.0/24), which are never routable on the internet.
 */

export interface Asset {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  type: "server" | "workstation" | "firewall" | "router" | "switch" | "domain_controller" | "database" | "web";
  location: string;
  owner: string;
  criticality: 1 | 2 | 3 | 4 | 5;
  monitored: boolean;
  online: boolean;
  simulated: true;
}

const mac = (i: number) =>
  ["00", "1a", "2b", (i >> 8).toString(16).padStart(2, "0"), (i & 255).toString(16).padStart(2, "0"), "5e"].join(":");

let n = 0;
const a = (hostname: string, ip: string, type: Asset["type"], os: string, location: string, owner: string, criticality: Asset["criticality"]): Asset => ({
  id: `AST-${String(++n).padStart(4, "0")}`, hostname, ip, mac: mac(n), os, type, location, owner, criticality,
  monitored: true, online: true, simulated: true,
});

export const ASSETS: Asset[] = [
  a("fw-edge-01", "10.0.0.1", "firewall", "PAN-OS 11.1", "DC-East", "netops", 5),
  a("fw-edge-02", "10.0.0.2", "firewall", "FortiOS 7.4", "DC-West", "netops", 5),
  a("rtr-core-01", "10.0.0.10", "router", "Cisco IOS-XE 17", "DC-East", "netops", 5),
  a("sw-core-01", "10.0.0.20", "switch", "Arista EOS 4.31", "DC-East", "netops", 4),
  a("sw-access-01", "10.0.0.21", "switch", "Cisco NX-OS 10", "HQ-Floor2", "netops", 3),
  a("dc-01", "10.20.0.10", "domain_controller", "Windows Server 2022", "DC-East", "identity", 5),
  a("dc-02", "10.20.0.11", "domain_controller", "Windows Server 2022", "DC-West", "identity", 5),
  a("web-01", "10.10.1.10", "web", "Ubuntu 24.04", "DMZ", "platform", 4),
  a("web-02", "10.10.1.11", "web", "Ubuntu 24.04", "DMZ", "platform", 4),
  a("api-gw-01", "10.10.1.20", "web", "Debian 12", "DMZ", "platform", 4),
  a("vpn-01", "10.10.1.30", "server", "Ubuntu 22.04", "DMZ", "netops", 5),
  a("db-prod-01", "10.20.0.30", "database", "RHEL 9", "DC-East", "data", 5),
  a("db-prod-02", "10.20.0.31", "database", "RHEL 9", "DC-East", "data", 5),
  a("files-01", "10.20.0.40", "server", "Windows Server 2019", "DC-East", "it", 3),
  a("jump-01", "10.20.0.50", "server", "Windows Server 2022", "DC-East", "it", 4),
  a("k8s-node-01", "10.20.1.11", "server", "Flatcar 3815", "DC-East", "platform", 3),
  a("k8s-node-02", "10.20.1.12", "server", "Flatcar 3815", "DC-East", "platform", 3),
  a("k8s-node-03", "10.20.1.13", "server", "Flatcar 3815", "DC-West", "platform", 3),
  a("siem-collector", "10.20.0.90", "server", "Ubuntu 24.04", "DC-East", "secops", 4),
  a("mail-01", "10.10.1.40", "server", "Exchange 2019", "DMZ", "it", 4),
  a("dns-01", "10.20.0.53", "server", "BIND 9.18 / Debian", "DC-East", "netops", 5),
  ...Array.from({ length: 16 }, (_, i) =>
    a(`ws-${String(101 + i)}`, `10.30.0.${101 + i}`, "workstation", i % 4 === 0 ? "macOS 15" : "Windows 11 23H2", i < 8 ? "HQ-Floor2" : "HQ-Floor3", "employees", 2),
  ),
];
ASSETS.find((x) => x.hostname === "ws-114")!.online = false;
ASSETS.find((x) => x.hostname === "k8s-node-03")!.online = false;

export const SERVERS = ASSETS.filter((x) => x.type !== "workstation" && x.type !== "switch" && x.type !== "router" && x.type !== "firewall");
export const WORKSTATIONS = ASSETS.filter((x) => x.type === "workstation");
export const ASSET_BY_IP = new Map(ASSETS.map((x) => [x.ip, x]));

export interface ExternalActor { ip: string; country: string; code: string; lat: number; lon: number }

/** Demo GeoIP — fixed mapping of documentation addresses to locations. Not real geolocation. */
export const EXTERNAL_ACTORS: ExternalActor[] = [
  { ip: "203.0.113.17", country: "Russia", code: "RU", lat: 55.75, lon: 37.62 },
  { ip: "203.0.113.44", country: "China", code: "CN", lat: 39.9, lon: 116.4 },
  { ip: "203.0.113.91", country: "North Korea", code: "KP", lat: 39.03, lon: 125.75 },
  { ip: "198.51.100.23", country: "Iran", code: "IR", lat: 35.69, lon: 51.39 },
  { ip: "198.51.100.77", country: "Brazil", code: "BR", lat: -23.55, lon: -46.63 },
  { ip: "198.51.100.140", country: "Netherlands", code: "NL", lat: 52.37, lon: 4.9 },
  { ip: "192.0.2.12", country: "United States", code: "US", lat: 37.77, lon: -122.42 },
  { ip: "192.0.2.58", country: "Vietnam", code: "VN", lat: 21.03, lon: 105.85 },
  { ip: "192.0.2.201", country: "Romania", code: "RO", lat: 44.43, lon: 26.1 },
  { ip: "203.0.113.150", country: "India", code: "IN", lat: 19.08, lon: 72.88 },
  { ip: "198.51.100.200", country: "Germany", code: "DE", lat: 50.11, lon: 8.68 },
  { ip: "192.0.2.99", country: "Nigeria", code: "NG", lat: 6.52, lon: 3.38 },
];
export const ACTOR_BY_IP = new Map(EXTERNAL_ACTORS.map((x) => [x.ip, x]));

export const USERS = [
  "a.morgan", "j.chen", "s.patel", "m.rossi", "k.nakamura", "l.garcia", "d.okafor", "e.novak",
  "r.silva", "t.berg", "svc_backup", "svc_deploy", "administrator", "root", "admin", "oracle",
];

/** Demo analyst names used when seeding triage state; they match the seeded demo users. */
export const ANALYSTS = ["N. Carter", "A. Volkova", "T. Okoye", "S. Lindqvist"];

export const DOMAINS = [
  "login.microsoftonline.com", "api.github.com", "updates.ubuntu.com", "cdn.jsdelivr.net", "slack.com",
  "graph.microsoft.com", "registry.npmjs.org", "time.windows.com", "s3.amazonaws.com", "zoom.us",
];
