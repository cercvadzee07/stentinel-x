# SENTINEL X

Enterprise SIEM · SOC · NOC platform. Next.js 15 / React 19 / TypeScript / PostgreSQL, with a real
ingestion → normalization → correlation → alerting pipeline running server-side, multi-tenant
organizations, role-based access control and an audit trail.

> **Demo tenant.** The seeded *ACME Corp* organization is fed by a built-in event simulator.
> Simulated events use RFC 1918 (internal) and RFC 5737 documentation (external) addresses and are
> labelled **SIM** everywhere. Threat-map geolocation is a fixed demo table, not real GeoIP.
> Organizations created through sign-up start empty, with the simulator off.

## Quick start

```bash
npm install
npm run dev        # http://localhost:3100  → sign in with a demo account listed on the login page
npm test           # 43 tests: SXQL, normalizers, rules vs. attack scenarios, auth, tenancy, persistence, scan policy, analytics
npm run build && npm start
```

Node 22.6+ (tests use Node's built-in type stripping). **No database server needed**: without
`DATABASE_URL` the app runs PostgreSQL 17 in-process via [PGlite](https://pglite.dev) and stores it
under `.data/pglite`. Set `DATABASE_URL=postgresql://…` to use a PostgreSQL server instead, with the same SQL
and migrations. Configuration is documented in `.env.example`; the demo accounts and their shared password are in
`src/server/db/seed.ts`.

## Roles

| Permission | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| Dashboards, live events, search, alerts, incidents, rules, assets (read) | ✓ | ✓ | ✓ |
| Export events, ingest via session | | ✓ | ✓ |
| Triage alerts, manage incidents, manage assets, backtest rules, launch scenarios | | ✓ | ✓ |
| Run / cancel scans, triage vulnerability findings | | ✓ | ✓ |
| Create/edit/delete rules, control/reset simulator, manage the scan allowlist | | | ✓ |
| Users & roles, API keys, audit log | | | ✓ |

Enforced server-side in every route (`src/server/context.ts` → `src/lib/rbac.ts`); the UI only mirrors it.

## Security model

- **Passwords**: scrypt (N=2¹⁴, r=8, p=1), constant-time comparison; policy ≥10 chars with letters and digits.
- **Sessions**: 256-bit random token in an `HttpOnly; SameSite=Lax` cookie (`Secure` behind HTTPS); only its
  SHA-256 is stored; 12 h sliding expiry; revoked on logout, password change, role change, disable, admin reset.
- **Brute force**: 5 consecutive failures lock the account for 15 min; 10 login attempts / min / IP. Unknown
  emails get the same response (and timing) as wrong passwords.
- **CSRF**: SameSite cookies + mutations must be same-origin with `Content-Type: application/json`.
- **Tenant isolation**: every table carries `org_id`; every repository statement filters on it; the tenant comes
  only from the session (or API key). Cross-tenant IDs return 404. Covered by tests.
- **Ingestion**: organization API keys (`Authorization: Bearer sx_…`), shown once, SHA-256 stored, revocable.
- **Audit log**: logins, failures, lockouts, user/role/key changes, rule/alert/incident/asset changes, exports,
  simulator commands — with actor and IP.
- **Input validation**: zod schemas on every body; SXQL is parsed (never evaluated as code); CSV export
  neutralizes formula injection.

## Scanning safety

Enforced in `src/server/scan/policy.ts` on every request **and again right before a job runs**:

- Targets are one IPv4 address or a CIDR block ≤ /22 (1,024 addresses), never hostnames.
- The whole range must lie inside one of the organization's allowlisted CIDRs (managed by admins, audited).
- Public addresses are rejected unless `SCAN_ALLOW_PUBLIC=1`, and even then they must be allowlisted.
  Loopback, link-local, multicast and reserved ranges are always rejected.
- Work is bounded: ≤ 1,024 ports for multi-host scans, ≤ 100 UDP ports, ≤ 65,536 probes, timing T1–T4, timeout 30–1800 s.
- The client must re-type the exact target (HTTP 428 otherwise); scans, rejections and cancellations are audited.
- **nmap adapter** (`src/server/scan/nmap.ts`): off unless `SCAN_ENABLE_NMAP=1` and the binary answers
  `--version`; spawned without a shell from a fixed argument vector; TCP connect scans (`-sT`) only. No SYN/stealth,
  idle, decoy, spoofing, fragmentation, OS fingerprinting or NSE scripts. The executed command is shown on the job.
- **Simulated engine**: sends no packets, reports only hosts present in the asset inventory within the target, and
  flags every job, result and finding as SIMULATED.
- **Vulnerability checks** are non-intrusive: port exposure plus version banners (e.g. CVE-2024-6387 regreSSHion,
  CVE-2021-41773/42013 Apache, CVE-2011-2523 vsftpd, unauthenticated Docker API). Version matches are labelled potential.

## What works today

| Module | Status |
|---|---|
| **Overview** | 12 live KPIs, EPS chart, severity timeline, traffic by direction, severity & category distribution, threat map, top sources / destinations / ports / assets, live activity. Panels deep-link into Log Explorer. |
| **Live Events** | SSE stream, pause/resume, SXQL + field filters, sort, paging, CSV/JSON export, event drawer (normalized fields, raw payload, related events, contributing alerts). |
| **Log Explorer** | SXQL editor with autocomplete and positioned errors, condition builder, time ranges, histogram zoom, facets, saved searches & history, export. |
| **Correlation Rules** | 10 built-in rules with MITRE ATT&CK mapping; create / edit / enable / delete; backtest against history. |
| **Security Alerts** | Auto-generated; assign, status, severity, suppress, comments, history, bulk actions, create incident. |
| **Incident Management** | Created from alerts or by hand; auto-built attack timeline; notes, history, resolution. |
| **Asset Inventory** | CRUD with validation, search/filter/sort, live event & alert counts, investigation drawer. Events are enriched with the tenant's hostnames at ingestion. |
| **System Administration** | Users (invite, role, disable, unlock, reset password), API keys, searchable audit log. |
| **Settings** | Profile, password change, per-tenant simulator configuration, effective permissions. |
| **Auth** | Login, self-service organization sign-up, logout, session-expiry redirect. |
| **Network Monitoring** | Topology inferred from the asset inventory (barycentric layered layout, animated links coloured by utilisation), device inventory (CPU, memory, latency, loss, throughput, uptime), WAN traffic, interface errors, device drawer with interface table, history charts and per-minute availability. Telemetry is **simulated** for the demo tenant, with link load derived from the live flow events, so a DDoS scenario saturates the edge uplink. Tenants without a telemetry source see the topology only. |
| **Firewall Monitoring** | Allowed vs blocked trend, top sources (allow/deny split, demo GeoIP), destinations, ports, protocols, per-device counts + health, suspicious-pattern heuristics (repeated blocks, port sweeps, allowed C2 ports, blocked outbound, large outbound flows). Filters for source/destination address and port, protocol, action, device, time range; one click to open the same SXQL in Log Explorer. |
| **Authentication Monitoring** | Success/failure, SSH, RDP, lockouts (EventID 4740), sessions inferred from logons, repeated failures, unusual (external) login locations, **success-after-failures compromise detection**, and a failed-login investigation drawer per account or source with an assessment, related alerts, timeline, "mark benign" and "escalate to incident". |
| **Scan Center** | Allowlist-restricted host discovery, TCP/UDP port scans, service detection, network discovery and basic vulnerability assessment; live server-side policy check; type-the-target confirmation; scheduling (now / once / recurring); queue with progress and cancel; per-host results. Engines: nmap adapter (opt-in) or a clearly labelled simulated engine. |
| **Vulnerability Management** | Findings register merged from assessments (open → not detected → reopened, risk acceptance persists), severity/status filters, evidence, remediation, references, notes, history; shown per asset in the inventory. |

The remaining 4 modules (Threat Intel, Analytics, Reports, Integrations) open a roadmap page that states they are not
built yet.

## Architecture

```
simulator ─┐               ┌─► hot store (80k ring buffer) ─► SXQL queries · SSE /api/stream
REST ingest┼─► normalize ──┤─► metrics
 (API key) ┘  CEF · 5424 · └─► correlator ─► alerts ─► incidents
              WinSec · ECS         │
                                   └── write-behind (2 s, one tx) ──► PostgreSQL / PGlite
```

One engine per organization, rehydrated from the database on boot. See `docs/ARCHITECTURE.md` for
decisions, the SXQL grammar, the schema and the roadmap.

### REST ingestion

```bash
curl -X POST http://localhost:3100/api/ingest \
  -H "Authorization: Bearer <api key from System Admin → API keys>" \
  -H "Content-Type: application/json" \
  -d '[{"format":"syslog","payload":"<38>1 2026-11-02T21:30:00Z web-01 sshd 42 - - Failed password for root from 192.0.2.77 port 50000 ssh2"}]'
```

## Known limitations

- **SXQL searches the hot window** (the newest 80k events per tenant in memory). Older events are persisted
  (up to 500k per tenant) but are not searchable yet; a SQL-backed query path for history is planned.
- In-memory rate limiting and the scan queue are per process. Run a single instance, or move them to Redis before scaling out.
- Network telemetry exists only for the demo tenant (simulated). Real SNMP / streaming-telemetry collection is an Integrations (Phase 6) item.
- UDP scanning through nmap normally requires root privileges; without them nmap reports an error on the job.
- No syslog UDP/TCP listener yet (the normalizer already parses RFC 5424; REST ingestion is live).
- No email delivery: invited users get an initial password from their admin out of band. No MFA/SSO yet.
- In `npm run dev`, engines intentionally survive hot reloads, so edits under `src/server/` need a dev-server restart.
- On Windows, PGlite prints "The system cannot find the path specified." a couple of dozen times at startup. This is
  upstream noise from its embedded `initdb` and is harmless.

## Roadmap

Phases 1–5 are done. Next is Phase 6: threat intelligence (IOC management, reputation adapters that never fabricate
results), the integrations registry (syslog listener, SNMP, Suricata, Zeek, Wazuh, Elastic/OpenSearch), reports with
PDF/CSV export, and long-range analytics.
