# SENTINEL X — Architecture & Roadmap

## 1. Workspace inspection (2026-11-02)

- Empty workspace: greenfield project.
- Toolchain: Node 24, npm 11. **No PostgreSQL, Redis or Nmap installed locally.**
- Consequence: the platform must run fully self-contained in demo mode, with the
  persistence / queue / scanner layers behind adapter interfaces so real
  infrastructure can be plugged in without touching the UI or the engine.

## 2. Architecture

```
┌──────────────────────────── Next.js 15 (App Router) ───────────────────────────┐
│  UI (React 19, Tailwind v4, Framer Motion, Recharts)                            │
│   └─ useLiveStream() ── EventSource /api/stream (SSE) ── live events, alerts,   │
│                                                         metrics ticks          │
│  Route handlers (/api/*)  — zod-validated input, JSON responses                │
│   ├─ /api/events          query (SXQL), paging, sort, export                   │
│   ├─ /api/ingest          REST ingestion → normalization pipeline              │
│   ├─ /api/rules           CRUD + /test (backtest against stored events)        │
│   ├─ /api/alerts          status/assign/severity/comment/suppress, bulk         │
│   ├─ /api/incidents       create-from-alerts, notes, timeline                  │
│   ├─ /api/simulator       start/stop/rate/scenario/reset                       │
│   └─ /api/metrics         dashboard aggregates                                 │
├──────────────────────────── Engine (src/server) ───────────────────────────────┤
│  Simulator ──► Normalizer (ECS-style fields) ──► EventStore ──► Correlator     │
│                     ▲                               │              │           │
│  REST / Syslog ─────┘                               ▼              ▼           │
│                                               Ring buffer +    AlertStore ──►  │
│                                               indexes          Bus (SSE fanout) │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Key decisions

| Concern | Decision | Why |
|---|---|---|
| Realtime | Server-Sent Events | One-way server→client fits event streams, works through Next route handlers, no extra server. WebSocket ingestion is an integration adapter. |
| Storage | PostgreSQL via a two-driver `Db` interface: **PGlite** (Postgres 17 compiled to WASM, in-process) when `DATABASE_URL` is unset, **node-postgres** when set. Plain parameterized SQL in a repository layer; ordered migrations in `src/server/db/migrations.ts`. | No Postgres on the dev machine, yet the same SQL, constraints and indexes run in dev, tests and production. Prisma was dropped: its query engine has no clean PGlite path, and two code paths would hide bugs. |
| Hot path | Per-tenant engine keeps an 80k-event ring buffer + indexes in memory for live views and SXQL; **write-behind** batches (2 s, one transaction) persist events, alerts, incidents and rules. Engines rehydrate from the DB on boot. | Sub-10 ms queries over the hot window without a search cluster; the database is the system of record. |
| Tenancy | One engine per organization; every table carries `org_id`; every repository statement filters on it; routes resolve the tenant from the session only. | Isolation enforced in one layer and covered by tests. |
| Auth | scrypt passwords, random 256-bit session tokens (only SHA-256 stored) in HttpOnly SameSite=Lax cookies, 12 h sliding expiry, 5-strike / 15 min lockout, per-IP login rate limit, same-origin + JSON-only mutations (CSRF), RBAC matrix in `src/lib/rbac.ts`, org API keys for ingestion, audit log. | Standard, dependency-free, testable. |
| Query language | **SXQL** — hand-written tokenizer + recursive-descent parser → AST → predicate | Real filtering, testable, autocompletable. |
| Correlation | Sliding-window, group-by, threshold / distinct-count rules evaluated per event | Same model as QRadar/Sentinel threshold rules; rules are data, user-editable. |
| Scanning | Policy module validates every request and re-validates at run time; job manager (2 concurrent, scheduler, cancel, restart recovery); engines: `nmap` (opt-in, fixed args, `-sT` only) or `simulated` (inventory-based, labelled). Findings merged into `vuln_findings`. | Safety requirements; scheduled scans stop when a range is removed from the allowlist. |
| Network telemetry | Topology inferred from inventory; per-tenant `Telemetry` samples every 5 s; link bytes = flow bytes × sampling factor routed up the tree; device metrics respond to load; fault injection for demo realism. | Lets the NOC views react to real pipeline traffic without inventing infrastructure for real tenants. |

## 3. SXQL grammar

```
query      := orExpr
orExpr     := andExpr ( "OR" andExpr )*
andExpr    := notExpr ( ["AND"] notExpr )*      -- juxtaposition = AND
notExpr    := "NOT" notExpr | primary
primary    := "(" orExpr ")" | term
term       := FIELD ":" value          -- equality / wildcard (*) / CIDR for IPs
            | FIELD (">"|">="|"<"|"<=") NUMBER
            | FIELD                    -- field exists / truthy
            | TEXT                     -- full-text over all string fields
value      := WORD | "quoted string" | a..b (numeric range)
```

Examples: `source.ip:192.168.1.10`, `destination.port:3389 AND event.outcome:failure`,
`source.ip:10.0.0.0/8 event.severity>=high`, `NOT network.protocol:dns`.

## 4. Database schema (`src/server/db/migrations.ts`, migration 1)

Every tenant-owned table carries `org_id` (FK → organizations, ON DELETE CASCADE).

| Table | Purpose | Notable constraints / indexes |
|---|---|---|
| `organizations` | tenants; `demo` flag; `settings` JSONB (simulator config) | `slug` unique |
| `users` | email, name, scrypt hash, role, disabled, failed_logins, locked_until | unique `lower(email)`; role CHECK |
| `sessions` | SHA-256 of the token, ip, user agent, expiry | `token_hash` unique; cascade on user delete |
| `api_keys` | ingestion keys: prefix + SHA-256, revoked_at | `key_hash` unique |
| `audit_log` | actor, action, target, meta JSONB, ip | `(org_id, created_at DESC)` |
| `assets` | hostname, ip, mac, os, type, location, owner, criticality 1–5, monitored, online, simulated | unique `(org_id, ip)`; criticality CHECK |
| `events` | normalized event: typed hot columns + full doc JSONB | PK `(org_id, id)`; `(org_id, ts DESC)`, `(org_id, source_ip, ts)`, `(org_id, destination_port, ts)`, `(org_id, type, ts)` |
| `rules` / `alerts` / `incidents` | engine documents as JSONB with status / time columns for listing | PK `(org_id, id)`; alerts `(org_id, status, last_seen DESC)` |

Migration 2 adds `scan_allowlist` (unique `(org_id, cidr)`), `scan_jobs` (job document + `status`/`next_run_at` for the scheduler) and `vuln_findings` (stable id per org+host+check+port, status CHECK, `(org_id, status, severity)` and `(org_id, host_ip)` indexes).

Retention: the newest 500k events per tenant are kept (pruned every 10 min). Planned: monthly range partitions on `events.ts`, plus `indicators`, `integrations`, `reports` tables with their modules.

## 5. Core analyst workflows

1. **Triage**: Overview → spike in critical → Security Alerts → open drawer → related events → assign → Investigating.
2. **Hunt**: Log Explorer → SXQL query → histogram narrows window → pivot on field value → save search.
3. **Detection engineering**: Correlation Rules → clone rule → change threshold → backtest on history → enable.
4. **Incident response**: select alerts → Create incident → timeline auto-built from alert/event times → notes → resolve with resolution details.
5. **NOC**: Network Monitoring → topology node degraded → interface stats → related firewall denies.

## 6. Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Design system, shell, navigation (18 modules), command palette, Overview | **done** |
| 3/4 core | Simulator → normalizer → store → correlator → alerts, SSE stream, SXQL, Live Events, Log Explorer, Rules, Alerts, Incidents | **done (pulled forward: the dashboard needs a real data source)** — syslog listener still open |
| 2 | PostgreSQL (PGlite / pg), migrations, auth + sessions + lockout, organizations + sign-up, RBAC, API keys, audit log, per-tenant persistent engines, Asset Inventory, System Admin, Settings | **done** |
| 5 | Network monitoring (inferred topology, simulated telemetry driven by flow events), firewall and authentication analytics with compromise detection and investigation, Scan Center (allowlist policy, nmap adapter, simulated engine, scheduler), vulnerability register | **done** |
| 6 | Threat intel adapters, integrations registry, reports (CSV / print-to-PDF), analytics | planned |
| 7 | Tests, security review, perf, Docker deployment | ongoing |
