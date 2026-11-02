/**
 * Ordered, append-only SQL migrations (PostgreSQL 15+ / PGlite).
 * Every tenant-owned table carries org_id; every repository query filters on it.
 * Statements are separated by a semicolon at end of line.
 */
export const MIGRATIONS: { version: number; name: string; sql: string }[] = [
  {
    version: 1,
    name: "init",
    sql: `
CREATE TABLE organizations (
  id text PRIMARY KEY,
  name text NOT NULL,
  slug text NOT NULL UNIQUE,
  demo boolean NOT NULL DEFAULT false,
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL,
  name text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
  disabled boolean NOT NULL DEFAULT false,
  failed_logins int NOT NULL DEFAULT 0,
  locked_until timestamptz,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_uq ON users (lower(email));
CREATE INDEX users_org_idx ON users (org_id);

CREATE TABLE sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  ip text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE api_keys (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  prefix text NOT NULL,
  key_hash text NOT NULL UNIQUE,
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX api_keys_org_idx ON api_keys (org_id);

CREATE TABLE audit_log (
  id bigserial PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id text,
  actor_name text NOT NULL,
  action text NOT NULL,
  target text,
  meta jsonb,
  ip text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_time_idx ON audit_log (org_id, created_at DESC);

CREATE TABLE assets (
  id text PRIMARY KEY,
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hostname text NOT NULL,
  ip text NOT NULL,
  mac text,
  os text,
  type text NOT NULL,
  location text,
  owner text,
  criticality int NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
  monitored boolean NOT NULL DEFAULT true,
  online boolean NOT NULL DEFAULT true,
  simulated boolean NOT NULL DEFAULT false,
  notes text,
  last_seen timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, ip)
);
CREATE INDEX assets_org_host_idx ON assets (org_id, hostname);

CREATE TABLE rules (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  doc jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id)
);

CREATE TABLE alerts (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  status text NOT NULL,
  severity text NOT NULL,
  last_seen timestamptz NOT NULL,
  doc jsonb NOT NULL,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX alerts_org_status_idx ON alerts (org_id, status, last_seen DESC);

CREATE TABLE incidents (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  status text NOT NULL,
  updated_at timestamptz NOT NULL,
  doc jsonb NOT NULL,
  PRIMARY KEY (org_id, id)
);

CREATE TABLE events (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  ts timestamptz NOT NULL,
  type text NOT NULL,
  severity text NOT NULL,
  source_ip text NOT NULL,
  destination_ip text NOT NULL,
  destination_port int,
  username text,
  simulated boolean NOT NULL,
  doc jsonb NOT NULL,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX events_org_ts_idx ON events (org_id, ts DESC);
CREATE INDEX events_org_src_idx ON events (org_id, source_ip, ts DESC);
CREATE INDEX events_org_dport_idx ON events (org_id, destination_port, ts DESC);
CREATE INDEX events_org_type_idx ON events (org_id, type, ts DESC)
`,
  },
  {
    version: 2,
    name: "scan_center",
    sql: `
CREATE TABLE scan_allowlist (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  cidr text NOT NULL,
  label text NOT NULL,
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, cidr)
);

CREATE TABLE scan_jobs (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  status text NOT NULL,
  engine text NOT NULL CHECK (engine IN ('nmap', 'simulated')),
  next_run_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  doc jsonb NOT NULL,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX scan_jobs_org_created_idx ON scan_jobs (org_id, created_at DESC);
CREATE INDEX scan_jobs_due_idx ON scan_jobs (status, next_run_at);

CREATE TABLE vuln_findings (
  org_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  id text NOT NULL,
  host_ip text NOT NULL,
  check_id text NOT NULL,
  severity text NOT NULL,
  status text NOT NULL CHECK (status IN ('open', 'accepted', 'remediated', 'not_detected')),
  simulated boolean NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  doc jsonb NOT NULL,
  PRIMARY KEY (org_id, id)
);
CREATE INDEX vuln_org_status_idx ON vuln_findings (org_id, status, severity);
CREATE INDEX vuln_org_host_idx ON vuln_findings (org_id, host_ip)
`,
  },
];
