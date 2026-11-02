/** Role-based access control. Shared by server (enforcement) and client (UI gating only). */
export const ROLES = ["ADMIN", "ANALYST", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABEL: Record<Role, string> = { ADMIN: "Administrator", ANALYST: "SOC Analyst", VIEWER: "Read-only Viewer" };

const ALL: Role[] = ["ADMIN", "ANALYST", "VIEWER"];
const OPS: Role[] = ["ADMIN", "ANALYST"];
const ADMIN: Role[] = ["ADMIN"];

export const PERMISSIONS = {
  "events:read": ALL,
  "alerts:read": ALL,
  "incidents:read": ALL,
  "rules:read": ALL,
  "assets:read": ALL,
  "network:read": ALL,
  "scans:read": ALL,
  "vulns:read": ALL,
  "events:export": OPS,
  "events:ingest": OPS,
  "alerts:write": OPS,
  "incidents:write": OPS,
  "assets:write": OPS,
  "rules:test": OPS,
  "simulator:scenario": OPS,
  "scans:run": OPS,
  "vulns:write": OPS,
  "rules:write": ADMIN,
  "simulator:control": ADMIN,
  "users:manage": ADMIN,
  "keys:manage": ADMIN,
  "audit:read": ADMIN,
  "scans:allowlist": ADMIN,
} as const satisfies Record<string, Role[]>;

export type Permission = keyof typeof PERMISSIONS;

export const can = (role: Role | undefined | null, perm: Permission) => !!role && (PERMISSIONS[perm] as readonly Role[]).includes(role);

/** Minimum role that holds a permission — for "requires …" hints in the UI. */
export const requiredRole = (perm: Permission): Role => (PERMISSIONS[perm].includes("VIEWER" as never) ? "VIEWER" : PERMISSIONS[perm].includes("ANALYST" as never) ? "ANALYST" : "ADMIN");

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  orgId: string;
  orgName: string;
  orgSlug: string;
  demo: boolean;
}
