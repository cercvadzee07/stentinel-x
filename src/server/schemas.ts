import { z } from "zod";
import { ALERT_STATUSES, INCIDENT_STATUSES, SEVERITIES } from "../lib/types.ts";
import { getField } from "../lib/fields.ts";
import { ROLES } from "../lib/rbac.ts";
import { inCidr, ipToInt } from "../lib/sxql.ts";
import { SCAN_TYPES } from "./scan/policy.ts";

const fieldPath = z.string().refine((f) => !!getField(f), { message: "Unknown field" });

export const RuleLogicSchema = z.object({
  filter: z.string().max(2000),
  groupBy: z.array(fieldPath).min(1).max(4),
  aggregate: z.enum(["count", "distinct", "sum_bytes"]),
  distinctField: fieldPath.optional(),
  threshold: z.number().positive().max(1e12),
  windowSec: z.number().int().min(1).max(86_400),
});

export const RuleInput = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(1000).default(""),
  logic: RuleLogicSchema,
  severity: z.enum(SEVERITIES),
  mitre: z.array(z.string().trim().min(1).max(120)).max(10).default([]),
  enabled: z.boolean().default(true),
});

export const AlertPatch = z.object({
  status: z.enum(ALERT_STATUSES).optional(),
  assignee: z.string().max(80).nullable().optional(),
  severity: z.enum(SEVERITIES).optional(),
  suppressed: z.boolean().optional(),
  comment: z.string().max(4000).optional(),
});

export const IncidentCreate = z.object({
  title: z.string().trim().min(3).max(200),
  description: z.string().trim().max(4000).default(""),
  alertIds: z.array(z.string()).max(200).default([]),
  assignee: z.string().max(80).nullable().optional(),
  severity: z.enum(SEVERITIES).optional(),
});

export const IncidentPatch = z.object({
  status: z.enum(INCIDENT_STATUSES).optional(),
  assignee: z.string().max(80).nullable().optional(),
  severity: z.enum(SEVERITIES).optional(),
  note: z.string().max(8000).optional(),
  resolution: z.string().max(8000).optional(),
  addAlertIds: z.array(z.string()).max(200).optional(),
});

// ── Phase 2: identity, administration, assets ──────────────────────────
const email = z.string().trim().toLowerCase().email().max(200);
const password = z.string().min(10, "Password must be at least 10 characters").max(200)
  .refine((p) => /[a-zA-Z]/.test(p) && /\d/.test(p), "Password must contain letters and digits");

export const LoginInput = z.object({ email, password: z.string().min(1).max(200) });
export const SignupInput = z.object({ orgName: z.string().trim().min(2).max(80), name: z.string().trim().min(2).max(80), email, password });
export const PasswordChange = z.object({ current: z.string().min(1).max(200), next: password });
export const UserCreate = z.object({ email, name: z.string().trim().min(2).max(80), role: z.enum(ROLES), password });
export const UserPatch = z.object({ role: z.enum(ROLES).optional(), disabled: z.boolean().optional(), name: z.string().trim().min(2).max(80).optional(), password: password.optional(), unlock: z.boolean().optional() });
export const KeyCreate = z.object({ name: z.string().trim().min(2).max(60) });

const ipv4 = z.string().trim().refine((v) => ipToInt(v) !== null, "Must be a valid IPv4 address");
export const AssetInputSchema = z.object({
  hostname: z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, "Letters, digits, dot, dash, underscore"),
  ip: ipv4,
  mac: z.string().trim().regex(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i, "Format aa:bb:cc:dd:ee:ff").nullable().optional().or(z.literal("").transform(() => null)),
  os: z.string().trim().max(120).nullable().optional(),
  type: z.enum(["server", "workstation", "firewall", "router", "switch", "domain_controller", "database", "web", "iot", "other"]),
  location: z.string().trim().max(120).nullable().optional(),
  owner: z.string().trim().max(120).nullable().optional(),
  criticality: z.number().int().min(1).max(5),
  monitored: z.boolean(),
  online: z.boolean().optional(),
  notes: z.string().max(2000).nullable().optional(),
});
/** PATCH uses AssetInputSchema.partial(); only creation applies defaults. */
export const AssetCreateSchema = AssetInputSchema.extend({ monitored: z.boolean().default(true) });
export const isPrivateIp = (ip: string) => ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].some((c) => inCidr(ip, c));

// ── Phase 5: scanning & vulnerabilities ─────────────────────────────────
export const ScanRequestSchema = z.object({
  name: z.string().trim().max(80).optional(),
  target: z.string().trim().min(7).max(18),
  ports: z.string().trim().max(200).default("top100"),
  type: z.enum(SCAN_TYPES),
  intensity: z.number().int().min(1).max(4).default(3),
  timeoutSec: z.number().int().min(30).max(1800).default(300),
  engine: z.enum(["nmap", "simulated"]),
  schedule: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("now") }),
    z.object({ kind: z.literal("once"), at: z.number().int() }),
    z.object({ kind: z.literal("recurring"), everyHours: z.union([z.literal(1), z.literal(6), z.literal(12), z.literal(24), z.literal(168)]), at: z.number().int().optional() }),
  ]).default({ kind: "now" }),
  /** the client must echo the exact target the analyst typed into the confirmation dialog */
  confirmTarget: z.string().trim().optional(),
});
export const AllowlistInput = z.object({ cidr: z.string().trim().min(9).max(18), label: z.string().trim().min(2).max(80) });
export const FindingPatch = z.object({ status: z.enum(["open", "accepted", "remediated", "not_detected"]).optional(), note: z.string().max(2000).nullable().optional() });
