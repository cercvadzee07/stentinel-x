/**
 * SXQL — SENTINEL X Query Language.
 *
 *   query   := or
 *   or      := and ("OR" and)*
 *   and     := not (["AND"] not)*          juxtaposition means AND
 *   not     := "NOT" not | "-" not | primary
 *   primary := "(" or ")" | term
 *   term    := field (":" | ">" | ">=" | "<" | "<=") value | field | text
 *
 * Values: exact, wildcard (*), quoted strings, numeric ranges (a..b),
 * CIDR blocks for IP fields, severity names for comparisons.
 */
import { getField, type FieldDef } from "./fields.ts";
import { SEVERITIES, type SecurityEvent, type Severity } from "./types.ts";

export class SxqlError extends Error {
  position: number;
  constructor(message: string, position: number) {
    super(message);
    this.name = "SxqlError";
    this.position = position;
  }
}

type Op = ":" | ">" | ">=" | "<" | "<=";

export type Node =
  | { kind: "and"; children: Node[] }
  | { kind: "or"; children: Node[] }
  | { kind: "not"; child: Node }
  | { kind: "field"; field: FieldDef; op: Op; value: string }
  | { kind: "exists"; field: FieldDef }
  | { kind: "text"; value: string }
  | { kind: "all" };

type Token =
  | { t: "lp" | "rp" | "and" | "or" | "not"; pos: number }
  | { t: "word"; v: string; quoted: boolean; pos: number };

export function tokenize(input: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  const readQuoted = (): string => {
    const start = i;
    i++; // opening quote
    let s = "";
    while (i < input.length && input[i] !== '"') {
      if (input[i] === "\\" && i + 1 < input.length) i++;
      s += input[i++];
    }
    if (input[i] !== '"') throw new SxqlError("Unterminated string", start);
    i++;
    return s;
  };
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "(") { out.push({ t: "lp", pos: i++ }); continue; }
    if (c === ")") { out.push({ t: "rp", pos: i++ }); continue; }
    const pos = i;
    if (c === '"') { out.push({ t: "word", v: readQuoted(), quoted: true, pos }); continue; }
    if (c === "-" && i + 1 < input.length && /[A-Za-z_"(]/.test(input[i + 1])) { out.push({ t: "not", pos: i++ }); continue; }
    let w = "";
    while (i < input.length && !/[\s()]/.test(input[i])) {
      if (input[i] === '"' && /(:|>=|<=|>|<)$/.test(w)) { w += "\u0000" + readQuoted(); break; }
      w += input[i++];
    }
    const up = w.toUpperCase();
    if (up === "AND" || w === "&&") out.push({ t: "and", pos });
    else if (up === "OR" || w === "||") out.push({ t: "or", pos });
    else if (up === "NOT" || w === "!") out.push({ t: "not", pos });
    else out.push({ t: "word", v: w, quoted: false, pos });
  }
  return out;
}

const TERM_RE = /^([A-Za-z_@][\w.@]*)(>=|<=|:|>|<)([\s\S]*)$/;

export function parse(input: string): Node {
  const tokens = tokenize(input);
  let p = 0;
  const peek = () => tokens[p];

  const parseOr = (): Node => {
    const children = [parseAnd()];
    while (peek()?.t === "or") { p++; children.push(parseAnd()); }
    return children.length === 1 ? children[0] : { kind: "or", children };
  };
  const parseAnd = (): Node => {
    const children = [parseNot()];
    for (;;) {
      const tk = peek();
      if (!tk || tk.t === "or" || tk.t === "rp") break;
      if (tk.t === "and") p++;
      children.push(parseNot());
    }
    return children.length === 1 ? children[0] : { kind: "and", children };
  };
  const parseNot = (): Node => {
    if (peek()?.t === "not") { p++; return { kind: "not", child: parseNot() }; }
    return parsePrimary();
  };
  const parsePrimary = (): Node => {
    const tk = peek();
    if (!tk) throw new SxqlError("Unexpected end of query", input.length);
    if (tk.t === "lp") {
      p++;
      const n = parseOr();
      if (peek()?.t !== "rp") throw new SxqlError("Missing closing parenthesis", tk.pos);
      p++;
      return n;
    }
    if (tk.t !== "word") throw new SxqlError(`Unexpected ${tk.t.toUpperCase()}`, tk.pos);
    p++;
    if (tk.quoted) return { kind: "text", value: tk.v };
    const m = TERM_RE.exec(tk.v);
    if (m) {
      const field = getField(m[1]);
      if (!field) throw new SxqlError(`Unknown field "${m[1]}"`, tk.pos);
      const value = m[3].replace(/^\u0000/, "");
      if (value === "") throw new SxqlError(`Missing value for ${m[1]}`, tk.pos + m[1].length);
      const op = m[2] as Op;
      if (op !== ":" && field.kind !== "number" && field.kind !== "severity" && field.kind !== "time")
        throw new SxqlError(`Operator ${op} needs a numeric or severity field`, tk.pos);
      if (op === ":" && value === "*") return { kind: "exists", field };
      return { kind: "field", field, op, value };
    }
    const bare = getField(tk.v);
    if (bare && tk.v.includes(".")) return { kind: "exists", field: bare };
    return { kind: "text", value: tk.v };
  };

  if (tokens.length === 0) return { kind: "all" };
  const node = parseOr();
  if (p < tokens.length) {
    const tk = tokens[p];
    throw new SxqlError(tk.t === "rp" ? "Unbalanced closing parenthesis" : "Unexpected token", tk.pos);
  }
  return node;
}

// ── evaluation ───────────────────────────────────────────────────────────

export function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const v = Number(part);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const a = ipToInt(ip), b = ipToInt(base);
  if (a === null || b === null || !(bits >= 0 && bits <= 32)) return false;
  const block = 2 ** (32 - bits);
  return Math.floor(a / block) === Math.floor(b / block);
}

const wildcard = (pattern: string) =>
  new RegExp("^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");

const sevRank = (v: string) => SEVERITIES.indexOf(v.toLowerCase() as Severity);

function compare(op: Op, a: number, b: number) {
  switch (op) {
    case ">": return a > b;
    case ">=": return a >= b;
    case "<": return a < b;
    case "<=": return a <= b;
    default: return a === b;
  }
}

type Pred = (e: SecurityEvent) => boolean;

function compileField(field: FieldDef, op: Op, value: string): Pred {
  const key = field.key;
  switch (field.kind) {
    case "severity": {
      const r = sevRank(value);
      if (r < 0) throw new SxqlError(`Unknown severity "${value}"`, 0);
      return (e) => compare(op, sevRank(e.severity), r);
    }
    case "number":
    case "time": {
      const range = /^(-?\d+)\.\.(-?\d+)$/.exec(value);
      if (range && op === ":") {
        const lo = Number(range[1]), hi = Number(range[2]);
        return (e) => { const v = e[key] as number | null; return v != null && v >= lo && v <= hi; };
      }
      const n = Number(value);
      if (Number.isNaN(n)) throw new SxqlError(`"${value}" is not a number`, 0);
      return (e) => { const v = e[key] as number | null; return v != null && compare(op, v, n); };
    }
    case "ip": {
      if (value.includes("/")) return (e) => inCidr(String(e[key] ?? ""), value);
      if (value.includes("*")) { const re = wildcard(value); return (e) => re.test(String(e[key] ?? "")); }
      return (e) => e[key] === value;
    }
    default: {
      if (value.includes("*")) { const re = wildcard(value); return (e) => re.test(String(e[key] ?? "")); }
      const v = value.toLowerCase();
      if (field.kind === "text") return (e) => String(e[key] ?? "").toLowerCase().includes(v);
      return (e) => String(e[key] ?? "").toLowerCase() === v;
    }
  }
}

const TEXT_KEYS: (keyof SecurityEvent)[] = [
  "message", "eventId", "type", "sourceIp", "destinationIp", "sourceHost", "destinationHost",
  "username", "application", "vendor", "product", "dnsQuery", "category", "action",
];

export function compileNode(n: Node): Pred {
  switch (n.kind) {
    case "all": return () => true;
    case "and": { const cs = n.children.map(compileNode); return (e) => cs.every((c) => c(e)); }
    case "or": { const cs = n.children.map(compileNode); return (e) => cs.some((c) => c(e)); }
    case "not": { const c = compileNode(n.child); return (e) => !c(e); }
    case "exists": return (e) => { const v = e[n.field.key]; return v !== null && v !== undefined && v !== "" && v !== false; };
    case "field": return compileField(n.field, n.op, n.value);
    case "text": {
      const v = n.value.toLowerCase();
      if (v.includes("*")) { const re = new RegExp(wildcard(v).source.slice(1, -1), "i"); return (e) => TEXT_KEYS.some((k) => re.test(String(e[k] ?? ""))); }
      return (e) => TEXT_KEYS.some((k) => String(e[k] ?? "").toLowerCase().includes(v));
    }
  }
}

export function compile(query: string): Pred {
  return compileNode(parse(query));
}

/** Validate without throwing — for the editor. */
export function check(query: string): { ok: true } | { ok: false; message: string; position: number } {
  try {
    compile(query);
    return { ok: true };
  } catch (err) {
    if (err instanceof SxqlError) return { ok: false, message: err.message, position: err.position };
    return { ok: false, message: String(err), position: 0 };
  }
}
