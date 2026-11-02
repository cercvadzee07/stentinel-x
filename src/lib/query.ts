/** Helpers for composing SXQL from UI filters. */
export const term = (field: string, value: string | number) => {
  const v = String(value);
  return `${field}:${/[\s()"]/.test(v) || v === "" ? `"${v.replace(/"/g, '\\"')}"` : v}`;
};

export const anyOf = (field: string, values: (string | number)[]) =>
  values.length === 0 ? "" : values.length === 1 ? term(field, values[0]) : `(${values.map((v) => term(field, v)).join(" OR ")})`;

export const and = (...parts: (string | null | undefined | false)[]) => {
  const xs = parts.filter((p): p is string => !!p && p.trim() !== "");
  return xs.map((p) => (/\sOR\s/i.test(p) && !/^\(.*\)$/.test(p.trim()) ? `(${p})` : p)).join(" AND ");
};

export const TIME_RANGES = [
  { value: "5m", label: "Last 5 min", ms: 5 * 60_000 },
  { value: "15m", label: "Last 15 min", ms: 15 * 60_000 },
  { value: "30m", label: "Last 30 min", ms: 30 * 60_000 },
  { value: "1h", label: "Last 1 hour", ms: 60 * 60_000 },
  { value: "24h", label: "Last 24 hours", ms: 24 * 60 * 60_000 },
  { value: "all", label: "All retained", ms: 0 },
] as const;
