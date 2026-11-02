import type { Severity } from "./types";

export class ApiError extends Error {
  status: number; data: unknown;
  constructor(status: number, message: string, data: unknown) { super(message); this.status = status; this.data = data; }
}

/** Session expired or missing → back to the login page, returning here afterwards. */
export function toLogin() {
  if (typeof window === "undefined" || location.pathname === "/login") return;
  location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
}

export async function api<T>(path: string, init?: RequestInit & { json?: unknown; noAuthRedirect?: boolean }): Promise<T> {
  const { json, noAuthRedirect, ...rest } = init ?? {};
  const res = await fetch(path, {
    ...rest,
    headers: { ...(json !== undefined ? { "content-type": "application/json" } : {}), ...rest.headers },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    cache: "no-store",
  });
  if (res.status === 401 && !noAuthRedirect) toLogin();
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string })?.error ?? res.statusText, data);
  return data as T;
}

export const fmtNum = (n: number) => new Intl.NumberFormat("en-US").format(Math.round(n));
export const fmtCompact = (n: number) => new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
export function fmtBytes(b: number) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}
export const fmtTime = (t: number) => new Date(t).toLocaleTimeString("en-GB", { hour12: false });
export const fmtTimeMs = (t: number) => {
  const d = new Date(t);
  return `${d.toLocaleTimeString("en-GB", { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`;
};
export const fmtDateTime = (t: number) => new Date(t).toLocaleString("en-GB", { hour12: false, month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
export function relTime(t: number, now = Date.now()) {
  const s = Math.round((now - t) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const SEV_COLOR: Record<Severity, string> = {
  info: "#64748b", low: "#22d3ee", medium: "#f59e0b", high: "#f97316", critical: "#ef4444",
};
export const SEV_CLASS: Record<Severity, string> = {
  info: "text-slate-300 bg-slate-500/10 border-slate-500/30",
  low: "text-cyan-300 bg-cyan-500/10 border-cyan-500/30",
  medium: "text-amber-300 bg-amber-500/10 border-amber-500/30",
  high: "text-orange-300 bg-orange-500/10 border-orange-500/35",
  critical: "text-red-300 bg-red-500/15 border-red-500/45",
};

export function downloadUrl(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export function cx(...xs: (string | false | null | undefined)[]) {
  return xs.filter(Boolean).join(" ");
}

/** Bits per second, SI units */
export const fmtBps = (b: number) => {
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  let i = 0;
  while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};

