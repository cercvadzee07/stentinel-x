"use client";

import { AnimatePresence, animate, motion, useMotionValue, useReducedMotion, useTransform } from "framer-motion";
import { AlertTriangle, Inbox, Loader2, X } from "lucide-react";
import Link from "next/link";
import {
  createContext, useCallback, useContext, useEffect, useRef, useState,
  type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes,
} from "react";
import { SEV_CLASS, cx } from "@/lib/client";
import { ALERT_STATUS_LABEL, type AlertStatus, type Severity } from "@/lib/types";

// ── Panel ──────────────────────────────────────────────────────────────
export function Panel({ title, subtitle, actions, children, className, bodyClass, tone }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; tone?: "critical" | "emerald";
}) {
  return (
    <section className={cx("glass relative rounded-xl overflow-hidden flex flex-col", tone === "critical" && "glow-critical", tone === "emerald" && "glow-emerald", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3 pb-2 border-b border-line/60">
          <div className="min-w-0">
            <h3 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-2 truncate">{title}</h3>
            {subtitle && <p className="text-[11px] text-ink-3 truncate mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={cx("flex-1 min-h-0", bodyClass ?? "p-4")}>{children}</div>
    </section>
  );
}

// ── Animated counter ───────────────────────────────────────────────────
export function Counter({ value, format = (n) => Math.round(n).toLocaleString("en-US") }: { value: number; format?: (n: number) => string }) {
  const reduce = useReducedMotion();
  const mv = useMotionValue(value);
  const text = useTransform(mv, (v) => format(v));
  useEffect(() => {
    if (reduce) { mv.set(value); return; }
    const c = animate(mv, value, { duration: 0.6, ease: "easeOut" });
    return () => c.stop();
  }, [value, reduce, mv]);
  return <motion.span className="tnum">{text}</motion.span>;
}

export function Stat({ label, value, format, hint, accent = "emerald", icon, href, pulse }: {
  label: string; value: number; format?: (n: number) => string; hint?: ReactNode; accent?: "emerald" | "cyan" | "critical" | "high" | "medium" | "slate";
  icon?: ReactNode; href?: string; pulse?: boolean;
}) {
  const color = { emerald: "text-emerald", cyan: "text-cyan", critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", slate: "text-ink" }[accent];
  const bar = { emerald: "bg-emerald", cyan: "bg-cyan", critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", slate: "bg-ink-3" }[accent];
  const body = (
    <div className="glass group relative rounded-xl px-4 py-3 overflow-hidden h-full transition-colors hover:border-line-strong">
      <span className={cx("absolute left-0 top-3 bottom-3 w-[2px] rounded-full opacity-70", bar)} />
      <div className="flex items-center justify-between text-[10.5px] uppercase tracking-[0.14em] text-ink-3">
        <span className="truncate">{label}</span>
        <span className="flex items-center gap-1.5">
          {pulse && <span className={cx("h-1.5 w-1.5 rounded-full animate-pulse-dot", bar)} />}
          {icon}
        </span>
      </div>
      <div className={cx("mt-1.5 text-2xl font-semibold tracking-tight", color)}>
        <Counter value={value} format={format} />
      </div>
      {hint && <div className="mt-0.5 text-[11px] text-ink-3 truncate">{hint}</div>}
    </div>
  );
  return href ? <Link href={href} className="block h-full">{body}</Link> : body;
}

// ── Badges ─────────────────────────────────────────────────────────────
export function SevBadge({ s, glow }: { s: Severity; glow?: boolean }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-md border px-1.5 py-[1px] text-[10.5px] font-medium uppercase tracking-wider", SEV_CLASS[s])}>
      <span className={cx("h-1.5 w-1.5 rounded-full", glow && s === "critical" && "animate-pulse-dot")} style={{ background: "currentColor" }} />
      {s}
    </span>
  );
}

const STATUS_CLASS: Record<AlertStatus, string> = {
  new: "text-emerald border-emerald/40 bg-emerald/10",
  investigating: "text-cyan border-cyan/40 bg-cyan/10",
  escalated: "text-sev-high border-sev-high/40 bg-sev-high/10",
  resolved: "text-ink-3 border-line-strong bg-raised",
  false_positive: "text-violet border-violet/40 bg-violet/10",
};
export function StatusBadge({ s }: { s: AlertStatus }) {
  return <span className={cx("inline-flex rounded-md border px-1.5 py-[1px] text-[10.5px] font-medium", STATUS_CLASS[s])}>{ALERT_STATUS_LABEL[s]}</span>;
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("inline-flex items-center rounded border border-line-strong bg-raised px-1.5 py-[1px] text-[10.5px] text-ink-2", className)}>{children}</span>;
}

export function SimBadge() {
  return <span title="Generated by the SENTINEL X event simulator — not a real network observation" className="inline-flex rounded border border-violet/40 bg-violet/10 px-1 text-[9.5px] font-semibold uppercase tracking-wider text-violet">sim</span>;
}

// ── Form controls ──────────────────────────────────────────────────────
type BtnVariant = "primary" | "ghost" | "outline" | "danger";
export function Button({ variant = "outline", size = "md", loading, className, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; size?: "sm" | "md"; loading?: boolean }) {
  const v = {
    primary: "bg-emerald text-black hover:bg-emerald/90 border-emerald font-semibold shadow-[0_0_20px_-6px_rgb(16_240_160/0.7)]",
    ghost: "border-transparent text-ink-2 hover:text-ink hover:bg-raised",
    outline: "border-line-strong bg-panel/60 text-ink-2 hover:text-ink hover:border-ink-3",
    danger: "border-sev-critical/50 bg-sev-critical/10 text-red-300 hover:bg-sev-critical/20",
  }[variant];
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={cx("inline-flex items-center justify-center gap-1.5 rounded-lg border transition-all disabled:opacity-40 disabled:pointer-events-none active:scale-[0.98]",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8.5 px-3 text-[13px]", v, className)}
    >
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
      {children}
    </button>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement> & { ref?: React.Ref<HTMLInputElement> }) {
  return <input {...rest} className={cx("h-8.5 rounded-lg border border-line-strong bg-base/80 px-2.5 text-[13px] text-ink placeholder:text-ink-3 outline-none focus:border-emerald/60 focus:ring-2 focus:ring-emerald/15 disabled:cursor-not-allowed disabled:opacity-45", className)} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...rest} className={cx("h-8.5 rounded-lg border border-line-strong bg-base/80 px-2 text-[13px] text-ink outline-none focus:border-emerald/60 disabled:cursor-not-allowed disabled:opacity-45", className)}>{children}</select>;
}

export function Textarea({ className, ...rest }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...rest} className={cx("rounded-lg border border-line-strong bg-base/80 px-2.5 py-2 text-[13px] text-ink placeholder:text-ink-3 outline-none focus:border-emerald/60 disabled:cursor-not-allowed disabled:opacity-45", className)} />;
}

export function Field({ label, children, hint, error }: { label: string; children: ReactNode; hint?: ReactNode; error?: string | null }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] uppercase tracking-wider text-ink-3">{label}</span>
      {children}
      {error ? <span className="text-[11px] text-red-300">{error}</span> : hint ? <span className="text-[11px] text-ink-3">{hint}</span> : null}
    </label>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-line-strong bg-raised px-1 font-mono text-[10px] text-ink-2">{children}</kbd>;
}

// ── States ─────────────────────────────────────────────────────────────
export function Empty({ title, body, icon }: { title: string; body?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <div className="rounded-full border border-line bg-raised p-3 text-ink-3">{icon ?? <Inbox className="h-5 w-5" />}</div>
      <div className="text-sm text-ink-2">{title}</div>
      {body && <div className="max-w-sm text-xs text-ink-3">{body}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-red-200">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="flex-1">{message}</span>
      {onRetry && <Button size="sm" variant="danger" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("skeleton rounded-md", className)} />;
}

// ── Overlays ───────────────────────────────────────────────────────────
function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); onClose(); } };
    window.addEventListener("keydown", h, true);
    return () => window.removeEventListener("keydown", h, true);
  }, [open, onClose]);
}

export function Drawer({ open, onClose, title, subtitle, children, width = 720, actions }: {
  open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; width?: number; actions?: ReactNode;
}) {
  useEscape(open, onClose);
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-[2px]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside
            role="dialog" aria-modal="true"
            className="fixed right-0 top-0 bottom-0 z-50 flex flex-col border-l border-line-strong bg-panel/95 backdrop-blur-xl shadow-2xl"
            style={{ width: `min(${width}px, 100vw)` }}
            initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 40, opacity: 0 }} transition={{ type: "spring", stiffness: 380, damping: 36 }}
          >
            <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
              <div className="min-w-0">
                <div className="text-[15px] font-semibold text-ink truncate">{title}</div>
                {subtitle && <div className="mt-0.5 text-xs text-ink-3">{subtitle}</div>}
              </div>
              <div className="flex items-center gap-2">
                {actions}
                <button aria-label="Close" onClick={onClose} className="rounded-md p-1.5 text-ink-3 hover:bg-raised hover:text-ink"><X className="h-4 w-4" /></button>
              </div>
            </header>
            <div className="flex-1 overflow-y-auto scrollbar-thin">{children}</div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

export function Modal({ open, onClose, title, children, footer, width = 520 }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; width?: number;
}) {
  useEscape(open, onClose);
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={onClose}>
          <motion.div
            role="dialog" aria-modal="true" onMouseDown={(e) => e.stopPropagation()}
            className="glass w-full rounded-xl bg-panel/95" style={{ maxWidth: width }}
            initial={{ scale: 0.96, y: 8 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.97, y: 4 }} transition={{ type: "spring", stiffness: 420, damping: 32 }}
          >
            <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
              <div className="text-sm font-semibold">{title}</div>
              <button aria-label="Close" onClick={onClose} className="rounded p-1 text-ink-3 hover:text-ink"><X className="h-4 w-4" /></button>
            </div>
            <div className="max-h-[70vh] overflow-y-auto px-5 py-4 scrollbar-thin">{children}</div>
            {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/** Promise-based confirmation dialog: `if (await confirm({...})) …` */
type ConfirmOpts = { title: string; body?: ReactNode; confirmLabel?: string; danger?: boolean };
const ConfirmCtx = createContext<(o: ConfirmOpts) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmCtx);

// ── Toasts ─────────────────────────────────────────────────────────────
type Toast = { id: number; tone: "info" | "success" | "warn" | "critical" | "error"; title: string; body?: string; href?: string };
const ToastCtx = createContext<(t: Omit<Toast, "id">) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function OverlayProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [conf, setConf] = useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null);
  const idRef = useRef(0);

  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++idRef.current;
    setToasts((xs) => [...xs.slice(-4), { ...t, id }]);
    setTimeout(() => setToasts((xs) => xs.filter((x) => x.id !== id)), t.tone === "critical" ? 9000 : 5000);
  }, []);
  const confirm = useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => setConf({ ...o, resolve })), []);
  const close = (v: boolean) => { conf?.resolve(v); setConf(null); };

  const tone = {
    info: "border-cyan/40", success: "border-emerald/50", warn: "border-sev-high/50", critical: "border-sev-critical/60 glow-critical", error: "border-sev-critical/50",
  };
  const dot = { info: "bg-cyan", success: "bg-emerald", warn: "bg-sev-high", critical: "bg-sev-critical", error: "bg-sev-critical" };

  return (
    <ToastCtx.Provider value={push}>
      <ConfirmCtx.Provider value={confirm}>
        {children}
        <div className="pointer-events-none fixed bottom-4 right-4 z-[70] flex w-[340px] max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
          <AnimatePresence initial={false}>
            {toasts.map((t) => {
              const inner = (
                <>
                  <span className={cx("mt-1.5 h-2 w-2 shrink-0 rounded-full", dot[t.tone], t.tone === "critical" && "animate-pulse-dot")} />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium text-ink">{t.title}</div>
                    {t.body && <div className="truncate font-mono text-[11px] text-ink-3">{t.body}</div>}
                  </div>
                </>
              );
              return (
                <motion.div key={t.id} layout initial={{ opacity: 0, x: 30 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 30 }}
                  className={cx("pointer-events-auto glass flex gap-2.5 rounded-lg bg-panel/95 px-3 py-2.5", tone[t.tone])}>
                  {t.href ? <Link href={t.href} className="flex flex-1 gap-2.5 min-w-0">{inner}</Link> : inner}
                  <button aria-label="Dismiss" onClick={() => setToasts((xs) => xs.filter((x) => x.id !== t.id))} className="self-start text-ink-3 hover:text-ink"><X className="h-3.5 w-3.5" /></button>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
        <Modal open={!!conf} onClose={() => close(false)} title={conf?.title} width={440}
          footer={<><Button variant="ghost" onClick={() => close(false)}>Cancel</Button><Button variant={conf?.danger ? "danger" : "primary"} onClick={() => close(true)} autoFocus>{conf?.confirmLabel ?? "Confirm"}</Button></>}>
          <div className="text-sm text-ink-2">{conf?.body}</div>
        </Modal>
      </ConfirmCtx.Provider>
    </ToastCtx.Provider>
  );
}

// ── Tabs ───────────────────────────────────────────────────────────────
export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { value: T; label: ReactNode }[] }) {
  return (
    <div className="flex gap-1 rounded-lg border border-line bg-base/60 p-0.5" role="tablist">
      {items.map((it) => (
        <button key={it.value} role="tab" aria-selected={value === it.value} onClick={() => onChange(it.value)}
          className={cx("relative rounded-md px-2.5 py-1 text-xs transition-colors", value === it.value ? "text-ink" : "text-ink-3 hover:text-ink-2")}>
          {value === it.value && <motion.span layoutId={`tab-${items.map((i) => i.value).join()}`} className="absolute inset-0 rounded-md bg-raised border border-line-strong" />}
          <span className="relative">{it.label}</span>
        </button>
      ))}
    </div>
  );
}

export function KV({ k, v, mono = true }: { k: string; v: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 border-b border-line/50 py-1.5 text-[12.5px]">
      <span className="text-ink-3 font-mono text-[11.5px]">{k}</span>
      <span className={cx("text-ink break-all", mono && "font-mono text-[12px]")}>{v ?? <span className="text-ink-3">—</span>}</span>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[13px] text-ink-3">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  return (
    <div className="flex items-center gap-1 text-[12px]">
      <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(1)} aria-label="First page">«</Button>
      <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">‹</Button>
      <span className="px-1 tnum text-ink-2">{page} / {pages}</span>
      <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">›</Button>
      <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(pages)} aria-label="Last page">»</Button>
    </div>
  );
}
