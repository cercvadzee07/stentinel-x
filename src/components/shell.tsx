"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Bell, ChevronRight, CornerDownLeft, Database, LogOut, Menu, Pause, Play, RotateCcw, Search, Settings, Shield, Zap } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, cx, fmtCompact } from "@/lib/client";
import { NAV, NAV_GROUPS } from "@/lib/nav";
import { ROLE_LABEL } from "@/lib/rbac";
import { LiveProvider, useLive } from "./live";
import { SessionProvider, deniedHint, useSession } from "./session";
import { Kbd, Modal, OverlayProvider, useConfirm, useToast } from "./ui";

interface Scenario { id: string; name: string; description: string; duration: number }

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <OverlayProvider>
      <SessionProvider fallback={<ShellLoading />}>
        <LiveProvider>
          <Frame>{children}</Frame>
        </LiveProvider>
      </SessionProvider>
    </OverlayProvider>
  );
}

function ShellLoading() {
  return (
    <div className="ambient grid min-h-screen place-items-center">
      <div className="flex items-center gap-3 text-[12px] uppercase tracking-[0.2em] text-ink-3">
        <Shield className="h-5 w-5 animate-pulse-dot text-emerald" />Verifying session…
      </div>
    </div>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const [palette, setPalette] = useState(false);
  const [help, setHelp] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const sim = useSimulatorActions();

  useEffect(() => setMobileNav(false), [pathname]);

  // global shortcuts: Ctrl/⌘+K palette, "/" palette, "?" help, "g x" navigation
  useEffect(() => {
    let gAt = 0;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((v) => !v); return; }
      const t = e.target as HTMLElement;
      if (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "/") { e.preventDefault(); setPalette(true); return; }
      if (e.key === "?") { setHelp(true); return; }
      if (e.key === "g") { gAt = Date.now(); return; }
      if (Date.now() - gAt < 1200) {
        const item = NAV.find((n) => n.shortcut === `g ${e.key}`);
        if (item) { e.preventDefault(); router.push(item.href); }
        gAt = 0;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);

  return (
    <div className="ambient min-h-screen text-ink">
      <div className="flex">
        <Sidebar className="hidden lg:flex sticky top-0 h-screen" />
        <AnimatePresence>
          {mobileNav && (
            <>
              <motion.div className="fixed inset-0 z-40 bg-black/60 lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setMobileNav(false)} />
              <motion.div className="fixed inset-y-0 left-0 z-50 lg:hidden" initial={{ x: -260 }} animate={{ x: 0 }} exit={{ x: -260 }} transition={{ type: "spring", stiffness: 400, damping: 40 }}>
                <Sidebar className="flex h-full" />
              </motion.div>
            </>
          )}
        </AnimatePresence>
        <div className="flex min-w-0 flex-1 flex-col overflow-x-clip">
          <Topbar onPalette={() => setPalette(true)} onMenu={() => setMobileNav(true)} sim={sim} />
          <main key={pathname} className="page-enter min-w-0 flex-1 px-4 py-5 lg:px-6">
            {children}
          </main>
        </div>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} sim={sim} onHelp={() => setHelp(true)} />
      <Modal open={help} onClose={() => setHelp(false)} title="Keyboard shortcuts" width={440}>
        <div className="grid grid-cols-[1fr_auto] gap-y-2 text-sm">
          {[["Command palette", "Ctrl K"], ["Command palette", "/"], ["This help", "?"], ...NAV.filter((n) => n.shortcut).map((n) => [`Go to ${n.label}`, n.shortcut!]),
            ["Pause / resume live stream (Live Events)", "Space"], ["Run query (Log Explorer)", "Enter"], ["Close drawer / dialog", "Esc"]].map(([l, k], i) => (
            <div key={i} className="contents"><span className="text-ink-2">{l}</span><span className="flex gap-1 justify-end">{k.split(" ").map((x) => <Kbd key={x}>{x}</Kbd>)}</span></div>
          ))}
        </div>
      </Modal>
    </div>
  );
}

function Sidebar({ className }: { className?: string }) {
  const pathname = usePathname();
  const { metrics } = useLive();
  const { user, can, db } = useSession();
  const badge: Record<string, number | undefined> = {
    "/alerts": metrics ? metrics.alertsBySeverity.critical + metrics.alertsBySeverity.high : undefined,
    "/incidents": metrics?.activeIncidents,
  };
  return (
    <aside className={cx("w-[232px] shrink-0 flex-col border-r border-line bg-base/80 backdrop-blur-xl", className)}>
      <Link href="/" className="flex items-center gap-2.5 px-4 h-14 border-b border-line">
        <div className="relative grid h-8 w-8 place-items-center rounded-lg bg-emerald/10 border border-emerald/40 glow-emerald">
          <Shield className="h-4 w-4 text-emerald" strokeWidth={2.4} />
        </div>
        <div className="leading-none">
          <div className="text-[13px] font-bold tracking-[0.2em]">SENTINEL<span className="text-emerald"> X</span></div>
          <div className="mt-1 text-[9.5px] uppercase tracking-[0.18em] text-ink-3">SIEM · SOC · NOC</div>
        </div>
      </Link>
      <nav className="flex-1 overflow-y-auto scrollbar-thin px-2 py-3">
        {NAV_GROUPS.map((g) => (
          <div key={g} className="mb-3">
            <div className="px-2.5 pb-1 text-[9.5px] font-semibold uppercase tracking-[0.18em] text-ink-3/80">{g}</div>
            {NAV.filter((n) => n.group === g && (!n.perm || can(n.perm))).map((n) => {
              const active = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
              const Icon = n.icon;
              const b = badge[n.href];
              return (
                <Link key={n.href} href={n.href} title={n.ready ? n.summary : `${n.summary} — ships in Phase ${n.phase}`}
                  className={cx("group relative flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] transition-colors",
                    active ? "text-ink bg-raised" : "text-ink-2 hover:text-ink hover:bg-raised/60")}>
                  {active && <motion.span layoutId="nav-active" className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-full bg-emerald shadow-[0_0_10px_rgb(16_240_160)]" />}
                  <Icon className={cx("h-4 w-4 shrink-0", active ? "text-emerald" : "text-ink-3 group-hover:text-ink-2")} />
                  <span className="flex-1 truncate">{n.label}</span>
                  {!n.ready && <span className="text-[9px] font-mono text-ink-3/70">P{n.phase}</span>}
                  {!!b && <span className="rounded-full bg-sev-critical/20 px-1.5 text-[10px] font-semibold text-red-300 tnum">{b}</span>}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="border-t border-line px-4 py-3 text-[10.5px] text-ink-3">
        <div className="flex items-center justify-between"><span>Tenant</span><span className="truncate pl-2 text-ink-2" title={user.orgSlug}>{user.orgName}</span></div>
        <div className="mt-1 flex items-center justify-between"><span>Mode</span>{user.demo
          ? <span className="rounded border border-violet/40 bg-violet/10 px-1.5 font-semibold text-violet" title="Demo tenant fed by the event simulator">DEMO</span>
          : <span className="rounded border border-emerald/40 bg-emerald/10 px-1.5 font-semibold text-emerald">LIVE</span>}</div>
        <div className="mt-1 flex items-center justify-between"><span>Storage</span><span className="flex items-center gap-1 text-ink-2"><Database className="h-3 w-3" />{db === "pglite" ? "PGlite (embedded)" : "PostgreSQL"}</span></div>
      </div>
    </aside>
  );
}

function useSimulatorActions() {
  const toast = useToast();
  const confirm = useConfirm();
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  useEffect(() => { api<{ scenarios: Scenario[] }>("/api/simulator").then((r) => setScenarios(r.scenarios)).catch(() => {}); }, []);
  const send = useCallback(async (json: Record<string, unknown>, msg: string) => {
    try { await api("/api/simulator", { method: "POST", json }); toast({ tone: "success", title: msg }); }
    catch (e) { toast({ tone: "error", title: "Simulator command failed", body: (e as Error).message }); }
  }, [toast]);
  return {
    scenarios,
    start: () => send({ action: "start" }, "Simulator started"),
    stop: () => send({ action: "stop" }, "Simulator paused"),
    launch: (s: Scenario) => send({ action: "scenario", id: s.id }, `Scenario launched: ${s.name}`),
    rate: (rate: number) => send({ action: "config", rate }, `Generation rate set to ${rate} EPS`),
    reset: async () => {
      if (await confirm({ title: "Reset demo environment?", body: "All simulated events, alerts, incidents and rule edits are discarded and 30 minutes of fresh history are regenerated.", confirmLabel: "Reset", danger: true }))
        send({ action: "reset" }, "Demo environment reset");
    },
  };
}
type SimActions = ReturnType<typeof useSimulatorActions>;

const initials = (name: string) => name.split(/[\s.]+/).filter(Boolean).map((x) => x[0]).join("").slice(0, 2).toUpperCase();

function Topbar({ onPalette, onMenu, sim }: { onPalette: () => void; onMenu: () => void; sim: SimActions }) {
  const { metrics, connected } = useLive();
  const { user, can, logout } = useSession();
  const s = metrics?.simulator;
  const [menu, setMenu] = useState(false);
  const [userMenu, setUserMenu] = useState(false);
  const control = can("simulator:control"), scenario = can("simulator:scenario");
  const crit = metrics?.alertsBySeverity.critical ?? 0;
  return (
    <header className="sticky top-0 z-30 flex h-14 min-w-0 items-center gap-3 border-b border-line bg-void/70 px-4 backdrop-blur-xl lg:px-6">
      <button className="lg:hidden rounded-md p-1.5 text-ink-2 hover:bg-raised" aria-label="Open navigation" onClick={onMenu}><Menu className="h-5 w-5" /></button>
      <button onClick={onPalette} className="flex h-9 min-w-0 w-full max-w-md items-center gap-2 rounded-lg border border-line-strong bg-panel/60 px-3 text-left text-[13px] text-ink-3 hover:border-ink-3 transition-colors">
        <Search className="h-4 w-4" />
        <span className="flex-1 truncate">Search modules, run SXQL, launch scenarios…</span>
        <span className="hidden sm:flex gap-1"><Kbd>Ctrl</Kbd><Kbd>K</Kbd></span>
      </button>
      <div className="ml-auto flex shrink-0 items-center gap-2">
        <div className="hidden md:flex items-center gap-2 rounded-lg border border-line bg-panel/50 px-2.5 h-9 font-mono text-[12px]" title={connected ? "Live stream connected (SSE)" : "Reconnecting…"}>
          <span className={cx("h-2 w-2 rounded-full", connected ? "bg-emerald animate-pulse-dot shadow-[0_0_8px_rgb(16_240_160)]" : "bg-sev-medium")} />
          <span className="text-ink-3">EPS</span>
          <span className="w-10 text-right text-emerald tnum">{metrics ? fmtCompact(metrics.eps) : "—"}</span>
        </div>
        <div className="relative">
          <button onClick={() => setMenu((v) => !v)} className={cx("flex h-9 items-center gap-2 rounded-lg border px-2.5 text-[12px] transition-colors",
            s?.running ? "border-violet/40 bg-violet/10 text-violet" : "border-line-strong bg-panel/50 text-ink-3")}>
            <Zap className="h-3.5 w-3.5" />
            <span className="hidden xl:inline">Simulator</span>
            <span className="font-semibold">{s?.running ? "ON" : "OFF"}</span>
            {!!s?.activeScenarios.length && <span className="rounded bg-sev-critical/25 px-1 text-[10px] text-red-200">{s.activeScenarios.length} attack</span>}
          </button>
          <AnimatePresence>
            {menu && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setMenu(false)} />
                <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}
                  className="glass absolute right-0 z-50 mt-2 w-80 rounded-xl bg-panel/95 p-3 text-[13px]">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-[11px] uppercase tracking-wider text-ink-3">Event simulator</span>
                    <span className="text-[11px] text-ink-3 tnum">{fmtCompact(s?.generated ?? 0)} generated</span>
                  </div>
                  {!control && <p className="mb-2 rounded-md border border-line bg-base/60 px-2 py-1.5 text-[11px] text-ink-3">{deniedHint("simulator:control")} to start, pause, reset or retune the generator.</p>}
                  <div className="flex gap-2">
                    {s?.running
                      ? <button disabled={!control} onClick={sim.stop} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-line-strong py-1.5 hover:bg-raised"><Pause className="h-3.5 w-3.5" />Pause</button>
                      : <button disabled={!control} onClick={sim.start} className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-emerald/50 bg-emerald/10 py-1.5 text-emerald hover:bg-emerald/20"><Play className="h-3.5 w-3.5" />Start</button>}
                    <button disabled={!control} onClick={() => { setMenu(false); sim.reset(); }} className="flex items-center gap-1.5 rounded-lg border border-line-strong px-3 py-1.5 hover:bg-raised"><RotateCcw className="h-3.5 w-3.5" />Reset</button>
                  </div>
                  <label className="mt-3 block text-[11px] text-ink-3">Background rate: <span className="text-ink tnum">{s?.rate ?? 0} EPS</span>
                    <input disabled={!control} type="range" min={5} max={300} step={5} defaultValue={s?.rate ?? 35} onMouseUp={(e) => sim.rate(Number((e.target as HTMLInputElement).value))}
                      onKeyUp={(e) => sim.rate(Number((e.target as HTMLInputElement).value))} className="mt-1 w-full accent-emerald" />
                  </label>
                  <div className="mt-2 text-[11px] uppercase tracking-wider text-ink-3">Launch attack scenario</div>
                  <div className="mt-1 grid grid-cols-2 gap-1">
                    {sim.scenarios.map((sc) => (
                      <button key={sc.id} disabled={!scenario} title={scenario ? sc.description : deniedHint("simulator:scenario")} onClick={() => sim.launch(sc)}
                        className={cx("truncate rounded-md border px-2 py-1 text-left text-[12px] hover:bg-raised",
                          s?.activeScenarios.some((a) => a.id === sc.id) ? "border-sev-critical/50 text-red-200" : "border-line text-ink-2")}>{sc.name}</button>
                    ))}
                  </div>
                  <p className="mt-2 text-[10.5px] leading-snug text-ink-3">Simulated events use RFC 1918 and RFC 5737 documentation addresses and are labelled <span className="text-violet">SIM</span> everywhere.</p>
                </motion.div>
              </>
            )}
          </AnimatePresence>
        </div>
        <Link href="/alerts" className="relative grid h-9 w-9 place-items-center rounded-lg border border-line-strong bg-panel/50 text-ink-2 hover:text-ink" aria-label="Open alerts">
          <Bell className="h-4 w-4" />
          {crit > 0 && <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-sev-critical px-1 text-center text-[10px] font-bold text-white tnum glow-critical">{crit}</span>}
        </Link>
        <div className="relative">
          <button onClick={() => setUserMenu((v) => !v)} aria-label="Account menu" className="flex h-9 items-center gap-2 rounded-lg border border-line bg-panel/50 pl-1 pr-1 hover:border-line-strong xl:pr-2.5">
            <div className="grid h-7 w-7 place-items-center rounded-md bg-cyan/15 text-[11px] font-bold text-cyan">{initials(user.name)}</div>
            <div className="hidden text-left leading-tight xl:block"><div className="text-[12px]">{user.name}</div><div className="text-[10px] text-ink-3">{ROLE_LABEL[user.role]}</div></div>
          </button>
          <AnimatePresence>
            {userMenu && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setUserMenu(false)} />
                <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} className="glass absolute right-0 z-50 mt-2 w-64 rounded-xl bg-panel/95 p-1.5 text-[13px]">
                  <div className="px-2.5 py-2">
                    <div className="font-medium">{user.name}</div>
                    <div className="truncate text-[11.5px] text-ink-3">{user.email}</div>
                    <div className="mt-1.5 flex gap-1.5"><span className="rounded border border-cyan/40 bg-cyan/10 px-1.5 text-[10.5px] text-cyan">{user.role}</span><span className="truncate rounded border border-line-strong px-1.5 text-[10.5px] text-ink-2">{user.orgName}</span></div>
                  </div>
                  <div className="my-1 h-px bg-line" />
                  <Link href="/settings" onClick={() => setUserMenu(false)} className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-ink-2 hover:bg-raised hover:text-ink"><Settings className="h-4 w-4" />Settings & password</Link>
                  <button onClick={logout} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-ink-2 hover:bg-raised hover:text-red-300"><LogOut className="h-4 w-4" />Sign out</button>
                </motion.div>
              </>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  );
}

// ── Command palette ───────────────────────────────────────────────────
interface Cmd { id: string; label: string; hint?: string; group: string; run: () => void; keywords?: string }

function CommandPalette({ open, onClose, sim, onHelp }: { open: boolean; onClose: () => void; sim: SimActions; onHelp: () => void }) {
  const router = useRouter();
  const { can, logout } = useSession();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => { if (open) { setQ(""); setSel(0); setTimeout(() => inputRef.current?.focus(), 10); } }, [open]);

  const cmds = useMemo<Cmd[]>(() => {
    const go = (href: string) => () => { router.push(href); onClose(); };
    const base: Cmd[] = [
      ...NAV.filter((n) => !n.perm || can(n.perm)).map((n) => ({ id: n.href, label: n.label, hint: n.ready ? n.summary : `Phase ${n.phase} · ${n.summary}`, group: "Navigate", run: go(n.href), keywords: n.group })),
      ...(can("simulator:control") ? [
        { id: "sim-start", label: "Start simulator", group: "Simulator", run: () => { sim.start(); onClose(); } },
        { id: "sim-stop", label: "Pause simulator", group: "Simulator", run: () => { sim.stop(); onClose(); } },
        { id: "sim-reset", label: "Reset demo environment", group: "Simulator", run: () => { onClose(); sim.reset(); } },
      ] : []),
      ...sim.scenarios.filter(() => can("simulator:scenario")).map((s) => ({ id: `sc-${s.id}`, label: `Launch scenario: ${s.name}`, hint: s.description, group: "Simulator", run: () => { sim.launch(s); onClose(); }, keywords: "attack simulate" })),
      { id: "q-crit", label: "Hunt: critical & high events", hint: "event.severity>=high", group: "Saved hunts", run: go("/log-explorer?q=" + encodeURIComponent("event.severity>=high")) },
      { id: "q-ssh", label: "Hunt: failed SSH", hint: "destination.port:22 AND event.outcome:failure", group: "Saved hunts", run: go("/log-explorer?q=" + encodeURIComponent("destination.port:22 AND event.outcome:failure")) },
      { id: "q-rdp", label: "Hunt: failed RDP", hint: "destination.port:3389 AND event.outcome:failure", group: "Saved hunts", run: go("/log-explorer?q=" + encodeURIComponent("destination.port:3389 AND event.outcome:failure")) },
      { id: "q-out", label: "Hunt: large outbound transfers", hint: "network.direction:outbound AND network.bytes>1000000", group: "Saved hunts", run: go("/log-explorer?q=" + encodeURIComponent("network.direction:outbound AND network.bytes>1000000")) },
      ...(can("rules:write") ? [{ id: "new-rule", label: "Create detection rule", group: "Actions", run: go("/rules?new=1") }] : []),
      ...(can("assets:write") ? [{ id: "new-asset", label: "Add asset", group: "Actions", run: go("/assets?new=1") }] : []),
      { id: "logout", label: "Sign out", group: "Actions", run: () => { onClose(); void logout(); } },
      { id: "help", label: "Keyboard shortcuts", group: "Actions", run: () => { onClose(); onHelp(); } },
    ];
    return base;
  }, [router, onClose, sim, onHelp, can, logout]);

  const results = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = s ? cmds.filter((c) => `${c.label} ${c.hint ?? ""} ${c.keywords ?? ""} ${c.group}`.toLowerCase().includes(s)) : cmds.filter((c) => c.group !== "Saved hunts" || true);
    const extra: Cmd[] = [];
    if (s) {
      extra.push({ id: "search", label: `Search logs: ${q.trim()}`, hint: "Run as SXQL in Log Explorer", group: "Query", run: () => { router.push("/log-explorer?q=" + encodeURIComponent(q.trim())); onClose(); } });
      if (/^alr-/i.test(s)) extra.push({ id: "alert", label: `Open alert ${q.trim().toUpperCase()}`, group: "Query", run: () => { router.push(`/alerts?id=${q.trim().toUpperCase()}`); onClose(); } });
      if (/^inc-/i.test(s)) extra.push({ id: "inc", label: `Open incident ${q.trim().toUpperCase()}`, group: "Query", run: () => { router.push(`/incidents?id=${q.trim().toUpperCase()}`); onClose(); } });
    }
    return [...extra, ...list].slice(0, 40);
  }, [q, cmds, router, onClose]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => { listRef.current?.querySelector(`[data-i="${sel}"]`)?.scrollIntoView({ block: "nearest" }); }, [sel]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((i) => Math.min(results.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); results[sel]?.run(); }
    else if (e.key === "Escape") onClose();
  };

  let lastGroup = "";
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[80] flex items-start justify-center bg-black/60 px-4 pt-[12vh] backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={onClose}>
          <motion.div onMouseDown={(e) => e.stopPropagation()} initial={{ opacity: 0, scale: 0.97, y: -10 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 500, damping: 34 }} className="glass w-full max-w-xl overflow-hidden rounded-xl bg-panel/95 glow-emerald" role="dialog" aria-label="Command palette">
            <div className="flex items-center gap-2.5 border-b border-line px-4">
              <Search className="h-4 w-4 text-emerald" />
              <input ref={inputRef} autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Type a command, module, ALR-/INC- id, or an SXQL query…"
                className="h-12 flex-1 bg-transparent text-[14px] text-ink outline-none placeholder:text-ink-3" aria-label="Command" />
              <Kbd>Esc</Kbd>
            </div>
            <div ref={listRef} className="max-h-[52vh] overflow-y-auto p-1.5 scrollbar-thin">
              {results.length === 0 && <div className="px-3 py-6 text-center text-sm text-ink-3">No matching commands</div>}
              {results.map((c, i) => {
                const header = c.group !== lastGroup ? (lastGroup = c.group) : null;
                return (
                  <div key={c.id}>
                    {header && <div className="px-2.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-3">{header}</div>}
                    <button data-i={i} onMouseMove={() => setSel(i)} onClick={c.run}
                      className={cx("flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left", i === sel ? "bg-emerald/10 text-ink" : "text-ink-2")}>
                      <ChevronRight className={cx("h-3.5 w-3.5 shrink-0", i === sel ? "text-emerald" : "text-ink-3")} />
                      <span className="flex-1 min-w-0">
                        <span className="block truncate text-[13px]">{c.label}</span>
                        {c.hint && <span className="block truncate font-mono text-[11px] text-ink-3">{c.hint}</span>}
                      </span>
                      {i === sel && <CornerDownLeft className="h-3.5 w-3.5 text-emerald" />}
                    </button>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
