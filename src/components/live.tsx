"use client";

import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { Alert, MetricsSnapshot, SecurityEvent, StreamPayload } from "@/lib/types";
import { toLogin } from "@/lib/client";
import { useToast } from "./ui";

interface LiveState {
  connected: boolean;
  metrics: MetricsSnapshot | null;
  /** newest first, rolling window */
  events: SecurityEvent[];
  alerts: Alert[];
  /** bumps whenever alerts change — lets pages refetch */
  alertVersion: number;
  lastTick: number;
}

const Ctx = createContext<LiveState>({ connected: false, metrics: null, events: [], alerts: [], alertVersion: 0, lastTick: 0 });
const MAX_EVENTS = 1500;

/** Prepend a batch (oldest-first) to the newest-first buffer. The hello snapshot can overlap the first tick, so dedupe by id. */
function mergeEvents(batch: SecurityEvent[], cur: SecurityEvent[]) {
  const have = new Set(cur.slice(0, 600).map((e) => e.id));
  const fresh = batch.filter((e) => !have.has(e.id)).reverse();
  return fresh.length ? fresh.concat(cur).slice(0, MAX_EVENTS) : cur;
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>({ connected: false, metrics: null, events: [], alerts: [], alertVersion: 0, lastTick: 0 });
  const toast = useToast();
  const seen = useRef(new Set<string>());

  useEffect(() => {
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout>;
    let attempt = 0;

    const mergeAlerts = (cur: Alert[], incoming: Alert[]) => {
      const map = new Map(cur.map((a) => [a.id, a]));
      for (const a of incoming) map.set(a.id, a);
      return [...map.values()].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, 500);
    };

    const connect = () => {
      es = new EventSource("/api/stream");
      es.addEventListener("hello", (m) => {
        attempt = 0;
        const p = JSON.parse((m as MessageEvent).data) as StreamPayload;
        p.alerts.forEach((a) => seen.current.add(a.id));
        setState((s) => ({ ...s, connected: true, metrics: p.metrics, events: [...p.events].reverse(), alerts: mergeAlerts([], p.alerts), alertVersion: s.alertVersion + 1, lastTick: Date.now() }));
      });
      es.addEventListener("tick", (m) => {
        const p = JSON.parse((m as MessageEvent).data) as StreamPayload;
        for (const a of p.alerts) {
          if (seen.current.has(a.id)) continue;
          seen.current.add(a.id);
          if (a.severity === "critical" || a.severity === "high")
            toast({ tone: a.severity === "critical" ? "critical" : "warn", title: a.ruleName, body: `${a.sourceIp ?? "?"} → ${a.asset ?? a.targetIp ?? "?"}`, href: `/alerts?id=${a.id}` });
        }
        setState((s) => ({
          connected: true,
          metrics: p.metrics,
          events: p.events.length ? mergeEvents(p.events, s.events) : s.events,
          alerts: p.alerts.length ? mergeAlerts(s.alerts, p.alerts) : s.alerts,
          alertVersion: p.alerts.length ? s.alertVersion + 1 : s.alertVersion,
          lastTick: Date.now(),
        }));
      });
      es.onerror = () => {
        es?.close();
        fetch("/api/auth/me", { cache: "no-store" }).then((r) => { if (r.status === 401) toLogin(); }).catch(() => {});
        setState((s) => ({ ...s, connected: false }));
        retry = setTimeout(connect, Math.min(10_000, 1000 * 2 ** attempt++));
      };
    };
    connect();
    return () => { es?.close(); clearTimeout(retry); };
  }, [toast]);

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export const useLive = () => useContext(Ctx);
