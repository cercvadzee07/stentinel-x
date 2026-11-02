"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Activity, Ban, Cpu, Database, Globe2, KeyRound, ShieldAlert, Siren, Waves } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo } from "react";
import { BarList, Donut, EpsChart, HBar, SeverityTimeline, ThreatMap, TrafficChart } from "@/components/charts";
import { useLive } from "@/components/live";
import { PageHeader, Panel, SevBadge, SimBadge, Skeleton, Stat } from "@/components/ui";
import { SEV_COLOR, fmtBytes, fmtCompact, fmtTime, relTime } from "@/lib/client";
import { EVENT_TYPE_LABEL, SEVERITIES, severityRank } from "@/lib/types";

export default function Overview() {
  const { metrics: m, events, alerts } = useLive();
  const router = useRouter();

  const activity = useMemo(() => {
    const evs = events.filter((e) => severityRank(e.severity) >= 2).slice(0, 14).map((e) => ({ kind: "event" as const, at: e.timestamp, id: e.id, e }));
    const als = alerts.slice(0, 6).map((a) => ({ kind: "alert" as const, at: a.lastSeen, id: a.id, a }));
    return [...als, ...evs].sort((x, y) => y.at - x.at).slice(0, 14);
  }, [events, alerts]);

  if (!m) return <OverviewSkeleton />;

  const sevDonut = SEVERITIES.map((s) => ({ name: s, value: m.severityDist[s], color: SEV_COLOR[s] })).filter((d) => d.value > 0);
  const catColors = ["#10f0a0", "#22d3ee", "#3b82f6", "#a78bfa", "#f59e0b", "#f97316", "#ef4444", "#64748b"];
  const trafficLastMin = m.traffic.at(-2);

  return (
    <div className="space-y-4">
      <PageHeader title="Security Operations Overview" subtitle={<>Live posture for tenant <span className="text-ink-2">acme-corp</span> · refreshed {fmtTime(m.at)} · data source: <span className="text-violet">event simulator (demo)</span></>} />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-6">
        <Stat label="Events / sec" value={m.eps} accent="emerald" pulse icon={<Activity className="h-3.5 w-3.5" />} hint="5s moving average" href="/live-events" />
        <Stat label="Events today" value={m.eventsToday} format={fmtCompact} accent="slate" icon={<Database className="h-3.5 w-3.5" />} hint={`${fmtCompact(m.epsSeries.reduce((s, x) => s + x.v, 0))} in last 2 min`} href="/log-explorer" />
        <Stat label="Critical alerts" value={m.alertsBySeverity.critical} accent="critical" pulse={m.alertsBySeverity.critical > 0} icon={<ShieldAlert className="h-3.5 w-3.5" />} hint="open, unsuppressed" href="/alerts?severity=critical" />
        <Stat label="High alerts" value={m.alertsBySeverity.high} accent="high" hint="open, unsuppressed" href="/alerts?severity=high" />
        <Stat label="Medium alerts" value={m.alertsBySeverity.medium} accent="medium" hint="open, unsuppressed" href="/alerts?severity=medium" />
        <Stat label="Active incidents" value={m.activeIncidents} accent="critical" icon={<Siren className="h-3.5 w-3.5" />} hint="not resolved / closed" href="/incidents" />
        <Stat label="Monitored devices" value={m.devices.total} accent="cyan" icon={<Cpu className="h-3.5 w-3.5" />} hint={<><span className="text-emerald">{m.devices.online} online</span> · <span className="text-sev-high">{m.devices.offline} offline</span> · <SimBadge /></>} />
        <Stat label="Suspicious IPs" value={m.suspiciousIps} accent="high" icon={<Globe2 className="h-3.5 w-3.5" />} hint="external sources w/ deny or high-sev" href={`/log-explorer?q=${encodeURIComponent("NOT source.ip:10.0.0.0/8 AND event.severity>=high")}`} />
        <Stat label="Failed auth" value={m.failedAuth} format={fmtCompact} accent="medium" icon={<KeyRound className="h-3.5 w-3.5" />} hint="since ingest start" href={`/log-explorer?q=${encodeURIComponent("event.category:authentication AND event.outcome:failure")}`} />
        <Stat label="Blocked connections" value={m.blocked} format={fmtCompact} accent="cyan" icon={<Ban className="h-3.5 w-3.5" />} hint="deny / drop / block" href={`/log-explorer?q=${encodeURIComponent("event.action:deny")}`} />
        <Stat label="Traffic volume" value={m.bytesTotal} format={fmtBytes} accent="cyan" icon={<Waves className="h-3.5 w-3.5" />} hint={trafficLastMin ? `${fmtBytes(trafficLastMin.inbound + trafficLastMin.outbound + trafficLastMin.internal)} last full minute` : undefined} />
        <Stat label="Open alerts" value={m.openAlerts} accent="emerald" hint="all severities" href="/alerts" />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Live events per second" subtitle="Last 120 seconds · all sources" className="xl:col-span-2" actions={<span className="flex items-center gap-1.5 text-[11px] text-emerald"><span className="h-1.5 w-1.5 rounded-full bg-emerald animate-pulse-dot" />LIVE</span>}>
          <EpsChart data={m.epsSeries} height={210} />
        </Panel>
        <Panel title="Live activity" subtitle="Alerts and medium+ events" bodyClass="p-0" actions={<Link href="/live-events" className="text-[11px] text-ink-3 hover:text-emerald">Open stream →</Link>}>
          <ul className="h-[250px] overflow-hidden px-3 py-2">
            <AnimatePresence initial={false}>
              {activity.map((x) => (
                <motion.li key={x.kind + x.id} layout initial={{ opacity: 0, x: -12, height: 0 }} animate={{ opacity: 1, x: 0, height: "auto" }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }}>
                  {x.kind === "alert" ? (
                    <Link href={`/alerts?id=${x.a.id}`} className="flex items-center gap-2 rounded-md border border-sev-critical/30 bg-sev-critical/[0.06] px-2 py-1 my-0.5 text-[12px] hover:border-sev-critical/60">
                      <span className="text-[9.5px] font-bold uppercase tracking-wider text-red-300">alert</span>
                      <span className="flex-1 truncate">{x.a.ruleName} <span className="font-mono text-ink-3">{x.a.sourceIp}</span></span>
                      <span className="text-[10.5px] text-ink-3">{relTime(x.at)}</span>
                    </Link>
                  ) : (
                    <button onClick={() => router.push(`/log-explorer?q=${encodeURIComponent(`event.id:${x.e.eventId}`)}`)} className="flex w-full items-center gap-2 px-2 py-1 text-left text-[12px] hover:bg-raised/60 rounded-md">
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEV_COLOR[x.e.severity] }} />
                      <span className="w-[62px] shrink-0 font-mono text-[11px] text-ink-3">{fmtTime(x.e.timestamp)}</span>
                      <span className="flex-1 truncate text-ink-2">{EVENT_TYPE_LABEL[x.e.type]}</span>
                      <span className="font-mono text-[11px] text-ink-3">{x.e.sourceIp}</span>
                    </button>
                  )}
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Security events timeline" subtitle="Per minute, stacked by severity · click a bar to investigate" className="xl:col-span-2">
          <SeverityTimeline data={m.timeline} height={220}
            onSelect={(t) => router.push(`/log-explorer?q=${encodeURIComponent("event.severity>=medium")}&from=${t}&to=${t + 60_000}`)} />
        </Panel>
        <Panel title="Severity distribution" subtitle="All ingested events">
          <Donut data={sevDonut} height={170} />
          <div className="mt-3 grid grid-cols-5 gap-1 text-center">
            {SEVERITIES.map((s) => (
              <Link key={s} href={`/log-explorer?q=event.severity:${s}`} className="rounded-md py-1 hover:bg-raised">
                <div className="text-[13px] font-semibold tnum" style={{ color: SEV_COLOR[s] }}>{fmtCompact(m.severityDist[s])}</div>
                <div className="text-[9.5px] uppercase tracking-wider text-ink-3">{s}</div>
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Network traffic over time" subtitle="Bytes per minute by direction" className="xl:col-span-2"
          actions={<div className="flex gap-3 text-[10.5px] text-ink-3">{[["inbound", "#22d3ee"], ["outbound", "#3b82f6"], ["internal", "#a78bfa"]].map(([k, c]) => <span key={k} className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm" style={{ background: c }} />{k}</span>)}</div>}>
          <TrafficChart data={m.traffic} height={220} />
        </Panel>
        <Panel title="Event categories">
          <Donut data={m.categories.map((c, i) => ({ name: c.name, value: c.value, color: catColors[i % catColors.length] }))} height={150} />
          <ul className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 text-[11.5px]">
            {m.categories.map((c, i) => (
              <li key={c.name}><Link href={`/log-explorer?q=event.category:${c.name}`} className="flex items-center gap-1.5 hover:text-emerald">
                <span className="h-2 w-2 rounded-sm" style={{ background: catColors[i % catColors.length] }} />
                <span className="flex-1 truncate text-ink-2">{c.name}</span><span className="font-mono text-ink-3 tnum">{fmtCompact(c.value)}</span>
              </Link></li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Geographic threat map" subtitle="External event origins · demo GeoIP over RFC 5737 documentation ranges" className="xl:col-span-2" bodyClass="p-2">
          <ThreatMap points={m.geo} height={290} />
        </Panel>
        <Panel title="Top attacking source IPs" subtitle="External sources by event volume">
          <BarList items={m.topSources.filter((s) => !s.key.startsWith("10.")).slice(0, 9)} color="#ef4444" query={(k) => `source.ip:${k}`} />
        </Panel>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Panel title="Top source IPs"><BarList items={m.topSources} color="#10f0a0" query={(k) => `source.ip:${k}`} /></Panel>
        <Panel title="Top destination IPs"><BarList items={m.topDestinations} color="#22d3ee" query={(k) => `destination.ip:${k}`} /></Panel>
        <Panel title="Top destination ports"><BarList items={m.topPorts} color="#3b82f6" query={(k) => `destination.port:${k}`} /></Panel>
        <Panel title="Top targeted assets" subtitle="Medium+ severity events"><HBar data={m.topAssets.map((a) => ({ name: a.key, value: a.value }))} height={240} color="#f97316" /></Panel>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-3">
        <SevBadge s="info" /> <SevBadge s="low" /> <SevBadge s="medium" /> <SevBadge s="high" /> <SevBadge s="critical" />
        <span className="ml-2">Every panel links into Log Explorer with the matching SXQL query.</span>
      </div>
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-80" />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-6">{Array.from({ length: 12 }, (_, i) => <Skeleton key={i} className="h-[84px]" />)}</div>
      <div className="grid gap-4 xl:grid-cols-3"><Skeleton className="h-[270px] xl:col-span-2" /><Skeleton className="h-[270px]" /></div>
      <div className="grid gap-4 xl:grid-cols-3"><Skeleton className="h-[270px] xl:col-span-2" /><Skeleton className="h-[270px]" /></div>
    </div>
  );
}
