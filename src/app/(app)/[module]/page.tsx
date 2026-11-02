import { CheckCircle2, Circle } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { NAV } from "@/lib/nav";

/** Roadmap page for modules scheduled in later phases. States plainly what exists and what does not. */
export function generateStaticParams() {
  return NAV.filter((n) => !n.ready).map((n) => ({ module: n.href.slice(1) }));
}

export async function generateMetadata({ params }: { params: Promise<{ module: string }> }) {
  const { module } = await params;
  return { title: NAV.find((n) => n.href === `/${module}`)?.label ?? "Not found" };
}

export default async function ModulePage({ params }: { params: Promise<{ module: string }> }) {
  const { module } = await params;
  const item = NAV.find((n) => n.href === `/${module}` && !n.ready);
  if (!item) notFound();
  const Icon = item.icon;
  const shipped = NAV.filter((n) => n.ready);
  return (
    <div className="mx-auto max-w-3xl py-10">
      <div className="glass rounded-2xl p-8">
        <div className="flex items-center gap-4">
          <div className="grid h-12 w-12 place-items-center rounded-xl border border-line-strong bg-raised"><Icon className="h-6 w-6 text-cyan" /></div>
          <div>
            <div className="text-[11px] uppercase tracking-[0.16em] text-ink-3">{item.group} · Roadmap phase {item.phase}</div>
            <h1 className="text-xl font-semibold">{item.label}</h1>
          </div>
        </div>
        <p className="mt-5 text-[14px] leading-relaxed text-ink-2">{item.summary}.</p>
        <p className="mt-3 text-[13px] leading-relaxed text-ink-3">
          This module is not built yet — there are intentionally no controls here, so nothing on this page pretends to work.
          It ships in phase {item.phase} on top of the same engine (normalized event store, SXQL, correlation, alerting) that powers the modules below.
        </p>
        <div className="mt-6 text-[11px] uppercase tracking-wider text-ink-3">Available now</div>
        <ul className="mt-2 grid gap-1.5 sm:grid-cols-2">
          {shipped.map((n) => (
            <li key={n.href}><Link href={n.href} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-[13px] text-ink-2 hover:bg-raised hover:text-ink"><CheckCircle2 className="h-4 w-4 text-emerald" />{n.label}</Link></li>
          ))}
        </ul>
        <div className="mt-5 text-[11px] uppercase tracking-wider text-ink-3">Also scheduled</div>
        <ul className="mt-2 grid gap-1 sm:grid-cols-2">
          {NAV.filter((n) => !n.ready && n.href !== item.href).map((n) => (
            <li key={n.href} className="flex items-center gap-2 px-2 py-1 text-[12.5px] text-ink-3"><Circle className="h-3.5 w-3.5" />{n.label} <span className="font-mono text-[10px]">P{n.phase}</span></li>
          ))}
        </ul>
      </div>
    </div>
  );
}
