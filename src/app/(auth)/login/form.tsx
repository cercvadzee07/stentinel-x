"use client";

import { ArrowRight, Eye, EyeOff, KeyRound, Lock } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { Button, ErrorState, Field, Input } from "@/components/ui";
import { api } from "@/lib/client";

const DEMO = [
  { email: "admin@acme.test", role: "Administrator", note: "everything, incl. users, rules, simulator" },
  { email: "analyst@acme.test", role: "SOC Analyst", note: "triage, incidents, assets, scenarios" },
  { email: "viewer@acme.test", role: "Read-only", note: "dashboards and search only" },
];

/** Only allow same-site relative redirects after login (no open redirect). */
const safeNext = (n: string | null) => (n && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/\\") ? n : "/");

export function LoginForm({ demo, signup }: { demo: boolean; signup: boolean }) {
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await api("/api/auth/login", { method: "POST", json: { email, password }, noAuthRedirect: true });
      router.replace(safeNext(params.get("next")));
      router.refresh();
    } catch (x) { setErr((x as Error).message); setBusy(false); }
  };

  return (
    <>
      <form onSubmit={submit} className="glass rounded-2xl p-6">
        <h1 className="text-[17px] font-semibold">Sign in to the console</h1>
        <p className="mt-1 text-[12.5px] text-ink-3">Your session is bound to your organization and role.</p>
        <div className="mt-5 space-y-3">
          <Field label="Email"><Input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></Field>
          <Field label="Password">
            <div className="relative">
              <Input type={show ? "text" : "password"} autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pr-9" />
              <button type="button" onClick={() => setShow((v) => !v)} aria-label={show ? "Hide password" : "Show password"} className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-3 hover:text-ink">
                {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </Field>
          {err && <ErrorState message={err} />}
          <Button type="submit" variant="primary" loading={busy} className="h-10 w-full">Sign in <ArrowRight className="h-4 w-4" /></Button>
        </div>
        <div className="mt-4 flex items-center justify-between text-[11.5px] text-ink-3">
          <span className="flex items-center gap-1.5"><Lock className="h-3 w-3" />5 failed attempts lock the account for 15 min</span>
          {signup && <Link href="/signup" className="text-emerald hover:underline">Create organization</Link>}
        </div>
      </form>
      {demo && (
        <div className="mt-4 rounded-xl border border-violet/30 bg-violet/[0.06] p-4">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-violet"><KeyRound className="h-3.5 w-3.5" />Demo tenant · ACME Corp</div>
          <p className="mt-1 text-[11.5px] text-ink-3">Pick an account to prefill the email. The shared demo password is documented in <code className="font-mono text-ink-2">src/server/db/seed.ts</code>.</p>
          <div className="mt-2 space-y-1">
            {DEMO.map((d) => (
              <button key={d.email} type="button" onClick={() => setEmail(d.email)} className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-raised">
                <span className="font-mono text-[12px] text-ink">{d.email}</span>
                <span className="ml-auto text-right text-[10.5px] text-ink-3"><span className="text-ink-2">{d.role}</span> · {d.note}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
