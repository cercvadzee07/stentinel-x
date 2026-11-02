"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button, ErrorState, Field, Input } from "@/components/ui";
import { ApiError, api } from "@/lib/client";

export default function SignupPage() {
  const router = useRouter();
  const [f, setF] = useState({ orgName: "", name: "", email: "", password: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [issues, setIssues] = useState<Record<string, string>>({});
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null); setIssues({});
    try {
      await api("/api/auth/signup", { method: "POST", json: f, noAuthRedirect: true });
      router.replace("/");
      router.refresh();
    } catch (x) {
      const list = ((x as ApiError).data as { issues?: { path: string; message: string }[] })?.issues ?? [];
      setIssues(Object.fromEntries(list.map((i) => [i.path, i.message])));
      setErr((x as Error).message);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="glass rounded-2xl p-6">
      <h1 className="text-[17px] font-semibold">Create an organization</h1>
      <p className="mt-1 text-[12.5px] text-ink-3">You become its first administrator. New tenants start empty — no simulated data — until you ingest events or start the simulator.</p>
      <div className="mt-5 space-y-3">
        <Field label="Organization" error={issues.orgName}><Input required value={f.orgName} onChange={set("orgName")} autoFocus /></Field>
        <Field label="Your name" error={issues.name}><Input required value={f.name} onChange={set("name")} autoComplete="name" /></Field>
        <Field label="Work email" error={issues.email}><Input type="email" required value={f.email} onChange={set("email")} autoComplete="email" /></Field>
        <Field label="Password" error={issues.password} hint="At least 10 characters with letters and digits."><Input type="password" required value={f.password} onChange={set("password")} autoComplete="new-password" /></Field>
        {err && !Object.keys(issues).length && <ErrorState message={err} />}
        <Button type="submit" variant="primary" loading={busy} className="h-10 w-full">Create organization <ArrowRight className="h-4 w-4" /></Button>
      </div>
      <div className="mt-4 text-center text-[12px] text-ink-3">Already have an account? <Link href="/login" className="text-emerald hover:underline">Sign in</Link></div>
    </form>
  );
}
