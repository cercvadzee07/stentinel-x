import { Shield } from "lucide-react";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="ambient relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-emerald/50 to-transparent" />
      <div className="w-full max-w-[400px]">
        <div className="mb-7 flex flex-col items-center text-center">
          <div className="grid h-12 w-12 place-items-center rounded-xl border border-emerald/40 bg-emerald/10 glow-emerald">
            <Shield className="h-6 w-6 text-emerald" strokeWidth={2.2} />
          </div>
          <div className="mt-3 text-[15px] font-bold tracking-[0.25em]">SENTINEL<span className="text-emerald"> X</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.2em] text-ink-3">SIEM · SOC · NOC</div>
        </div>
        {children}
      </div>
    </div>
  );
}
