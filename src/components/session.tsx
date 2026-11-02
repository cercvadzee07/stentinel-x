"use client";

import { Lock } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, toLogin } from "@/lib/client";
import { ROLE_LABEL, can as canRole, requiredRole, type Permission, type SessionUser } from "@/lib/rbac";

interface SessionState { user: SessionUser; db: "pglite" | "postgres"; can: (p: Permission) => boolean; logout: () => Promise<void> }
const Ctx = createContext<SessionState | null>(null);

export function SessionProvider({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const [s, setS] = useState<{ user: SessionUser; db: "pglite" | "postgres" } | null>(null);
  useEffect(() => {
    api<{ user: SessionUser; db: "pglite" | "postgres" }>("/api/auth/me").then(setS).catch(() => toLogin());
  }, []);
  const logout = useCallback(async () => {
    await api("/api/auth/logout", { method: "POST", json: {}, noAuthRedirect: true }).catch(() => {});
    location.href = "/login";
  }, []);
  if (!s) return <>{fallback}</>;
  return <Ctx.Provider value={{ ...s, can: (p) => canRole(s.user.role, p), logout }}>{children}</Ctx.Provider>;
}

export function useSession(): SessionState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

/** Tooltip text for a control the current role may not use (UI hint only; the API enforces it). */
export const deniedHint = (p: Permission) => `Requires ${ROLE_LABEL[requiredRole(p)]} role`;

export function Forbidden({ perm }: { perm: Permission }) {
  return (
    <div className="mx-auto mt-16 max-w-md rounded-2xl border border-line bg-panel/70 p-8 text-center">
      <div className="mx-auto grid h-11 w-11 place-items-center rounded-full border border-line-strong bg-raised"><Lock className="h-5 w-5 text-ink-3" /></div>
      <h1 className="mt-4 text-lg font-semibold">Access restricted</h1>
      <p className="mt-1 text-[13px] text-ink-3">{deniedHint(perm)}. Ask an administrator of your organization if you need access.</p>
    </div>
  );
}
