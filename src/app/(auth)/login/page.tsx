import { Suspense } from "react";
import { LoginForm } from "./form";

export const metadata = { title: "Sign in" };
// read DEMO_MODE / ALLOW_SIGNUP at request time, not at build time
export const dynamic = "force-dynamic";

/** Demo accounts are listed only on demo deployments (DEMO_MODE != "0"). Their password is documented in src/server/db/seed.ts. */
export default function LoginPage() {
  const demo = process.env.DEMO_MODE !== "0" && process.env.SEED_DEMO !== "0";
  return <Suspense><LoginForm demo={demo} signup={process.env.ALLOW_SIGNUP !== "0"} /></Suspense>;
}
