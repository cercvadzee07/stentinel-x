import { NextResponse, type NextRequest } from "next/server";

/**
 * Edge gate for pages only: no session cookie → /login. This is a UX redirect,
 * not the security boundary — every API route validates the session and the
 * user's permissions server-side (src/server/context.ts).
 */
export function middleware(req: NextRequest) {
  if (req.cookies.get("sx_session")?.value) return NextResponse.next();
  const url = req.nextUrl.clone();
  const next = req.nextUrl.pathname + req.nextUrl.search;
  url.pathname = "/login";
  url.search = next && next !== "/" ? `?next=${encodeURIComponent(next)}` : "";
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ["/((?!api|_next|login|signup|favicon.ico|.*\\.(?:svg|png|ico|txt)$).*)"],
};
