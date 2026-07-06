import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  // We want to protect the root / and any paths under /scans or /history
  // Basically, protect everything except /login and /api
  
  const pathname = request.nextUrl.pathname;
  
  if (pathname.startsWith("/login") || pathname.startsWith("/api") || pathname.startsWith("/_next") || pathname === "/favicon.ico") {
    return NextResponse.next();
  }

  const authCookie = request.cookies.get("sentinel_auth");
  
  // Very simple auth check: cookie must exist and have value 'authenticated'
  if (!authCookie || authCookie.value !== "authenticated") {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}
