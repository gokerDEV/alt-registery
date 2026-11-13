import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { getBaseConfig } from "@/lib/env";

/**
 * Next.js 16 Proxy (`src/proxy.ts`):
 * When `dotALT` proxies `https://register.alt`, it rewrites `Host` to the target origin,
 * strips `X-Forwarded-Host`, and sets `X-Alt-Domain: register.alt` (§4.1).
 * Browser navigation carrying `X-Alt-Domain: register.<tld>` receives a 307 redirect
 * strictly to the fixed, server-configured `APP_URL` — never to an untrusted header value.
 */
export function proxy(request: NextRequest) {
  const { APP_URL, ALT_TLD } = getBaseConfig();
  const altDomain = request.headers.get("x-alt-domain")?.trim().toLowerCase();

  if (altDomain === `register.${ALT_TLD}`) {
    const destUrl = new URL(
      `${request.nextUrl.pathname}${request.nextUrl.search}`,
      APP_URL,
    );
    return NextResponse.redirect(destUrl, 307);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
