import { describe, expect, test } from "bun:test";
import { NextRequest } from "next/server";
import nextConfig from "../next.config";
import { getBaseConfig } from "../src/lib/env";
import { proxy } from "../src/proxy";

describe("proxy: X-Alt-Domain register.alt canonical redirect", () => {
  test("enables skipProxyUrlNormalize so Next.js never relativizes same-host Location to /", () => {
    expect(nextConfig.skipProxyUrlNormalize).toBe(true);
  });

  test("redirects X-Alt-Domain: register.alt to absolute APP_URL and strips internal _rsc query", () => {
    const { APP_URL, ALT_TLD } = getBaseConfig();

    const rootReq = new NextRequest(`${APP_URL}/`, {
      headers: {
        host: new URL(APP_URL).host,
        "x-alt-domain": `register.${ALT_TLD}`,
      },
    });
    const rootRes = proxy(rootReq);
    expect(rootRes.status).toBe(307);
    expect(rootRes.headers.get("location")).toBe(`${APP_URL}/`);

    const subPathReq = new NextRequest(
      `${APP_URL}/dashboard?tab=keys&_rsc=internal123`,
      {
        headers: {
          host: new URL(APP_URL).host,
          "x-alt-domain": `  REGISTER.${ALT_TLD}  `,
        },
      },
    );
    const subPathRes = proxy(subPathReq);
    expect(subPathRes.status).toBe(307);
    expect(subPathRes.headers.get("location")).toBe(
      `${APP_URL}/dashboard?tab=keys`,
    );
  });

  test("passes through direct requests and non-registry X-Alt-Domain headers without redirect", () => {
    const { APP_URL } = getBaseConfig();

    const directRes = proxy(new NextRequest(`${APP_URL}/`));
    expect(directRes.status).toBe(200);
    expect(directRes.headers.get("x-middleware-next")).toBe("1");
    expect(directRes.headers.get("location")).toBeNull();

    const otherAltRes = proxy(
      new NextRequest(`${APP_URL}/`, {
        headers: { "x-alt-domain": "goker.alt" },
      }),
    );
    expect(otherAltRes.status).toBe(200);
    expect(otherAltRes.headers.get("x-middleware-next")).toBe("1");
    expect(otherAltRes.headers.get("location")).toBeNull();
  });
});
