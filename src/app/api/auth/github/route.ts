import { connection, NextResponse } from "next/server";
import { getWebAuthConfig, redactErrorMessage } from "@/lib/env";
import {
  buildOAuthFlowCookieOptions,
  createEncryptedOAuthFlowCookie,
  generatePkcePair,
} from "@/lib/session";

export async function GET(request: Request) {
  await connection();
  try {
    const cfg = getWebAuthConfig();
    const altDomain = request.headers.get("x-alt-domain")?.trim().toLowerCase();
    if (altDomain === `register.${cfg.ALT_TLD}`) {
      return NextResponse.redirect(
        new URL("/api/auth/github", cfg.APP_URL),
        307,
      );
    }

    const { state, codeVerifier, codeChallenge } = generatePkcePair();
    const encryptedFlow = await createEncryptedOAuthFlowCookie({
      state,
      codeVerifier,
    });

    const redirectUri = `${cfg.APP_URL}/api/auth/callback/github`;
    const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
    authorizeUrl.searchParams.set("client_id", cfg.GITHUB_CLIENT_ID);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    // Minimum identity scope: empty scope reads public profile + numeric user ID without private repo/email access
    authorizeUrl.searchParams.set("scope", "");

    const response = NextResponse.redirect(authorizeUrl, 302);
    response.headers.set("Cache-Control", "no-store");
    response.cookies.set({
      ...buildOAuthFlowCookieOptions(),
      value: encryptedFlow,
    });
    return response;
  } catch (err) {
    console.error(
      "[auth/github] Configuration error:",
      redactErrorMessage(err),
    );
    const fallbackUrl = new URL("/?error=auth_unconfigured", request.url);
    return NextResponse.redirect(fallbackUrl, 302);
  }
}
