import { cookies } from "next/headers";
import { connection, NextResponse } from "next/server";
import {
  exchangeGitHubOAuthCode,
  fetchGitHubUser,
  upsertAccountFromGitHub,
} from "@/lib/auth";
import { getWebAuthConfig, redactErrorMessage } from "@/lib/env";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";
import {
  buildOAuthFlowCookieOptions,
  buildSessionCookieOptions,
  createEncryptedSessionToken,
  decryptOAuthFlowCookie,
  getOAuthFlowCookieName,
  timingSafeEqualStrings,
} from "@/lib/session";

export async function GET(request: Request) {
  await connection();
  let appUrl = "http://localhost:3000";
  try {
    const cfg = getWebAuthConfig();
    appUrl = cfg.APP_URL;

    // Rate-limit OAuth callback attempts per IP (§13)
    const rl = await checkRateLimit(extractClientSubject(request), {
      action: "oauth_callback",
      limit: 20,
      windowSeconds: 60,
    });
    if (!rl.allowed) {
      return NextResponse.redirect(
        new URL("/?error=rate_limited", appUrl),
        302,
      );
    }

    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");
    const oauthError = url.searchParams.get("error");

    const cookieStore = await cookies();
    const rawFlowCookie = cookieStore.get(getOAuthFlowCookieName())?.value;

    const redirectWithError = (reason: string) => {
      const res = NextResponse.redirect(
        new URL(`/?error=${encodeURIComponent(reason)}`, appUrl),
        302,
      );
      res.headers.set("Cache-Control", "no-store");
      res.cookies.set({
        ...buildOAuthFlowCookieOptions(0),
        value: "",
      });
      return res;
    };

    if (oauthError) {
      return redirectWithError("oauth_denied");
    }
    if (!code || !returnedState || !rawFlowCookie) {
      return redirectWithError("invalid_oauth_state");
    }

    const flow = await decryptOAuthFlowCookie(rawFlowCookie);
    if (!flow || !timingSafeEqualStrings(flow.state, returnedState)) {
      return redirectWithError("invalid_oauth_state");
    }

    const redirectUri = `${appUrl}/api/auth/callback/github`;
    const githubAccessToken = await exchangeGitHubOAuthCode({
      code,
      codeVerifier: flow.codeVerifier,
      redirectUri,
    });

    const githubProfile = await fetchGitHubUser(githubAccessToken);
    const account = await upsertAccountFromGitHub(githubProfile);

    // Regenerate fresh encrypted session cookie after login (§4.1)
    const { token: sessionJwt } = await createEncryptedSessionToken({
      accountId: account._id.toHexString(),
      githubId: account.githubId.toString(),
      githubLogin: account.githubLogin,
      avatarUrl: account.avatarUrl,
    });

    const response = NextResponse.redirect(new URL("/dashboard", appUrl), 302);
    response.headers.set("Cache-Control", "no-store");
    response.cookies.set({
      ...buildOAuthFlowCookieOptions(0),
      value: "",
    });
    response.cookies.set({
      ...buildSessionCookieOptions(),
      value: sessionJwt,
    });

    return response;
  } catch (err) {
    console.error(
      "[auth/callback/github] Login failed:",
      redactErrorMessage(err),
    );
    const response = NextResponse.redirect(
      new URL("/?error=login_failed", appUrl),
      302,
    );
    response.headers.set("Cache-Control", "no-store");
    response.cookies.set({
      ...buildOAuthFlowCookieOptions(0),
      value: "",
    });
    return response;
  }
}
