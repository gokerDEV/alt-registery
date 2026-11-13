import crypto from "node:crypto";
import { EncryptJWT, jwtDecrypt } from "jose";
import { cookies } from "next/headers";
import {
  getBaseConfig,
  getSessionSecretString,
  isHttpsAppUrl,
} from "@/lib/env";

const SESSION_ISSUER = "urn:alt-registry:web";
const SESSION_AUDIENCE = "urn:alt-registry:browser";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days
const OAUTH_FLOW_MAX_AGE_SECONDS = 60 * 10; // 10 minutes

export interface WebSessionClaims {
  accountId: string; // MongoDB ObjectId hex
  githubId: string; // immutable numeric GitHub ID as decimal string
  githubLogin: string;
  avatarUrl?: string;
  csrfToken: string; // per-session anti-CSRF secret
}

interface OAuthFlowClaims {
  state: string;
  codeVerifier: string;
}

function deriveAes256Key(purpose: string): Uint8Array | null {
  const secret = getSessionSecretString();
  if (!secret) {
    return null;
  }
  const derived = crypto.hkdfSync(
    "sha256",
    Buffer.from(secret, "utf8"),
    Buffer.from("alt-registry-cookie-v1", "utf8"),
    Buffer.from(purpose, "utf8"),
    32,
  );
  return new Uint8Array(derived);
}

export function getSessionCookieName(): string {
  return isHttpsAppUrl() ? "__Host-alt_session" : "alt_session";
}

export function getOAuthFlowCookieName(): string {
  return isHttpsAppUrl() ? "__Host-alt_oauth" : "alt_oauth";
}

export async function createEncryptedSessionToken(
  claims: Omit<WebSessionClaims, "csrfToken"> & { csrfToken?: string },
): Promise<{ token: string; csrfToken: string }> {
  const key = deriveAes256Key("web-session-jwe");
  if (!key) {
    throw new Error(
      "SESSION_SECRET must be configured with at least 32 characters",
    );
  }
  const csrfToken =
    claims.csrfToken ?? crypto.randomBytes(24).toString("base64url");

  const token = await new EncryptJWT({
    accountId: claims.accountId,
    githubId: claims.githubId,
    githubLogin: claims.githubLogin,
    ...(claims.avatarUrl ? { avatarUrl: claims.avatarUrl } : {}),
    csrfToken,
  })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuer(SESSION_ISSUER)
    .setAudience(SESSION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_MAX_AGE_SECONDS}s`)
    .encrypt(key);

  return { token, csrfToken };
}

export async function decryptSessionToken(
  token: string,
): Promise<WebSessionClaims | null> {
  const key = deriveAes256Key("web-session-jwe");
  if (!key || !token) {
    return null;
  }
  try {
    const { payload } = await jwtDecrypt(token, key, {
      issuer: SESSION_ISSUER,
      audience: SESSION_AUDIENCE,
      contentEncryptionAlgorithms: ["A256GCM"],
      keyManagementAlgorithms: ["dir"],
    });

    if (
      typeof payload.accountId !== "string" ||
      typeof payload.githubId !== "string" ||
      typeof payload.githubLogin !== "string" ||
      typeof payload.csrfToken !== "string"
    ) {
      return null;
    }

    return {
      accountId: payload.accountId,
      githubId: payload.githubId,
      githubLogin: payload.githubLogin,
      avatarUrl:
        typeof payload.avatarUrl === "string" ? payload.avatarUrl : undefined,
      csrfToken: payload.csrfToken,
    };
  } catch {
    return null;
  }
}

export async function readWebSessionFromCookies(): Promise<WebSessionClaims | null> {
  const cookieStore = await cookies();
  const raw = cookieStore.get(getSessionCookieName())?.value;
  if (!raw) {
    return null;
  }
  return decryptSessionToken(raw);
}

export function buildSessionCookieOptions(maxAge = SESSION_MAX_AGE_SECONDS) {
  const secure = isHttpsAppUrl();
  return {
    name: getSessionCookieName(),
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    maxAge,
  };
}

export async function createEncryptedOAuthFlowCookie(
  flow: OAuthFlowClaims,
): Promise<string> {
  const key = deriveAes256Key("oauth-flow-jwe");
  if (!key) {
    throw new Error(
      "SESSION_SECRET must be configured with at least 32 characters",
    );
  }
  return new EncryptJWT({
    state: flow.state,
    codeVerifier: flow.codeVerifier,
  })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuer(SESSION_ISSUER)
    .setAudience("urn:alt-registry:oauth-flow")
    .setIssuedAt()
    .setExpirationTime(`${OAUTH_FLOW_MAX_AGE_SECONDS}s`)
    .encrypt(key);
}

export async function decryptOAuthFlowCookie(
  token: string,
): Promise<OAuthFlowClaims | null> {
  const key = deriveAes256Key("oauth-flow-jwe");
  if (!key || !token) {
    return null;
  }
  try {
    const { payload } = await jwtDecrypt(token, key, {
      issuer: SESSION_ISSUER,
      audience: "urn:alt-registry:oauth-flow",
      contentEncryptionAlgorithms: ["A256GCM"],
      keyManagementAlgorithms: ["dir"],
    });
    if (
      typeof payload.state !== "string" ||
      typeof payload.codeVerifier !== "string"
    ) {
      return null;
    }
    return {
      state: payload.state,
      codeVerifier: payload.codeVerifier,
    };
  } catch {
    return null;
  }
}

export function buildOAuthFlowCookieOptions(
  maxAge = OAUTH_FLOW_MAX_AGE_SECONDS,
) {
  return {
    name: getOAuthFlowCookieName(),
    httpOnly: true,
    secure: isHttpsAppUrl(),
    sameSite: "lax" as const,
    path: "/",
    maxAge,
  };
}

export function generatePkcePair(): {
  state: string;
  codeVerifier: string;
  codeChallenge: string;
} {
  const state = crypto.randomBytes(24).toString("base64url");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { state, codeVerifier, codeChallenge };
}

export function timingSafeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.byteLength !== bufB.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Enforces strict `Origin === APP_URL` and Fetch Metadata (`Sec-Fetch-Site`) checks
 * for cookie-authenticated browser mutations (§4.1, §13).
 */
export function verifyBrowserMutationRequest(
  request: Request,
  expectedCsrfToken?: string,
): { ok: true } | { ok: false; code: string; message: string } {
  const { APP_URL } = getBaseConfig();
  const origin = request.headers.get("origin");
  if (!origin || origin !== APP_URL) {
    return {
      ok: false,
      code: "FORBIDDEN_ORIGIN",
      message: `Origin header must match ${APP_URL}`,
    };
  }

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return {
      ok: false,
      code: "CROSS_SITE_REJECTED",
      message: "Cross-site browser mutations are rejected",
    };
  }

  if (expectedCsrfToken) {
    const providedCsrf = request.headers.get("x-csrf-token") ?? "";
    if (
      !providedCsrf ||
      !timingSafeEqualStrings(providedCsrf, expectedCsrfToken)
    ) {
      return {
        ok: false,
        code: "INVALID_CSRF_TOKEN",
        message: "Missing or invalid CSRF token",
      };
    }
  }

  return { ok: true };
}
