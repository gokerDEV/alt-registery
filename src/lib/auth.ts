import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { getCliPepper, getWebAuthConfig } from "@/lib/env";
import { type AccountDoc, getCollections, toMongoLong } from "@/lib/mongodb";
import {
  decryptSessionToken,
  getSessionCookieName,
  timingSafeEqualStrings,
  verifyBrowserMutationRequest,
  type WebSessionClaims,
} from "@/lib/session";

export interface GitHubUserProfile {
  id: number;
  login: string;
  avatar_url?: string;
}

export interface AuthenticatedContext {
  authType: "web" | "cli";
  account: AccountDoc;
  webSession?: WebSessionClaims;
  cliSessionId?: ObjectId;
}

/**
 * Exchanges a GitHub authorization code (with PKCE code_verifier) for a short-lived user access token.
 */
export async function exchangeGitHubOAuthCode(params: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<string> {
  const cfg = getWebAuthConfig();
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "alt-registry/0.1",
    },
    body: JSON.stringify({
      client_id: cfg.GITHUB_CLIENT_ID,
      client_secret: cfg.GITHUB_CLIENT_SECRET,
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    }),
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) {
    throw new Error(
      `GitHub token exchange failed with HTTP ${response.status}`,
    );
  }

  const data = (await response.json()) as {
    access_token?: string;
    error?: string;
  };

  if (!data.access_token || typeof data.access_token !== "string") {
    throw new Error(
      `GitHub token exchange returned error: ${data.error ?? "missing_access_token"}`,
    );
  }
  return data.access_token;
}

/**
 * Validates a GitHub user token directly against `GET https://api.github.com/user`
 * and extracts the immutable numeric `id`, `login`, and `avatar_url` (§4.1, §4.2).
 */
export async function fetchGitHubUser(
  githubAccessToken: string,
): Promise<GitHubUserProfile> {
  const response = await fetch("https://api.github.com/user", {
    method: "GET",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${githubAccessToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "alt-registry/0.1",
    },
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) {
    throw new Error(`GitHub GET /user failed with HTTP ${response.status}`);
  }

  const data = (await response.json()) as {
    id?: unknown;
    login?: unknown;
    avatar_url?: unknown;
  };

  if (
    typeof data.id !== "number" ||
    !Number.isSafeInteger(data.id) ||
    data.id <= 0 ||
    typeof data.login !== "string" ||
    data.login.trim() === ""
  ) {
    throw new Error("GitHub user response missing numeric id or login");
  }

  return {
    id: data.id,
    login: data.login.trim(),
    avatar_url:
      typeof data.avatar_url === "string" &&
      data.avatar_url.startsWith("https://")
        ? data.avatar_url
        : undefined,
  };
}

/**
 * Upserts an account keyed strictly by GitHub's immutable numeric `githubId` (`Long`).
 * `githubLogin` and `avatarUrl` are refreshed as display metadata only (§4.1, §5).
 */
export async function upsertAccountFromGitHub(
  profile: GitHubUserProfile,
): Promise<AccountDoc> {
  const { accounts } = await getCollections();
  const now = new Date();
  const githubIdLong = toMongoLong(profile.id);

  const setFields: Partial<AccountDoc> = {
    githubLogin: profile.login,
    updatedAt: now,
  };
  if (profile.avatar_url) {
    setFields.avatarUrl = profile.avatar_url;
  }

  const updated = await accounts.findOneAndUpdate(
    { githubId: githubIdLong },
    {
      $set: setFields,
      $setOnInsert: {
        githubId: githubIdLong,
        createdAt: now,
      },
    },
    {
      upsert: true,
      returnDocument: "after",
    },
  );

  if (!updated) {
    throw new Error("Failed to upsert GitHub account");
  }
  return updated;
}

export function hashCliToken(rawToken: string): string {
  const pepper = getCliPepper();
  return crypto
    .createHmac("sha256", Buffer.from(pepper, "utf8"))
    .update(rawToken, "utf8")
    .digest("hex");
}

function extractCookieFromHeader(
  cookieHeader: string | null,
  cookieName: string,
): string | null {
  if (!cookieHeader) {
    return null;
  }
  for (const part of cookieHeader.split(";")) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const k = part.slice(0, eqIdx).trim();
    if (k === cookieName) {
      return decodeURIComponent(part.slice(eqIdx + 1).trim());
    }
  }
  return null;
}

/**
 * Authenticates a request via either:
 * 1. `Authorization: Bearer <alt-cli-token>` (CLI bearer session), or
 * 2. Encrypted HTTP-only `jose` web session cookie (enforcing Origin + CSRF on mutations).
 */
export async function authenticateRequest(
  request: Request,
  options: {
    requireMutationCsrf?: boolean;
    allowWeb?: boolean;
    allowCli?: boolean;
  } = {},
): Promise<
  | { ok: true; ctx: AuthenticatedContext }
  | { ok: false; status: number; code: string; message: string }
> {
  const allowWeb = options.allowWeb ?? true;
  const allowCli = options.allowCli ?? true;

  const authHeader = request.headers.get("authorization");
  if (authHeader) {
    if (!allowCli) {
      return {
        ok: false,
        status: 403,
        code: "CLI_AUTH_NOT_ALLOWED",
        message: "This endpoint does not accept CLI bearer tokens",
      };
    }
    if (!authHeader.startsWith("Bearer ")) {
      return {
        ok: false,
        status: 401,
        code: "INVALID_AUTH_HEADER",
        message: "Authorization header must use Bearer scheme",
      };
    }
    const rawToken = authHeader.slice("Bearer ".length).trim();
    if (!rawToken) {
      return {
        ok: false,
        status: 401,
        code: "MISSING_BEARER_TOKEN",
        message: "Bearer token is empty",
      };
    }

    let tokenHash: string;
    try {
      tokenHash = hashCliToken(rawToken);
    } catch {
      return {
        ok: false,
        status: 503,
        code: "CLI_AUTH_UNCONFIGURED",
        message: "CLI authentication is not configured on this server",
      };
    }

    const { cliSessions, accounts } = await getCollections();
    const now = new Date();
    const sessionDoc = await cliSessions.findOne({ tokenHash });
    if (
      !sessionDoc ||
      !timingSafeEqualStrings(sessionDoc.tokenHash, tokenHash) ||
      sessionDoc.revokedAt ||
      sessionDoc.expiresAt.getTime() <= now.getTime()
    ) {
      return {
        ok: false,
        status: 401,
        code: "INVALID_CLI_TOKEN",
        message: "CLI session token is invalid, expired, or revoked",
      };
    }

    const account = await accounts.findOne({ _id: sessionDoc.accountId });
    if (!account) {
      return {
        ok: false,
        status: 401,
        code: "ACCOUNT_NOT_FOUND",
        message: "Account associated with CLI session no longer exists",
      };
    }

    void cliSessions.updateOne(
      { _id: sessionDoc._id },
      { $set: { lastUsedAt: now } },
    );

    return {
      ok: true,
      ctx: {
        authType: "cli",
        account,
        cliSessionId: sessionDoc._id,
      },
    };
  }

  if (!allowWeb) {
    return {
      ok: false,
      status: 401,
      code: "CLI_TOKEN_REQUIRED",
      message: "A valid ALT CLI bearer token is required",
    };
  }

  const rawCookie = extractCookieFromHeader(
    request.headers.get("cookie"),
    getSessionCookieName(),
  );
  if (!rawCookie) {
    return {
      ok: false,
      status: 401,
      code: "UNAUTHENTICATED",
      message: "Authentication required",
    };
  }

  const webSession = await decryptSessionToken(rawCookie);
  if (!webSession || !ObjectId.isValid(webSession.accountId)) {
    return {
      ok: false,
      status: 401,
      code: "INVALID_SESSION",
      message: "Session is invalid or expired",
    };
  }

  if (options.requireMutationCsrf) {
    const check = verifyBrowserMutationRequest(request, webSession.csrfToken);
    if (!check.ok) {
      return {
        ok: false,
        status: 403,
        code: check.code,
        message: check.message,
      };
    }
  }

  const { accounts } = await getCollections();
  const account = await accounts.findOne({
    _id: new ObjectId(webSession.accountId),
  });

  if (!account || account.githubId.toString() !== webSession.githubId) {
    return {
      ok: false,
      status: 401,
      code: "ACCOUNT_NOT_FOUND",
      message: "Authenticated account was not found",
    };
  }

  return {
    ok: true,
    ctx: {
      authType: "web",
      account,
      webSession,
    },
  };
}
