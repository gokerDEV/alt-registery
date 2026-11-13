import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { z } from "zod";
import { jsonError, jsonOk, serializePublicAccount } from "@/lib/api-response";
import {
  authenticateRequest,
  fetchGitHubUser,
  hashCliToken,
  upsertAccountFromGitHub,
} from "@/lib/auth";
import { redactErrorMessage } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";

const CLI_SESSION_TTL_DAYS = 30;
const CLI_TOKEN_PREFIX = "alt_cli_";

const exchangeBodySchema = z
  .object({
    githubAccessToken: z
      .string()
      .trim()
      .min(1, "`githubAccessToken` is required"),
  })
  .strict();

export async function POST(request: Request) {
  try {
    const rl = await checkRateLimit(extractClientSubject(request), {
      action: "cli_session_exchange",
      limit: 15,
      windowSeconds: 60,
    });
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many CLI login attempts; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return jsonError(400, "INVALID_JSON", "Request body must be valid JSON");
    }

    const parsedBody = exchangeBodySchema.safeParse(rawJson);
    if (!parsedBody.success) {
      return jsonError(
        400,
        "INVALID_BODY",
        parsedBody.error.issues[0]?.message ?? "Invalid request payload",
      );
    }

    // Validate the GitHub access token directly against GitHub GET /user (§4.2)
    let ghProfile: Awaited<ReturnType<typeof fetchGitHubUser>>;
    try {
      ghProfile = await fetchGitHubUser(parsedBody.data.githubAccessToken);
    } catch {
      return jsonError(
        401,
        "INVALID_GITHUB_TOKEN",
        "GitHub access token validation failed",
      );
    }

    const account = await upsertAccountFromGitHub(ghProfile);

    // 256-bit CSPRNG token; store ONLY HMAC-SHA256(CLI_TOKEN_PEPPER, rawToken) in MongoDB (§4.2, §5)
    const rawToken = `${CLI_TOKEN_PREFIX}${crypto.randomBytes(32).toString("base64url")}`;
    const tokenHash = hashCliToken(rawToken);
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + CLI_SESSION_TTL_DAYS * 24 * 60 * 60 * 1000,
    );

    const { cliSessions } = await getCollections();
    await cliSessions.insertOne({
      _id: new ObjectId(),
      accountId: account._id,
      tokenHash,
      createdAt: now,
      expiresAt,
    });

    return jsonOk(
      {
        token: rawToken,
        expiresAt: expiresAt.toISOString(),
        account: serializePublicAccount(account),
      },
      201,
    );
  } catch (err) {
    console.error("[POST /api/cli/session] Error:", redactErrorMessage(err));
    return jsonError(500, "INTERNAL_ERROR", "CLI session exchange failed");
  }
}

export async function DELETE(request: Request) {
  try {
    const auth = await authenticateRequest(request, {
      allowWeb: false,
      allowCli: true,
    });
    if (!auth.ok) {
      return jsonError(auth.status, auth.code, auth.message);
    }

    if (auth.ctx.cliSessionId) {
      const { cliSessions } = await getCollections();
      await cliSessions.updateOne(
        { _id: auth.ctx.cliSessionId },
        { $set: { revokedAt: new Date() } },
      );
    }

    return jsonOk({ revoked: true });
  } catch (err) {
    console.error("[DELETE /api/cli/session] Error:", redactErrorMessage(err));
    return jsonError(500, "INTERNAL_ERROR", "CLI session revocation failed");
  }
}
