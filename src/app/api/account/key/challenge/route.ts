import crypto from "node:crypto";
import { ObjectId } from "mongodb";
import { jsonError, jsonOk } from "@/lib/api-response";
import { authenticateRequest, hashCliToken } from "@/lib/auth";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";
import { formatUtcRfc3339Seconds } from "@/lib/records";

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes (§4.3)

export async function POST(request: Request) {
  try {
    const auth = await authenticateRequest(request, {
      allowWeb: false,
      allowCli: true,
    });
    if (!auth.ok) {
      return jsonError(auth.status, auth.code, auth.message);
    }

    const rl = await checkRateLimit(
      extractClientSubject(request, auth.ctx.account._id.toHexString()),
      {
        action: "account_key_challenge",
        limit: 15,
        windowSeconds: 60,
      },
    );
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many challenge requests; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    // Key replacement/recovery is outside MVP (§4.3); reject if a key is already bound
    if (auth.ctx.account.ownerPublicKey) {
      return jsonError(
        409,
        "KEY_ALREADY_BOUND",
        "An Ed25519 owner public key is already bound to this GitHub account.",
      );
    }

    const base = getBaseConfig();
    const { keyChallenges } = await getCollections();

    const now = new Date();
    const expiresDate = new Date(
      Math.floor((now.getTime() + CHALLENGE_TTL_MS) / 1000) * 1000,
    );
    const expiresAtStr = formatUtcRfc3339Seconds(expiresDate);
    const nonce = crypto.randomBytes(32).toString("base64url");
    const nonceHash = hashCliToken(`challenge:${nonce}`);
    const accountIdStr = `gh:${auth.ctx.account.githubId.toString()}`;

    await keyChallenges.insertOne({
      _id: new ObjectId(),
      accountId: auth.ctx.account._id,
      nonceHash,
      purpose: "bind_owner_key",
      expiresAt: expiresDate,
      createdAt: now,
    });

    return jsonOk(
      {
        networkId: base.ALT_NETWORK_ID,
        accountId: accountIdStr,
        nonce,
        purpose: "bind_owner_key" as const,
        expiresAt: expiresAtStr,
      },
      201,
    );
  } catch (err) {
    console.error(
      "[POST /api/account/key/challenge] Error:",
      redactErrorMessage(err),
    );
    return jsonError(
      500,
      "INTERNAL_ERROR",
      "Failed to issue owner-key challenge",
    );
  }
}
