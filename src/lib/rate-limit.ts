import crypto from "node:crypto";
import { getSessionSecretString } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";

export interface RateLimitPolicy {
  action: string;
  limit: number;
  windowSeconds: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfterSeconds: number;
}

function hashRateLimitSubject(subject: string): string {
  const secret =
    getSessionSecretString() ?? "alt-registry-ratelimit-default-salt";
  return crypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(subject, "utf8")
    .digest("hex");
}

export function extractClientSubject(
  request: Request,
  accountId?: string,
): string {
  if (accountId) {
    return `acct:${accountId}`;
  }
  const forwarded = request.headers.get("x-forwarded-for");
  const firstIp = forwarded?.split(",")[0]?.trim();
  const realIp = request.headers.get("x-real-ip")?.trim();
  return `ip:${firstIp || realIp || "unknown"}`;
}

/**
 * Enforces a fixed-window rate limit backed by MongoDB TTL window documents (§5, §13).
 * Safe across serverless Vercel instances without in-memory state.
 */
export async function checkRateLimit(
  subject: string,
  policy: RateLimitPolicy,
): Promise<RateLimitDecision> {
  const { rateLimits } = await getCollections();
  const nowMs = Date.now();
  const windowMs = policy.windowSeconds * 1000;
  const windowStartMs = Math.floor(nowMs / windowMs) * windowMs;
  const windowStartedAt = new Date(windowStartMs);
  const resetAt = new Date(windowStartMs + windowMs);
  // Expire slightly after resetAt so MongoDB's background TTL monitor reaps stale buckets cleanly
  const expiresAt = new Date(windowStartMs + windowMs + 60_000);
  const subjectHash = hashRateLimitSubject(subject);

  const updated = await rateLimits.findOneAndUpdate(
    {
      subjectHash,
      action: policy.action,
      windowStartedAt,
    },
    {
      $inc: { count: 1 },
      $setOnInsert: {
        expiresAt,
      },
    },
    {
      upsert: true,
      returnDocument: "after",
    },
  );

  const count = updated?.count ?? 1;
  const allowed = count <= policy.limit;
  const remaining = Math.max(0, policy.limit - count);
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((resetAt.getTime() - nowMs) / 1000),
  );

  return {
    allowed,
    remaining,
    resetAt,
    retryAfterSeconds,
  };
}
