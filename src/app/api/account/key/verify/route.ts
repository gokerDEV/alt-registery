import { z } from "zod";
import {
  jsonError,
  jsonOk,
  serializePublicAccount,
  serializePublicDomain,
} from "@/lib/api-response";
import { authenticateRequest, hashCliToken } from "@/lib/auth";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import {
  type AccountDoc,
  type DomainDoc,
  getCollections,
  toMongoLong,
  withTransaction,
} from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";
import { formatUtcRfc3339Seconds, parseEd25519PublicKey } from "@/lib/records";
import {
  issueOwnershipCertificate,
  verifyKeyChallengeSignature,
} from "@/lib/signing";

const verifyBodySchema = z
  .object({
    ownerPublicKey: z.string().trim().min(1),
    nonce: z.string().trim().min(1),
    expiresAt: z.string().trim().min(1),
    signature: z.string().trim().min(1),
  })
  .strict();

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
        action: "account_key_verify",
        limit: 15,
        windowSeconds: 60,
      },
    );
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many verification attempts; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return jsonError(400, "INVALID_JSON", "Request body must be valid JSON");
    }

    const parsedBody = verifyBodySchema.safeParse(rawJson);
    if (!parsedBody.success) {
      return jsonError(
        400,
        "INVALID_BODY",
        parsedBody.error.issues[0]?.message ?? "Invalid request payload",
      );
    }

    const { ownerPublicKey, nonce, expiresAt, signature } = parsedBody.data;

    try {
      parseEd25519PublicKey(ownerPublicKey);
    } catch {
      return jsonError(
        400,
        "INVALID_PUBLIC_KEY",
        "ownerPublicKey must be a valid ed25519:<base64> public key",
      );
    }

    if (auth.ctx.account.ownerPublicKey) {
      return jsonError(
        409,
        "KEY_ALREADY_BOUND",
        "An Ed25519 owner public key is already bound to this GitHub account.",
      );
    }

    const base = getBaseConfig();
    const accountIdStr = `gh:${auth.ctx.account.githubId.toString()}`;

    // Verify domain-separated Ed25519 proof (`alt.key-challenge.v1\x00<networkId>\x00<compact-json>`) (§4.4)
    try {
      verifyKeyChallengeSignature(
        base.ALT_NETWORK_ID,
        {
          accountId: accountIdStr,
          ownerPublicKey,
          nonce,
          purpose: "bind_owner_key",
          expiresAt,
        },
        signature,
      );
    } catch {
      return jsonError(
        400,
        "INVALID_CHALLENGE_SIGNATURE",
        "Owner-key challenge signature verification failed",
      );
    }

    const { accounts, domains, keyChallenges } = await getCollections();
    const nonceHash = hashCliToken(`challenge:${nonce}`);

    let txOutcome: { account: AccountDoc; domain: DomainDoc | null } | null =
      null;

    // Pre-sign ownership certificate strictly OUTSIDE the MongoDB transaction (§7).
    // If a `pending_key` domain is created concurrently between pre-read and transaction,
    // abort the transaction cleanly (preserving the unconsumed challenge) and re-sign outside.
    for (let attempt = 0; attempt < 3; attempt++) {
      const now = new Date();
      const pendingDomain = await domains.findOne({
        accountId: auth.ctx.account._id,
        kind: "user",
        status: "pending_key",
      });

      const preSignedCert = pendingDomain
        ? issueOwnershipCertificate({
            domain: pendingDomain.name,
            githubId: auth.ctx.account.githubId.toString(),
            ownerPublicKey,
            generation: 1,
            now,
          })
        : null;

      try {
        txOutcome = await withTransaction(async (session) => {
          const consumedChallenge = await keyChallenges.findOneAndUpdate(
            {
              accountId: auth.ctx.account._id,
              nonceHash,
              purpose: "bind_owner_key",
              consumedAt: { $exists: false },
              expiresAt: { $gt: now },
            },
            {
              $set: { consumedAt: now },
            },
            { session, returnDocument: "after" },
          );

          if (
            !consumedChallenge ||
            formatUtcRfc3339Seconds(consumedChallenge.expiresAt) !== expiresAt
          ) {
            throw new Error("TX_ABORT:CHALLENGE_INVALID_OR_EXPIRED");
          }

          const updatedAccount = await accounts.findOneAndUpdate(
            {
              _id: auth.ctx.account._id,
              $or: [
                { ownerPublicKey: { $exists: false } },
                { ownerPublicKey: undefined },
              ],
            },
            {
              $set: {
                ownerPublicKey,
                updatedAt: now,
              },
            },
            { session, returnDocument: "after" },
          );

          if (!updatedAccount) {
            throw new Error("TX_ABORT:KEY_ALREADY_BOUND");
          }

          let updatedDomain: DomainDoc | null = null;
          const currentUserDomain = await domains.findOne(
            {
              accountId: auth.ctx.account._id,
              kind: "user",
            },
            { session },
          );

          if (currentUserDomain) {
            if (currentUserDomain.status === "pending_key") {
              if (
                !preSignedCert ||
                preSignedCert.domain !== currentUserDomain.name
              ) {
                throw new Error("TX_RETRY_PRESIGN");
              }

              updatedDomain = await domains.findOneAndUpdate(
                {
                  _id: currentUserDomain._id,
                  status: "pending_key",
                },
                {
                  $set: {
                    generation: toMongoLong(1),
                    status: "pending_target",
                    ownerPublicKey,
                    ownershipRecord: preSignedCert,
                    updatedAt: now,
                  },
                },
                { session, returnDocument: "after" },
              );
            } else {
              updatedDomain = currentUserDomain;
            }
          }

          return {
            account: updatedAccount,
            domain: updatedDomain,
          };
        });
        break;
      } catch (txErr) {
        const msg = txErr instanceof Error ? txErr.message : String(txErr);
        if (msg.includes("TX_RETRY_PRESIGN")) {
          continue;
        }
        if (msg.includes("TX_ABORT:CHALLENGE_INVALID_OR_EXPIRED")) {
          return jsonError(
            400,
            "INVALID_OR_EXPIRED_CHALLENGE",
            "Challenge nonce is invalid, expired, or has already been consumed.",
          );
        }
        if (msg.includes("TX_ABORT:KEY_ALREADY_BOUND")) {
          return jsonError(
            409,
            "KEY_ALREADY_BOUND",
            "An Ed25519 owner public key is already bound to this GitHub account.",
          );
        }
        throw txErr;
      }
    }

    if (!txOutcome) {
      return jsonError(
        409,
        "CONCURRENT_MODIFICATION",
        "Account domain state changed concurrently; please retry.",
      );
    }

    return jsonOk({
      account: serializePublicAccount(txOutcome.account),
      domain: txOutcome.domain ? serializePublicDomain(txOutcome.domain) : null,
    });
  } catch (err) {
    console.error(
      "[POST /api/account/key/verify] Error:",
      redactErrorMessage(err),
    );
    return jsonError(
      500,
      "INTERNAL_ERROR",
      "Failed to verify and bind owner public key",
    );
  }
}
