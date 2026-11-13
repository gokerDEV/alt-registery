import { ObjectId } from "mongodb";
import { z } from "zod";
import { jsonError, jsonOk, serializePublicDomain } from "@/lib/api-response";
import { authenticateRequest } from "@/lib/auth";
import { evaluateDomainAllocationPolicy } from "@/lib/domains";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import {
  type DomainDoc,
  getCollections,
  isDuplicateKeyError,
  toMongoLong,
  withTransaction,
} from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";
import { issueOwnershipCertificate } from "@/lib/signing";

const registerBodySchema = z
  .object({
    name: z.string().trim().min(1, "Domain `name` is required"),
  })
  .strict();

export async function POST(request: Request) {
  try {
    const base = getBaseConfig();

    // Kill switch check before any allocation or signing work (§13)
    if (!base.REGISTRATION_ENABLED) {
      return jsonError(
        503,
        "REGISTRATION_DISABLED",
        "Domain registration is temporarily disabled.",
      );
    }

    const auth = await authenticateRequest(request, {
      requireMutationCsrf: true,
    });
    if (!auth.ok) {
      return jsonError(auth.status, auth.code, auth.message);
    }

    const rl = await checkRateLimit(
      extractClientSubject(request, auth.ctx.account._id.toHexString()),
      {
        action: "domains_register",
        limit: 10,
        windowSeconds: 60,
      },
    );
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many registration attempts; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return jsonError(400, "INVALID_JSON", "Request body must be valid JSON");
    }

    const parsedBody = registerBodySchema.safeParse(rawJson);
    if (!parsedBody.success) {
      return jsonError(
        400,
        "INVALID_BODY",
        parsedBody.error.issues[0]?.message ?? "Invalid request payload",
      );
    }

    const policy = evaluateDomainAllocationPolicy(
      parsedBody.data.name,
      base.ALT_TLD,
    );
    if (!policy.valid || !policy.domain || !policy.label) {
      const status = policy.reason === "NAME_RESERVED" ? 409 : 400;
      return jsonError(
        status,
        policy.reason ?? "INVALID_DOMAIN",
        policy.message ?? "Domain is not eligible for registration",
      );
    }

    const canonicalName = policy.domain;
    const canonicalLabel = policy.label;
    const { accounts, domains } = await getCollections();

    // Pre-sign ownership certificate strictly OUTSIDE the MongoDB transaction (§7).
    // If `ownerPublicKey` is bound concurrently between pre-read and transaction, abort and re-sign outside.
    let createdDomain: DomainDoc | null = null;

    for (let attempt = 0; attempt < 3; attempt++) {
      const freshAccount = await accounts.findOne({
        _id: auth.ctx.account._id,
      });
      if (!freshAccount) {
        return jsonError(
          401,
          "ACCOUNT_NOT_FOUND",
          "Authenticated account not found",
        );
      }

      const now = new Date();
      const preSignedOwnership = freshAccount.ownerPublicKey
        ? issueOwnershipCertificate({
            domain: canonicalName,
            githubId: freshAccount.githubId.toString(),
            ownerPublicKey: freshAccount.ownerPublicKey,
            generation: 1,
            now,
          })
        : null;

      try {
        createdDomain = await withTransaction(async (session) => {
          const txAccount = await accounts.findOne(
            { _id: freshAccount._id },
            { session },
          );
          if (!txAccount) {
            throw new Error("ACCOUNT_MISSING");
          }

          if (
            (txAccount.ownerPublicKey ?? null) !==
            (freshAccount.ownerPublicKey ?? null)
          ) {
            throw new Error("TX_RETRY_PRESIGN");
          }

          const hasKey = Boolean(
            txAccount.ownerPublicKey && preSignedOwnership,
          );
          const doc: DomainDoc = {
            _id: new ObjectId(),
            name: canonicalName,
            label: canonicalLabel,
            accountId: txAccount._id,
            generation: toMongoLong(hasKey ? 1 : 0),
            sequence: toMongoLong(0),
            kind: "user",
            status: hasKey ? "pending_target" : "pending_key",
            ...(hasKey && txAccount.ownerPublicKey && preSignedOwnership
              ? {
                  ownerPublicKey: txAccount.ownerPublicKey,
                  ownershipRecord: preSignedOwnership,
                }
              : {}),
            publicationStatus: "not_ready",
            createdAt: now,
            updatedAt: now,
          };

          await domains.insertOne(doc, { session });
          return doc;
        });
        break;
      } catch (txErr) {
        if (
          txErr instanceof Error &&
          txErr.message.includes("TX_RETRY_PRESIGN")
        ) {
          continue;
        }
        if (isDuplicateKeyError(txErr)) {
          const keyPattern = txErr.keyPattern ?? {};
          if (
            "accountId" in keyPattern ||
            txErr.message.includes("uniq_user_domain_per_account")
          ) {
            return jsonError(
              409,
              "DOMAIN_LIMIT_REACHED",
              "Each GitHub account can register only one .alt domain during the initial phase.",
            );
          }
          return jsonError(
            409,
            "NAME_TAKEN",
            `${canonicalName} is already registered.`,
          );
        }
        throw txErr;
      }
    }

    if (!createdDomain) {
      return jsonError(
        409,
        "CONCURRENT_MODIFICATION",
        "Account key state changed concurrently; please retry.",
      );
    }

    return jsonOk(
      {
        domain: serializePublicDomain(createdDomain),
      },
      201,
    );
  } catch (err) {
    console.error("[POST /api/domains] Error:", redactErrorMessage(err));
    return jsonError(500, "INTERNAL_ERROR", "Domain registration failed");
  }
}
