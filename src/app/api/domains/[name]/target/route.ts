import { jsonError, jsonOk, serializePublicDomain } from "@/lib/api-response";
import { authenticateRequest } from "@/lib/auth";
import { normalizeProtocolDomain } from "@/lib/domains";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import { publishRegistryManifest } from "@/lib/ipfs";
import { fromMongoLong, getCollections, toMongoLong } from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";
import {
  canonicalizeTargetRecord,
  isDisallowedPublicEndpointHost,
  serializeTargetRecord,
  targetRecordSchema,
} from "@/lib/records";
import { verifyTargetRecordSignature } from "@/lib/signing";

export async function PUT(
  request: Request,
  ctx: { params: Promise<{ name: string }> },
) {
  try {
    const auth = await authenticateRequest(request, {
      requireMutationCsrf: true,
    });
    if (!auth.ok) {
      return jsonError(auth.status, auth.code, auth.message);
    }

    const rl = await checkRateLimit(
      extractClientSubject(request, auth.ctx.account._id.toHexString()),
      {
        action: "domains_target_put",
        limit: 20,
        windowSeconds: 60,
      },
    );
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many target publication requests; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    const base = getBaseConfig();
    const { name: rawNameParam } = await ctx.params;

    let canonicalName: string;
    try {
      canonicalName = normalizeProtocolDomain(
        rawNameParam,
        base.ALT_TLD,
      ).domain;
    } catch {
      return jsonError(
        400,
        "INVALID_DOMAIN",
        `Invalid domain parameter under .${base.ALT_TLD}`,
      );
    }

    const { domains } = await getCollections();
    const domainDoc = await domains.findOne({
      name: canonicalName,
      kind: "user",
    });

    if (!domainDoc || !domainDoc.accountId.equals(auth.ctx.account._id)) {
      return jsonError(
        404,
        "DOMAIN_NOT_OWNED",
        `Domain ${canonicalName} is not registered to your account.`,
      );
    }

    if (domainDoc.status === "suspended") {
      return jsonError(
        403,
        "DOMAIN_SUSPENDED",
        `Domain ${canonicalName} is currently suspended.`,
      );
    }

    if (domainDoc.status === "pending_key" || !domainDoc.ownershipRecord) {
      return jsonError(
        409,
        "OWNERSHIP_NOT_ISSUED",
        `Bind your Ed25519 owner key with 'alt register ${canonicalName}' before publishing a target record.`,
      );
    }

    let rawJson: unknown;
    try {
      rawJson = await request.json();
    } catch {
      return jsonError(400, "INVALID_JSON", "Request body must be valid JSON");
    }

    const parsedBody = targetRecordSchema.safeParse(rawJson);
    if (!parsedBody.success) {
      return jsonError(
        400,
        "INVALID_TARGET_RECORD",
        parsedBody.error.issues[0]?.message ??
          "Request body must be a valid alt.target.v1 JSON object",
      );
    }

    const candidateTarget = canonicalizeTargetRecord(parsedBody.data);
    if (candidateTarget.domain !== canonicalName) {
      return jsonError(
        400,
        "DOMAIN_MISMATCH",
        `Target record domain "${candidateTarget.domain}" does not match URL domain "${canonicalName}"`,
      );
    }

    const now = new Date();
    try {
      verifyTargetRecordSignature(
        candidateTarget,
        domainDoc.ownershipRecord,
        now,
      );
    } catch (verifyErr) {
      return jsonError(
        400,
        "TARGET_VERIFICATION_FAILED",
        verifyErr instanceof Error
          ? verifyErr.message
          : "Target record verification failed",
      );
    }

    // Reject private, loopback, link-local, documentation, or special-use origin hosts up front
    if (candidateTarget.mode === "https" && candidateTarget.target) {
      const targetHostname = new URL(candidateTarget.target).hostname;
      if (isDisallowedPublicEndpointHost(targetHostname)) {
        return jsonError(
          400,
          "DISALLOWED_TARGET_HOST",
          "HTTPS target URL must point to a globally routable public hostname or IP address.",
        );
      }
    } else if (
      candidateTarget.mode === "p2p" &&
      candidateTarget.signalingEndpoints
    ) {
      for (const ep of candidateTarget.signalingEndpoints) {
        const epHost = new URL(ep).hostname;
        if (isDisallowedPublicEndpointHost(epHost)) {
          return jsonError(
            400,
            "DISALLOWED_SIGNALING_HOST",
            "WSS signaling endpoint must point to a globally routable public hostname or IP address.",
          );
        }
      }
    }

    const storedSequence = Number(fromMongoLong(domainDoc.sequence));
    const isIdempotentRetry =
      candidateTarget.sequence === storedSequence &&
      domainDoc.targetRecord !== undefined &&
      serializeTargetRecord(candidateTarget) ===
        serializeTargetRecord(domainDoc.targetRecord);

    if (!isIdempotentRetry && candidateTarget.sequence <= storedSequence) {
      return jsonError(
        409,
        "STALE_SEQUENCE",
        `Target sequence (${candidateTarget.sequence}) must be strictly greater than stored sequence (${storedSequence}).`,
      );
    }

    // Store target record and set `publicationStatus: "pending"`.
    // Per §7 step 6: `pending_target` -> `publication_pending`; already `active` stays `active`.
    let activeDomainDoc = domainDoc;
    if (!isIdempotentRetry || domainDoc.publicationStatus !== "published") {
      const nextStatus =
        domainDoc.status === "pending_target"
          ? "publication_pending"
          : domainDoc.status;

      const updated = await domains.findOneAndUpdate(
        {
          _id: domainDoc._id,
          ...(isIdempotentRetry
            ? { sequence: domainDoc.sequence }
            : { sequence: { $lt: toMongoLong(candidateTarget.sequence) } }),
        },
        {
          $set: {
            sequence: toMongoLong(candidateTarget.sequence),
            targetRecord: candidateTarget,
            publicationStatus: "pending",
            status: nextStatus,
            updatedAt: now,
          },
        },
        { returnDocument: "after" },
      );

      if (!updated) {
        return jsonError(
          409,
          "CONCURRENT_SEQUENCE_CONFLICT",
          "A newer target sequence was committed concurrently; refresh and retry.",
        );
      }
      activeDomainDoc = updated;
    }

    // Step 7: Trigger manifest publication AFTER database commit (§7, §11).
    // If IPFS/IPNS publication fails, never roll back ownership or target!
    let publicationError: string | null = null;
    let ipnsName: string | null = null;

    if (activeDomainDoc.publicationStatus !== "published") {
      try {
        const pubResult = await publishRegistryManifest();
        ipnsName = pubResult.ipnsName;
      } catch (pubErr) {
        publicationError = redactErrorMessage(pubErr);
        console.warn(
          `[PUT /api/domains/${canonicalName}/target] Manifest publication deferred/failed:`,
          publicationError,
        );
      }
    }

    const finalDomain =
      (await domains.findOne({ _id: activeDomainDoc._id })) ?? activeDomainDoc;

    return jsonOk({
      domain: serializePublicDomain(finalDomain),
      publication: {
        status: finalDomain.publicationStatus,
        manifestCid: finalDomain.manifestCid ?? null,
        ipnsName,
        error: publicationError,
      },
    });
  } catch (err) {
    console.error(
      "[PUT /api/domains/[name]/target] Error:",
      redactErrorMessage(err),
    );
    return jsonError(
      500,
      "INTERNAL_ERROR",
      "Failed to update signed target record",
    );
  }
}
