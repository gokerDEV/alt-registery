import { connection } from "next/server";
import { z } from "zod";
import { jsonError, jsonOk } from "@/lib/api-response";
import { authenticateRequest } from "@/lib/auth";
import { evaluateDomainAllocationPolicy } from "@/lib/domains";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";
import { checkRateLimit, extractClientSubject } from "@/lib/rate-limit";

const querySchema = z
  .object({
    name: z.string().trim().min(1, "Domain query parameter `name` is required"),
  })
  .strict();

export async function GET(request: Request) {
  await connection();
  try {
    const base = getBaseConfig();
    const url = new URL(request.url);

    const parsedQuery = querySchema.safeParse({
      name: url.searchParams.get("name") ?? "",
    });
    if (!parsedQuery.success) {
      return jsonError(
        400,
        "INVALID_QUERY",
        parsedQuery.error.issues[0]?.message ??
          "Missing `name` query parameter",
      );
    }

    // Optional auth: determine whether current account already owns a domain
    const auth = await authenticateRequest(request);
    const accountIdHex = auth.ok
      ? auth.ctx.account._id.toHexString()
      : undefined;

    const rl = await checkRateLimit(
      extractClientSubject(request, accountIdHex),
      {
        action: "domains_check",
        limit: 60,
        windowSeconds: 60,
      },
    );
    if (!rl.allowed) {
      return jsonError(
        429,
        "RATE_LIMITED",
        "Too many availability checks; please try again shortly.",
        { "Retry-After": String(rl.retryAfterSeconds) },
      );
    }

    const { domains } = await getCollections();

    let accountAlreadyOwnsDomain = false;
    let ownedDomainName: string | null = null;
    if (auth.ok) {
      const existingForAccount = await domains.findOne(
        { accountId: auth.ctx.account._id, kind: "user" },
        { projection: { name: 1 } },
      );
      if (existingForAccount) {
        accountAlreadyOwnsDomain = true;
        ownedDomainName = existingForAccount.name;
      }
    }

    const policy = evaluateDomainAllocationPolicy(
      parsedQuery.data.name,
      base.ALT_TLD,
    );

    if (!policy.domain || !policy.label) {
      return jsonError(
        400,
        policy.reason ?? "INVALID_DOMAIN",
        policy.message ?? "Invalid domain format",
      );
    }

    if (!policy.valid) {
      return jsonOk({
        name: policy.domain,
        label: policy.label,
        available: false,
        reserved: policy.reserved,
        reason: policy.reason ?? "INVALID_DOMAIN",
        message: policy.message ?? "Domain is not eligible for registration",
        accountOwnsDomain: accountAlreadyOwnsDomain,
        ownedDomainName,
        registrationEnabled: base.REGISTRATION_ENABLED,
      });
    }

    const takenDoc = await domains.findOne(
      { name: policy.domain },
      { projection: { _id: 1, kind: 1 } },
    );

    const isTaken = Boolean(takenDoc);
    const isSystemReserved = takenDoc?.kind === "system";

    return jsonOk({
      name: policy.domain,
      label: policy.label,
      available: !isTaken,
      reserved: isSystemReserved,
      reason: isSystemReserved
        ? "NAME_RESERVED"
        : isTaken
          ? "NAME_TAKEN"
          : null,
      message: isSystemReserved
        ? `${policy.domain} is a reserved system name`
        : isTaken
          ? `${policy.domain} is already registered`
          : `${policy.domain} is available`,
      accountOwnsDomain: accountAlreadyOwnsDomain,
      ownedDomainName,
      registrationEnabled: base.REGISTRATION_ENABLED,
    });
  } catch (err) {
    console.error("[GET /api/domains/check] Error:", redactErrorMessage(err));
    return jsonError(
      500,
      "INTERNAL_ERROR",
      "Unable to check domain availability",
    );
  }
}
