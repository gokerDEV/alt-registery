import { connection } from "next/server";
import {
  jsonError,
  jsonOk,
  serializePublicAccount,
  serializePublicDomain,
} from "@/lib/api-response";
import { authenticateRequest } from "@/lib/auth";
import { getBaseConfig, redactErrorMessage } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";

export async function GET(request: Request) {
  await connection();
  try {
    const auth = await authenticateRequest(request);
    if (!auth.ok) {
      return jsonError(auth.status, auth.code, auth.message);
    }

    const { domains } = await getCollections();
    const userDomain = await domains.findOne({
      accountId: auth.ctx.account._id,
      kind: "user",
    });

    const base = getBaseConfig();

    return jsonOk({
      account: serializePublicAccount(auth.ctx.account),
      domain: userDomain ? serializePublicDomain(userDomain) : null,
      network: {
        networkId: base.ALT_NETWORK_ID,
        tld: base.ALT_TLD,
        registrationEnabled: base.REGISTRATION_ENABLED,
      },
    });
  } catch (err) {
    console.error("[GET /api/account] Error:", redactErrorMessage(err));
    return jsonError(500, "INTERNAL_ERROR", "Unable to load account details");
  }
}
