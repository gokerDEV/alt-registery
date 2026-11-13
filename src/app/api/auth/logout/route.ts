import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { jsonError } from "@/lib/api-response";
import { getBaseConfig } from "@/lib/env";
import {
  buildSessionCookieOptions,
  decryptSessionToken,
  getSessionCookieName,
  timingSafeEqualStrings,
  verifyBrowserMutationRequest,
} from "@/lib/session";

export async function POST(request: Request) {
  const { APP_URL } = getBaseConfig();
  const originCheck = verifyBrowserMutationRequest(request);
  if (!originCheck.ok) {
    return jsonError(403, originCheck.code, originCheck.message);
  }

  const cookieStore = await cookies();
  const rawSession = cookieStore.get(getSessionCookieName())?.value;
  if (rawSession) {
    const session = await decryptSessionToken(rawSession);
    if (session) {
      // Accept CSRF token either via X-CSRF-Token header (AJAX) or form field `csrfToken`
      let providedCsrf = request.headers.get("x-csrf-token") ?? "";
      if (
        !providedCsrf &&
        request.headers
          .get("content-type")
          ?.includes("application/x-www-form-urlencoded")
      ) {
        const formData = await request.formData();
        const field = formData.get("csrfToken");
        if (typeof field === "string") {
          providedCsrf = field;
        }
      }
      if (
        !providedCsrf ||
        !timingSafeEqualStrings(providedCsrf, session.csrfToken)
      ) {
        return jsonError(403, "INVALID_CSRF_TOKEN", "Invalid CSRF token");
      }
    }
  }

  const response = NextResponse.redirect(new URL("/", APP_URL), 303);
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Clear-Site-Data", '"cookies", "storage", "cache"');
  response.cookies.set({
    ...buildSessionCookieOptions(0),
    value: "",
  });
  return response;
}
