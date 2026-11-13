// Domain normalization, protocol validation, and registry allocation policy.
// Protocol validity matches `dotALT/pkg/names`; allocation policy adds minLength=2,
// `xn--` IDN prefix rejection, and the reserved system-name list (§6).

export const DEFAULT_TLD = "alt";

// Exact protocol label pattern from dotALT/pkg/names/names.go:
// single lowercase DNS label (1..63 chars, lowercase ASCII letters/digits and interior hyphens).
const PROTOCOL_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const RESERVED_LABELS = [
  "register",
  "www",
  "api",
  "admin",
  "status",
  "search",
  "support",
  "mail",
  "ns",
  "root",
  "alt",
] as const;

const RESERVED_SET: ReadonlySet<string> = new Set(RESERVED_LABELS);

export type DomainValidationErrorCode =
  | "INVALID_TLD"
  | "INVALID_DOMAIN"
  | "LABEL_TOO_SHORT"
  | "LABEL_TOO_LONG"
  | "PUNYCODE_DISALLOWED"
  | "NAME_RESERVED";

export class DomainValidationError extends Error {
  readonly code: DomainValidationErrorCode;

  constructor(code: DomainValidationErrorCode, message: string) {
    super(message);
    this.name = "DomainValidationError";
    this.code = code;
  }
}

export interface NormalizedDomainResult {
  domain: string; // e.g. "goker.alt"
  label: string; // e.g. "goker"
  tld: string; // e.g. "alt"
}

/**
 * Normalizes a TLD exactly like `dotALT/pkg/names.NormalizeTLD`.
 */
export function normalizeTld(value: string): string {
  const tld = value.trim().toLowerCase().replace(/^\./, "");
  if (!PROTOCOL_LABEL_PATTERN.test(tld)) {
    throw new DomainValidationError("INVALID_TLD", `Invalid TLD "${value}"`);
  }
  return tld;
}

/**
 * Normalizes a single-label domain in the selected namespace exactly like `dotALT/pkg/names.NormalizeDomain`
 * (protocol-level validity: 1..63 lowercase ASCII letters/digits and interior hyphens).
 */
export function normalizeProtocolDomain(
  value: string,
  tldValue: string = DEFAULT_TLD,
): NormalizedDomainResult {
  const tld = normalizeTld(tldValue);
  let domain = value.trim().toLowerCase();
  if (domain.endsWith(".")) {
    domain = domain.slice(0, -1);
  }
  if (!domain.includes(".")) {
    domain = `${domain}.${tld}`;
  }

  const suffix = `.${tld}`;
  if (!domain.endsWith(suffix)) {
    throw new DomainValidationError(
      "INVALID_DOMAIN",
      `Domain must be a single lowercase DNS label under .${tld}`,
    );
  }

  const label = domain.slice(0, -suffix.length);
  if (label.length > 63) {
    throw new DomainValidationError(
      "LABEL_TOO_LONG",
      "Label must be 63 characters or fewer",
    );
  }
  if (!PROTOCOL_LABEL_PATTERN.test(label)) {
    throw new DomainValidationError(
      "INVALID_DOMAIN",
      `Domain must be a single lowercase DNS label under .${tld} using a-z, 0-9, and interior hyphens`,
    );
  }

  return { domain, label, tld };
}

/**
 * Reports whether `value` is already canonical at the protocol level (`dotALT/pkg/names.IsDomain`).
 */
export function isProtocolDomain(
  value: string,
  tldValue: string = DEFAULT_TLD,
): boolean {
  try {
    const normalized = normalizeProtocolDomain(value, tldValue);
    return normalized.domain === value;
  } catch {
    return false;
  }
}

export function isReservedLabel(label: string): boolean {
  return RESERVED_SET.has(label.toLowerCase());
}

export interface DomainCheckPolicyResult {
  valid: boolean;
  domain?: string;
  label?: string;
  reserved: boolean;
  reason?: DomainValidationErrorCode;
  message?: string;
}

/**
 * Evaluates both protocol validity and registry allocation policy (§6):
 * - single lowercase ASCII label under .<tld>
 * - length 2..63 (registry allocation policy; protocol allows 1)
 * - no leading/trailing hyphens, only a-z, 0-9, interior hyphens
 * - rejects `xn--` punycode labels
 * - flags reserved system names
 */
export function evaluateDomainAllocationPolicy(
  input: string,
  tldValue: string = DEFAULT_TLD,
): DomainCheckPolicyResult {
  let parsed: NormalizedDomainResult;
  try {
    parsed = normalizeProtocolDomain(input, tldValue);
  } catch (err) {
    if (err instanceof DomainValidationError) {
      return {
        valid: false,
        reserved: false,
        reason: err.code,
        message: err.message,
      };
    }
    return {
      valid: false,
      reserved: false,
      reason: "INVALID_DOMAIN",
      message: "Invalid domain name",
    };
  }

  if (parsed.label.length < 2) {
    return {
      valid: false,
      domain: parsed.domain,
      label: parsed.label,
      reserved: isReservedLabel(parsed.label),
      reason: "LABEL_TOO_SHORT",
      message: "Labels must be at least 2 characters long",
    };
  }

  if (parsed.label.startsWith("xn--")) {
    return {
      valid: false,
      domain: parsed.domain,
      label: parsed.label,
      reserved: false,
      reason: "PUNYCODE_DISALLOWED",
      message: "Punycode (xn--) labels are not permitted",
    };
  }

  if (isReservedLabel(parsed.label)) {
    return {
      valid: false,
      domain: parsed.domain,
      label: parsed.label,
      reserved: true,
      reason: "NAME_RESERVED",
      message: `${parsed.domain} is a reserved system name`,
    };
  }

  return {
    valid: true,
    domain: parsed.domain,
    label: parsed.label,
    reserved: false,
  };
}
