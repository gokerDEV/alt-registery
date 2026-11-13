import net from "node:net";
import { z } from "zod";
import { isProtocolDomain } from "@/lib/domains";

export const SCHEMA_OWNERSHIP_V1 = "alt.ownership.v1" as const;
export const SCHEMA_TARGET_V1 = "alt.target.v1" as const;
export const SCHEMA_KEY_CHALLENGE_V1 = "alt.key-challenge.v1" as const;
export const SCHEMA_MANIFEST_V1 = "alt.manifest.v1" as const;

export const ED25519_KEY_PREFIX = "ed25519:";
const ED25519_PUBKEY_BYTES = 32;
const ED25519_SIG_BYTES = 64;
const STANDARD_BASE64_REGEX =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UTC_WHOLE_SECOND_RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export interface OwnershipCertificate {
  schema: typeof SCHEMA_OWNERSHIP_V1;
  networkId: string;
  domain: string;
  accountId: string;
  ownerPublicKey: string;
  generation: number;
  issuedAt: string;
  expiresAt: string;
  issuerKeyId: string;
  signature: string;
}

export type UnsignedOwnershipCertificate = Omit<
  OwnershipCertificate,
  "signature"
>;

export interface TargetRecord {
  schema: typeof SCHEMA_TARGET_V1;
  networkId: string;
  domain: string;
  ownershipGeneration: number;
  sequence: number;
  mode: "https" | "p2p";
  target?: string;
  publisherIdentity?: string;
  signalingEndpoints?: string[];
  issuedAt: string;
  expiresAt: string;
  signature: string;
}

export type UnsignedTargetRecord = Omit<TargetRecord, "signature">;

export interface KeyChallengePayload {
  accountId: string;
  ownerPublicKey: string;
  nonce: string;
  purpose: "bind_owner_key";
  expiresAt: string;
}

export interface ManifestEntry {
  ownership: OwnershipCertificate;
  target: TargetRecord;
}

export interface Manifest {
  schema: typeof SCHEMA_MANIFEST_V1;
  networkId: string;
  generatedAt?: string;
  records: Record<string, ManifestEntry>;
}

/**
 * Formats a Date as UTC RFC3339 whole-second timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
 */
export function formatUtcRfc3339Seconds(date: Date): string {
  const truncated = new Date(Math.floor(date.getTime() / 1000) * 1000);
  return truncated.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Parses and validates an "ed25519:<standard-base64>" public key string exactly like `dotALT/pkg/records.ParsePublicKey`.
 */
export function parseEd25519PublicKey(encoded: string): Buffer {
  if (!encoded.startsWith(ED25519_KEY_PREFIX)) {
    throw new Error("records: invalid ed25519 public key format");
  }
  const b64 = encoded.slice(ED25519_KEY_PREFIX.length);
  if (!b64 || !STANDARD_BASE64_REGEX.test(b64)) {
    throw new Error("records: invalid ed25519 public key format");
  }
  const raw = Buffer.from(b64, "base64");
  if (
    raw.byteLength !== ED25519_PUBKEY_BYTES ||
    raw.toString("base64") !== b64
  ) {
    throw new Error("records: invalid ed25519 public key format");
  }
  return raw;
}

export function formatEd25519PublicKey(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.byteLength !== ED25519_PUBKEY_BYTES) {
    throw new Error("records: invalid ed25519 public key byte length");
  }
  return ED25519_KEY_PREFIX + Buffer.from(rawPublicKey).toString("base64");
}

export function parseStandardBase64Signature(encoded: string): Buffer {
  if (!encoded || !STANDARD_BASE64_REGEX.test(encoded)) {
    throw new Error("records: signature verification failed");
  }
  const raw = Buffer.from(encoded, "base64");
  if (
    raw.byteLength !== ED25519_SIG_BYTES ||
    raw.toString("base64") !== encoded
  ) {
    throw new Error("records: signature verification failed");
  }
  return raw;
}

/**
 * Escapes `<`, `>`, `&` in JSON strings the exact same way Go's `encoding/json.Marshal` does by default,
 * while serializing keys in an explicit deterministic order with zero whitespace.
 */
function goCompatibleJsonMarshal(
  obj: Record<string, unknown>,
  orderedKeys: readonly string[],
): string {
  const parts: string[] = [];
  for (const key of orderedKeys) {
    const val = obj[key];
    if (val === undefined) {
      continue;
    }
    const serializedVal = serializeGoJsonValue(val);
    parts.push(`${serializeGoJsonString(key)}:${serializedVal}`);
  }
  return `{${parts.join(",")}}`;
}

function serializeGoJsonString(str: string): string {
  return JSON.stringify(str)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}

function serializeGoJsonValue(val: unknown): string {
  if (typeof val === "string") {
    return serializeGoJsonString(val);
  }
  if (typeof val === "number") {
    if (!Number.isSafeInteger(val) || val < 0) {
      throw new Error("records: unsigned integer out of safe range");
    }
    return String(val);
  }
  if (typeof val === "boolean") {
    return val ? "true" : "false";
  }
  if (Array.isArray(val)) {
    return `[${val.map((item) => serializeGoJsonValue(item)).join(",")}]`;
  }
  throw new Error("records: unsupported canonical JSON value type");
}

const OWNERSHIP_CANONICAL_KEYS = [
  "schema",
  "networkId",
  "domain",
  "accountId",
  "ownerPublicKey",
  "generation",
  "issuedAt",
  "expiresAt",
  "issuerKeyId",
] as const;

const OWNERSHIP_SERIALIZED_KEYS = [
  ...OWNERSHIP_CANONICAL_KEYS,
  "signature",
] as const;

const TARGET_CANONICAL_KEYS = [
  "schema",
  "networkId",
  "domain",
  "ownershipGeneration",
  "sequence",
  "mode",
  "target",
  "publisherIdentity",
  "signalingEndpoints",
  "issuedAt",
  "expiresAt",
] as const;

const TARGET_SERIALIZED_KEYS = [...TARGET_CANONICAL_KEYS, "signature"] as const;

const CHALLENGE_CANONICAL_KEYS = [
  "accountId",
  "ownerPublicKey",
  "nonce",
  "purpose",
  "expiresAt",
] as const;

/**
 * Returns the exact domain-separated canonical signing bytes for an OwnershipCertificate (§8.1):
 * `alt.ownership.v1\x00<networkId>\x00<compact-json>`
 */
export function buildOwnershipSigningBytes(
  cert: UnsignedOwnershipCertificate,
): Buffer {
  if (!cert.networkId || cert.networkId.trim() === "") {
    throw new Error("records: missing or mismatched networkId");
  }
  const jsonPayload = goCompatibleJsonMarshal(
    {
      schema: cert.schema,
      networkId: cert.networkId,
      domain: cert.domain,
      accountId: cert.accountId,
      ownerPublicKey: cert.ownerPublicKey,
      generation: cert.generation,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      issuerKeyId: cert.issuerKeyId,
    },
    OWNERSHIP_CANONICAL_KEYS,
  );
  return Buffer.from(
    `${SCHEMA_OWNERSHIP_V1}\x00${cert.networkId}\x00${jsonPayload}`,
    "utf8",
  );
}

/**
 * Returns the exact domain-separated canonical signing bytes for a TargetRecord (§8.2):
 * `alt.target.v1\x00<networkId>\x00<compact-json>`
 * Matches Go `omitempty` semantics for `target`, `publisherIdentity`, and `signalingEndpoints`.
 */
export function buildTargetSigningBytes(target: UnsignedTargetRecord): Buffer {
  if (!target.networkId || target.networkId.trim() === "") {
    throw new Error("records: missing or mismatched networkId");
  }
  const canonicalObj: Record<string, unknown> = {
    schema: target.schema,
    networkId: target.networkId,
    domain: target.domain,
    ownershipGeneration: target.ownershipGeneration,
    sequence: target.sequence,
    mode: target.mode,
    target:
      target.target && target.target.length > 0 ? target.target : undefined,
    publisherIdentity:
      target.publisherIdentity && target.publisherIdentity.length > 0
        ? target.publisherIdentity
        : undefined,
    signalingEndpoints:
      target.signalingEndpoints && target.signalingEndpoints.length > 0
        ? target.signalingEndpoints
        : undefined,
    issuedAt: target.issuedAt,
    expiresAt: target.expiresAt,
  };
  const jsonPayload = goCompatibleJsonMarshal(
    canonicalObj,
    TARGET_CANONICAL_KEYS,
  );
  return Buffer.from(
    `${SCHEMA_TARGET_V1}\x00${target.networkId}\x00${jsonPayload}`,
    "utf8",
  );
}

/**
 * Returns the exact domain-separated canonical signing bytes for CLI owner-key binding (§4.4):
 * `alt.key-challenge.v1\x00<networkId>\x00<compact-json>`
 */
export function buildKeyChallengeSigningBytes(
  networkId: string,
  payload: KeyChallengePayload,
): Buffer {
  if (!networkId || networkId.trim() === "") {
    throw new Error("records: missing networkId");
  }
  if (!UTC_WHOLE_SECOND_RFC3339.test(payload.expiresAt)) {
    throw new Error(
      "records: challenge expiresAt must use whole-second UTC RFC3339",
    );
  }
  const jsonPayload = goCompatibleJsonMarshal(
    {
      accountId: payload.accountId,
      ownerPublicKey: payload.ownerPublicKey,
      nonce: payload.nonce,
      purpose: payload.purpose,
      expiresAt: payload.expiresAt,
    },
    CHALLENGE_CANONICAL_KEYS,
  );
  return Buffer.from(
    `${SCHEMA_KEY_CHALLENGE_V1}\x00${networkId}\x00${jsonPayload}`,
    "utf8",
  );
}

export function canonicalizeOwnershipCertificate(
  cert: OwnershipCertificate,
): OwnershipCertificate {
  return {
    schema: SCHEMA_OWNERSHIP_V1,
    networkId: cert.networkId,
    domain: cert.domain,
    accountId: cert.accountId,
    ownerPublicKey: cert.ownerPublicKey,
    generation: cert.generation,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    issuerKeyId: cert.issuerKeyId,
    signature: cert.signature,
  };
}

export function serializeOwnershipCertificate(
  cert: OwnershipCertificate,
): string {
  return goCompatibleJsonMarshal(
    canonicalizeOwnershipCertificate(cert) as unknown as Record<
      string,
      unknown
    >,
    OWNERSHIP_SERIALIZED_KEYS,
  );
}

export function canonicalizeTargetRecord(target: TargetRecord): TargetRecord {
  const out: TargetRecord = {
    schema: SCHEMA_TARGET_V1,
    networkId: target.networkId,
    domain: target.domain,
    ownershipGeneration: target.ownershipGeneration,
    sequence: target.sequence,
    mode: target.mode,
    ...(target.target ? { target: target.target } : {}),
    ...(target.publisherIdentity
      ? { publisherIdentity: target.publisherIdentity }
      : {}),
    ...(target.signalingEndpoints && target.signalingEndpoints.length > 0
      ? { signalingEndpoints: [...target.signalingEndpoints] }
      : {}),
    issuedAt: target.issuedAt,
    expiresAt: target.expiresAt,
    signature: target.signature,
  };
  return out;
}

export function serializeTargetRecord(target: TargetRecord): string {
  const c = canonicalizeTargetRecord(target);
  return goCompatibleJsonMarshal(
    {
      schema: c.schema,
      networkId: c.networkId,
      domain: c.domain,
      ownershipGeneration: c.ownershipGeneration,
      sequence: c.sequence,
      mode: c.mode,
      target: c.target,
      publisherIdentity: c.publisherIdentity,
      signalingEndpoints: c.signalingEndpoints,
      issuedAt: c.issuedAt,
      expiresAt: c.expiresAt,
      signature: c.signature,
    },
    TARGET_SERIALIZED_KEYS,
  );
}

// Strict Zod schemas matching dotALT's `DisallowUnknownFields()`
export const ownershipCertificateSchema = z
  .object({
    schema: z.literal(SCHEMA_OWNERSHIP_V1),
    networkId: z.string().min(1),
    domain: z.string().min(1),
    accountId: z.string().min(1),
    ownerPublicKey: z.string().min(1),
    generation: z.number().int().positive(),
    issuedAt: z.string().min(1),
    expiresAt: z.string().min(1),
    issuerKeyId: z.string().min(1),
    signature: z.string().min(1),
  })
  .strict();

export const targetRecordSchema = z
  .object({
    schema: z.literal(SCHEMA_TARGET_V1),
    networkId: z.string().min(1),
    domain: z.string().min(1),
    ownershipGeneration: z.number().int().positive(),
    sequence: z.number().int().positive(),
    mode: z.enum(["https", "p2p"]),
    target: z.string().optional(),
    publisherIdentity: z.string().optional(),
    signalingEndpoints: z.array(z.string()).optional(),
    issuedAt: z.string().min(1),
    expiresAt: z.string().min(1),
    signature: z.string().min(1),
  })
  .strict();

/**
 * Validates timestamps identically to `dotALT/pkg/records.verifyTimestamps`:
 * - valid RFC3339
 * - expiresAt strictly after issuedAt
 * - issuedAt <= now + 5 minutes clock skew
 * - now < expiresAt
 */
export function verifyRecordTimestamps(
  issuedAtStr: string,
  expiresAtStr: string,
  now: Date = new Date(),
): void {
  const rfc3339Pattern =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
  if (!rfc3339Pattern.test(issuedAtStr)) {
    throw new Error("records: invalid issuedAt timestamp");
  }
  if (!rfc3339Pattern.test(expiresAtStr)) {
    throw new Error("records: invalid expiresAt timestamp");
  }
  const issuedMs = Date.parse(issuedAtStr);
  const expiresMs = Date.parse(expiresAtStr);
  if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs)) {
    throw new Error("records: invalid timestamp");
  }
  if (expiresMs <= issuedMs) {
    throw new Error("records: expiresAt must be strictly after issuedAt");
  }
  if (issuedMs > now.getTime() + 5 * 60 * 1000) {
    throw new Error("records: record issuedAt is in the future");
  }
  if (now.getTime() >= expiresMs) {
    throw new Error("records: record has expired");
  }
}

/**
 * Reproduces `dotALT/pkg/records.validateStrictEndpointURL` exactly:
 * enforces scheme (`https` or `wss`), host presence, port 1..65535,
 * and forbids whitespace, userinfo, query strings (`?`), and fragments (`#`).
 */
export function validateStrictEndpointUrl(
  rawUrl: string,
  expectedScheme: "https" | "wss",
): void {
  if (!rawUrl || rawUrl.trim() !== rawUrl || /[ \t\r\n]/.test(rawUrl)) {
    throw new Error("URL must not be empty or contain whitespace");
  }
  if (rawUrl.includes("?") || rawUrl.includes("#")) {
    throw new Error(
      "query parameters and fragments are not allowed in target/signaling URLs",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("malformed endpoint URL");
  }

  if (parsed.protocol !== `${expectedScheme}:`) {
    throw new Error(`scheme must be ${expectedScheme}`);
  }
  if (!parsed.host || !parsed.hostname) {
    throw new Error("host is required");
  }
  if (
    parsed.username ||
    parsed.password ||
    rawUrl
      .slice(parsed.protocol.length + 2)
      .split("/")[0]
      ?.includes("@")
  ) {
    throw new Error("userinfo is not allowed in target/signaling URLs");
  }

  const authority =
    rawUrl.slice(parsed.protocol.length + 2).split("/")[0] ?? "";
  if (authority.endsWith(":")) {
    throw new Error("empty port suffix is not allowed");
  }

  if (parsed.port !== "") {
    const portNum = Number(parsed.port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      throw new Error("port must be between 1 and 65535");
    }
  }

  if (authority.includes("[") || authority.includes("]")) {
    const unwrapped = parsed.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(unwrapped) !== 6) {
      throw new Error("invalid IPv6 literal in host");
    }
  } else if (net.isIP(parsed.hostname) === 0) {
    if (
      parsed.hostname.startsWith(".") ||
      parsed.hostname.endsWith(".") ||
      parsed.hostname.includes("..")
    ) {
      throw new Error("invalid DNS hostname");
    }
  }
}

/**
 * Validates semantic structure of OwnershipCertificate prior to / alongside Ed25519 signature check.
 */
export function validateOwnershipSemantics(
  cert: OwnershipCertificate,
  expectedNetworkId: string,
  expectedTld: string,
  now: Date = new Date(),
): void {
  if (cert.schema !== SCHEMA_OWNERSHIP_V1) {
    throw new Error("records: invalid or unsupported schema");
  }
  if (!expectedNetworkId || cert.networkId !== expectedNetworkId) {
    throw new Error(
      `records: missing or mismatched networkId: got "${cert.networkId}", want "${expectedNetworkId}"`,
    );
  }
  if (!isProtocolDomain(cert.domain, expectedTld)) {
    throw new Error("records: invalid domain name");
  }
  if (!Number.isSafeInteger(cert.generation) || cert.generation < 1) {
    throw new Error("records: invalid generation number");
  }
  if (!cert.issuerKeyId || cert.issuerKeyId.trim() === "") {
    throw new Error("records: unknown or untrusted issuerKeyId");
  }
  parseEd25519PublicKey(cert.ownerPublicKey);
  verifyRecordTimestamps(cert.issuedAt, cert.expiresAt, now);
}

/**
 * Validates semantic structure of TargetRecord against an OwnershipCertificate (`dotALT/pkg/records.TargetRecord.Verify`).
 */
export function validateTargetSemantics(
  target: TargetRecord,
  cert: OwnershipCertificate,
  now: Date = new Date(),
): void {
  if (target.schema !== SCHEMA_TARGET_V1) {
    throw new Error("records: invalid or unsupported schema");
  }
  if (!cert.networkId || target.networkId !== cert.networkId) {
    throw new Error("records: missing or mismatched networkId");
  }
  if (target.domain !== cert.domain) {
    throw new Error("records: target domain does not match ownership domain");
  }
  if (target.ownershipGeneration !== cert.generation) {
    throw new Error(
      "records: target ownershipGeneration does not match ownership generation",
    );
  }
  if (!Number.isSafeInteger(target.sequence) || target.sequence < 1) {
    throw new Error("records: invalid sequence number");
  }

  if (target.mode === "https") {
    if (
      (target.publisherIdentity && target.publisherIdentity.length > 0) ||
      (target.signalingEndpoints && target.signalingEndpoints.length > 0) ||
      !target.target
    ) {
      throw new Error("records: invalid target mode or invalid endpoint URL");
    }
    validateStrictEndpointUrl(target.target, "https");
  } else if (target.mode === "p2p") {
    if (
      (target.target && target.target.length > 0) ||
      !target.signalingEndpoints ||
      target.signalingEndpoints.length === 0 ||
      !target.publisherIdentity
    ) {
      throw new Error("records: invalid target mode or invalid endpoint URL");
    }
    parseEd25519PublicKey(target.publisherIdentity);
    for (const ep of target.signalingEndpoints) {
      validateStrictEndpointUrl(ep, "wss");
    }
  } else {
    throw new Error("records: invalid target mode or invalid endpoint URL");
  }

  verifyRecordTimestamps(target.issuedAt, target.expiresAt, now);
}

const RESERVED_ORIGIN_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "intranet",
  "home.arpa",
  "invalid",
  "example",
  "test",
  "onion",
] as const;

function parseIpv4Uint32(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = ((value << 8) | octet) >>> 0;
  }
  return value >>> 0;
}

function inIpv4Cidr(
  ipUint: number,
  baseIp: string,
  prefixLen: number,
): boolean {
  const baseUint = parseIpv4Uint32(baseIp);
  if (baseUint === null) return false;
  const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
  return (ipUint & mask) === (baseUint & mask);
}

function expandIpv6ToBytes(rawIp: string): Uint8Array | null {
  if (rawIp.includes("%")) {
    return null; // Reject zone IDs
  }
  let ip = rawIp.toLowerCase();

  // Handle embedded dotted-quad IPv4 suffix (e.g., ::ffff:127.0.0.1)
  const lastColon = ip.lastIndexOf(":");
  if (lastColon !== -1 && ip.slice(lastColon + 1).includes(".")) {
    const v4Uint = parseIpv4Uint32(ip.slice(lastColon + 1));
    if (v4Uint === null) return null;
    const hi = ((v4Uint >>> 16) & 0xffff).toString(16);
    const lo = (v4Uint & 0xffff).toString(16);
    ip = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const doubleColonParts = ip.split("::");
  if (doubleColonParts.length > 2) return null;

  const left =
    doubleColonParts[0] && doubleColonParts[0].length > 0
      ? doubleColonParts[0].split(":")
      : [];
  const right =
    doubleColonParts.length === 2 &&
    doubleColonParts[1] &&
    doubleColonParts[1].length > 0
      ? doubleColonParts[1].split(":")
      : [];

  let groups: string[];
  if (doubleColonParts.length === 2) {
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array<string>(missing).fill("0"), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i] ?? "";
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const val = Number.parseInt(g, 16);
    out[i * 2] = (val >>> 8) & 0xff;
    out[i * 2 + 1] = val & 0xff;
  }
  return out;
}

function inIpv6Prefix(
  addrBytes: Uint8Array,
  prefixBytes: readonly number[],
  prefixBits: number,
): boolean {
  const fullBytes = Math.floor(prefixBits / 8);
  const remBits = prefixBits % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (addrBytes[i] !== (prefixBytes[i] ?? 0)) {
      return false;
    }
  }
  if (remBits > 0) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    if (
      ((addrBytes[fullBytes] ?? 0) & mask) !==
      ((prefixBytes[fullBytes] ?? 0) & mask)
    ) {
      return false;
    }
  }
  return true;
}

function isDisallowedIpv4Uint32(ipUint: number): boolean {
  const disallowedRanges: ReadonlyArray<readonly [string, number]> = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
    ["255.255.255.255", 32],
  ];
  return disallowedRanges.some(([base, len]) => inIpv4Cidr(ipUint, base, len));
}

/**
 * Mirrors `dotALT/pkg/daemon.IsDisallowedOriginHost` so the public registry rejects
 * loopback, RFC1918, CGNAT, link-local, documentation, or special-use HTTPS/WSS target hosts up front.
 */
export function isDisallowedPublicEndpointHost(rawHost: string): boolean {
  const unwrapped = rawHost
    .trim()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();

  if (!unwrapped || unwrapped.includes("%")) {
    return true;
  }

  for (const suffix of RESERVED_ORIGIN_SUFFIXES) {
    if (unwrapped === suffix || unwrapped.endsWith(`.${suffix}`)) {
      return true;
    }
  }

  const ipVer = net.isIP(unwrapped);
  if (ipVer === 4) {
    const v4Uint = parseIpv4Uint32(unwrapped);
    return v4Uint === null || isDisallowedIpv4Uint32(v4Uint);
  }

  if (ipVer === 6) {
    const b = expandIpv6ToBytes(unwrapped);
    if (!b) return true;

    // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::/96
    const first10Zero = b.subarray(0, 10).every((x) => x === 0);
    if (first10Zero && b[10] === 0xff && b[11] === 0xff) {
      const embeddedV4 =
        (((b[12] ?? 0) << 24) |
          ((b[13] ?? 0) << 16) |
          ((b[14] ?? 0) << 8) |
          (b[15] ?? 0)) >>>
        0;
      return isDisallowedIpv4Uint32(embeddedV4);
    }
    if (b.subarray(0, 12).every((x) => x === 0)) {
      return true; // Unspecified ::, loopback ::1, and IPv4-compatible ::w.x.y.z/96
    }

    // Must be in global unicast 2000::/3 (`001xxxxx` in first byte)
    if (((b[0] ?? 0) & 0xe0) !== 0x20) {
      return true;
    }

    const disallowedV6: ReadonlyArray<readonly [readonly number[], number]> = [
      [[0x00, 0x64, 0xff, 0x9b], 96], // 64:ff9b::/96 (covered by 2000::/3 check too, kept for defense-in-depth)
      [[0x01, 0x00, 0x00, 0x00], 64], // 100::/64
      [[0x20, 0x01, 0x00, 0x00], 23], // 2001::/23 (Teredo, Benchmarking, IETF)
      [[0x20, 0x01, 0x0d, 0xb8], 32], // 2001:db8::/32 (Documentation)
      [[0x20, 0x02], 16], // 2002::/16 (6to4)
      [[0xfc], 7], // fc00::/7 (ULA)
      [[0xfe, 0x80], 10], // fe80::/10 (Link-Local)
      [[0xfe, 0xc0], 10], // fec0::/10 (Site-Local)
      [[0xff], 8], // ff00::/8 (Multicast)
    ];

    return disallowedV6.some(([prefix, bits]) => inIpv6Prefix(b, prefix, bits));
  }

  return false;
}
