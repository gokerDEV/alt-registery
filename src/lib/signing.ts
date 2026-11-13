import crypto from "node:crypto";
import { getRegistrySigningConfig } from "@/lib/env";
import {
  buildKeyChallengeSigningBytes,
  buildOwnershipSigningBytes,
  buildTargetSigningBytes,
  canonicalizeOwnershipCertificate,
  formatEd25519PublicKey,
  formatUtcRfc3339Seconds,
  type KeyChallengePayload,
  type OwnershipCertificate,
  parseEd25519PublicKey,
  parseStandardBase64Signature,
  SCHEMA_OWNERSHIP_V1,
  type TargetRecord,
  type UnsignedOwnershipCertificate,
  type UnsignedTargetRecord,
  validateOwnershipSemantics,
  validateTargetSemantics,
} from "@/lib/records";

// PKCS#8 ASN.1 DER prefix for a 32-byte Ed25519 seed (RFC 8410)
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
// SPKI ASN.1 DER prefix for a 32-byte Ed25519 public key (RFC 8410)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Ed25519KeyMaterial {
  privateKeyObject: crypto.KeyObject;
  publicKeyObject: crypto.KeyObject;
  publicKeyEncoded: string; // "ed25519:<base64>"
  rawPrivateKey64: Buffer; // Go-compatible 64-byte Ed25519 private key (seed || pub)
}

export function createEd25519PublicKeyObject(
  encodedPublicKey: string,
): crypto.KeyObject {
  const rawPub = parseEd25519PublicKey(encodedPublicKey);
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub]),
    format: "der",
    type: "spki",
  });
}

/**
 * Parses an `ALT_REGISTRY_PRIVATE_KEY` secret into Node.js KeyObjects.
 * Accepts:
 * - base64-encoded 64-byte Go `ed25519.PrivateKey` (as produced by `cmd/alt-bootstrap-gen`), optionally prefixed with `ed25519:`
 * - base64-encoded 32-byte Ed25519 seed, optionally prefixed with `ed25519:`
 * Never logs or echoes secret bytes on failure.
 */
export function parseEd25519PrivateKeySecret(
  secret: string,
): Ed25519KeyMaterial {
  const trimmed = secret.trim();
  const b64 = trimmed.startsWith("ed25519:")
    ? trimmed.slice("ed25519:".length)
    : trimmed;

  const decoded = Buffer.from(b64, "base64");
  if (decoded.byteLength !== 32 && decoded.byteLength !== 64) {
    throw new Error(
      "Invalid Ed25519 private key secret length (expected 32-byte seed or 64-byte Go Ed25519 private key in base64)",
    );
  }

  const seed = decoded.subarray(0, 32);
  const privateKeyObject = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicKeyObject = crypto.createPublicKey(privateKeyObject);
  const spkiDer = publicKeyObject.export({ format: "der", type: "spki" });
  const derivedPubBytes = Buffer.from(spkiDer).subarray(
    ED25519_SPKI_PREFIX.byteLength,
  );

  if (decoded.byteLength === 64) {
    const embeddedPub = decoded.subarray(32, 64);
    if (!crypto.timingSafeEqual(derivedPubBytes, embeddedPub)) {
      throw new Error(
        "Ed25519 64-byte private key public suffix does not match seed",
      );
    }
  }

  return {
    privateKeyObject,
    publicKeyObject,
    publicKeyEncoded: formatEd25519PublicKey(derivedPubBytes),
    rawPrivateKey64: Buffer.concat([seed, derivedPubBytes]),
  };
}

export function generateEd25519KeyMaterial(): Ed25519KeyMaterial {
  const seed = crypto.randomBytes(32);
  return parseEd25519PrivateKeySecret(seed.toString("base64"));
}

export function signOwnershipCertificateWithKey(
  unsigned: UnsignedOwnershipCertificate,
  privateKeyObject: crypto.KeyObject,
): OwnershipCertificate {
  const signingBytes = buildOwnershipSigningBytes(unsigned);
  const sig = crypto.sign(null, signingBytes, privateKeyObject);
  return canonicalizeOwnershipCertificate({
    ...unsigned,
    signature: sig.toString("base64"),
  });
}

export function verifyOwnershipCertificateSignature(
  cert: OwnershipCertificate,
  authorityPublicKeyEncoded: string,
  expectedNetworkId: string,
  expectedTld: string,
  now: Date = new Date(),
): void {
  validateOwnershipSemantics(cert, expectedNetworkId, expectedTld, now);
  const pubKeyObj = createEd25519PublicKeyObject(authorityPublicKeyEncoded);
  const sigBytes = parseStandardBase64Signature(cert.signature);
  const msgBytes = buildOwnershipSigningBytes(cert);

  if (!crypto.verify(null, msgBytes, pubKeyObj, sigBytes)) {
    throw new Error("records: signature verification failed");
  }
}

export function signTargetRecordWithKey(
  unsigned: UnsignedTargetRecord,
  ownerPrivateKeyObject: crypto.KeyObject,
): TargetRecord {
  const signingBytes = buildTargetSigningBytes(unsigned);
  const sig = crypto.sign(null, signingBytes, ownerPrivateKeyObject);
  return {
    ...unsigned,
    signature: sig.toString("base64"),
  };
}

export function verifyTargetRecordSignature(
  target: TargetRecord,
  cert: OwnershipCertificate,
  now: Date = new Date(),
): void {
  validateTargetSemantics(target, cert, now);
  const ownerPubObj = createEd25519PublicKeyObject(cert.ownerPublicKey);
  const sigBytes = parseStandardBase64Signature(target.signature);
  const msgBytes = buildTargetSigningBytes(target);

  if (!crypto.verify(null, msgBytes, ownerPubObj, sigBytes)) {
    throw new Error("records: signature verification failed");
  }
}

export function signKeyChallengeWithKey(
  networkId: string,
  payload: KeyChallengePayload,
  ownerPrivateKeyObject: crypto.KeyObject,
): string {
  const msgBytes = buildKeyChallengeSigningBytes(networkId, payload);
  return crypto.sign(null, msgBytes, ownerPrivateKeyObject).toString("base64");
}

export function verifyKeyChallengeSignature(
  networkId: string,
  payload: KeyChallengePayload,
  signatureBase64: string,
): void {
  const ownerPubObj = createEd25519PublicKeyObject(payload.ownerPublicKey);
  const sigBytes = parseStandardBase64Signature(signatureBase64);
  const msgBytes = buildKeyChallengeSigningBytes(networkId, payload);

  if (!crypto.verify(null, msgBytes, ownerPubObj, sigBytes)) {
    throw new Error("records: challenge signature verification failed");
  }
}

const TEN_YEARS_DAYS = 3650;

/**
 * Issues and signs an authority `alt.ownership.v1` certificate using the configured registry authority key (§8.1).
 * Verifies at load time that `ALT_REGISTRY_PRIVATE_KEY` matches `ALT_REGISTRY_PUBLIC_KEY`.
 */
export function issueOwnershipCertificate(params: {
  domain: string;
  githubId: bigint | number | string;
  ownerPublicKey: string;
  generation: number;
  now?: Date;
}): OwnershipCertificate {
  const cfg = getRegistrySigningConfig();
  const keyMaterial = parseEd25519PrivateKeySecret(cfg.privateKey);

  if (keyMaterial.publicKeyEncoded !== cfg.publicKey) {
    throw new Error(
      "Registry signing configuration mismatch: ALT_REGISTRY_PRIVATE_KEY does not match ALT_REGISTRY_PUBLIC_KEY",
    );
  }

  const issuedDate = params.now ?? new Date();
  const issuedSec = new Date(Math.floor(issuedDate.getTime() / 1000) * 1000);
  const expiresSec = new Date(
    issuedSec.getTime() + TEN_YEARS_DAYS * 24 * 60 * 60 * 1000,
  );

  const accountId = `gh:${String(params.githubId)}`;
  const cert = signOwnershipCertificateWithKey(
    {
      schema: SCHEMA_OWNERSHIP_V1,
      networkId: cfg.networkId,
      domain: params.domain,
      accountId,
      ownerPublicKey: params.ownerPublicKey,
      generation: params.generation,
      issuedAt: formatUtcRfc3339Seconds(issuedSec),
      expiresAt: formatUtcRfc3339Seconds(expiresSec),
      issuerKeyId: cfg.keyId,
    },
    keyMaterial.privateKeyObject,
  );

  verifyOwnershipCertificateSignature(
    cert,
    cfg.publicKey,
    cfg.networkId,
    cfg.tld,
    issuedSec,
  );
  return cert;
}
