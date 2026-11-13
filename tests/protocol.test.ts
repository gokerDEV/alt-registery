import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import {
  evaluateDomainAllocationPolicy,
  isProtocolDomain,
  normalizeProtocolDomain,
  normalizeTld,
  RESERVED_LABELS,
} from "../src/lib/domains";
import {
  computeRawCidV1,
  serializeDeterministicManifest,
  verifyRawBlockCidV1,
} from "../src/lib/ipfs";
import {
  buildKeyChallengeSigningBytes,
  ownershipCertificateSchema,
  SCHEMA_OWNERSHIP_V1,
  SCHEMA_TARGET_V1,
  targetRecordSchema,
  validateStrictEndpointUrl,
} from "../src/lib/records";
import {
  generateEd25519KeyMaterial,
  signKeyChallengeWithKey,
  signOwnershipCertificateWithKey,
  signTargetRecordWithKey,
  verifyKeyChallengeSignature,
  verifyOwnershipCertificateSignature,
  verifyTargetRecordSignature,
} from "../src/lib/signing";

describe("domains: protocol & registry allocation rules", () => {
  test("matches dotALT/pkg/names test vectors for protocol normalization", () => {
    expect(normalizeProtocolDomain("local", "alt")).toEqual({
      domain: "local.alt",
      label: "local",
      tld: "alt",
    });
    expect(normalizeProtocolDomain("Blog.MESH.", ".mesh")).toEqual({
      domain: "blog.mesh",
      label: "blog",
      tld: "mesh",
    });
    expect(normalizeTld(".ALT")).toBe("alt");
    expect(isProtocolDomain("goker.alt", "alt")).toBe(true);
    expect(isProtocolDomain("Goker.alt", "alt")).toBe(false);
    expect(isProtocolDomain("x.alt", "alt")).toBe(true); // 1-char allowed at protocol layer

    for (const invalid of [
      "two.labels.alt",
      "-bad.alt",
      "bad-.alt",
      "bad_.alt",
      "",
    ]) {
      expect(() => normalizeProtocolDomain(invalid, "alt")).toThrow();
    }
  });

  test("enforces registry allocation policy (minLength 2, no xn--, reserved list)", () => {
    // 1-char rejected by allocation policy
    const oneChar = evaluateDomainAllocationPolicy("x", "alt");
    expect(oneChar.valid).toBe(false);
    expect(oneChar.reason).toBe("LABEL_TOO_SHORT");

    // Punycode rejected
    const puny = evaluateDomainAllocationPolicy("xn--bcher-kva", "alt");
    expect(puny.valid).toBe(false);
    expect(puny.reason).toBe("PUNYCODE_DISALLOWED");

    // All reserved names rejected and marked reserved: true
    for (const label of RESERVED_LABELS) {
      const res = evaluateDomainAllocationPolicy(label, "alt");
      expect(res.valid).toBe(false);
      expect(res.reserved).toBe(true);
      expect(res.reason).toBe("NAME_RESERVED");
      expect(res.domain).toBe(`${label}.alt`);
    }

    // Valid user label normalized cleanly
    const ok = evaluateDomainAllocationPolicy("  Goker-Dev.ALT. ", "alt");
    expect(ok).toEqual({
      valid: true,
      domain: "goker-dev.alt",
      label: "goker-dev",
      reserved: false,
    });
  });
});

describe("records & signing: cross-language golden verification with dotALT", () => {
  test("verifies real Go-generated fixture from dotALT/examples/demo-bootstrap", () => {
    const siblingManifestPath = path.resolve(
      import.meta.dir,
      "../../alt/examples/demo-bootstrap/manifest.json",
    );
    const siblingProfilePath = path.resolve(
      import.meta.dir,
      "../../alt/examples/demo-bootstrap/profile.yaml",
    );

    if (!fs.existsSync(siblingManifestPath)) {
      return;
    }

    const rawBytes = fs.readFileSync(siblingManifestPath);
    const profileText = fs.readFileSync(siblingProfilePath, "utf8");

    const cidMatch = profileText.match(/manifestCid:\s*(\S+)/);
    const pubKeyMatch = profileText.match(/publicKey:\s*(ed25519:\S+)/);
    expect(cidMatch).not.toBeNull();
    expect(pubKeyMatch).not.toBeNull();

    const expectedCid = cidMatch?.[1] ?? "";
    const authorityPub = pubKeyMatch?.[1] ?? "";

    // 1. Exact CIDv1 raw + sha2-256 parity with Go's resolver.ComputeRawCIDv1
    expect(computeRawCidV1(rawBytes)).toBe(expectedCid);
    expect(() => verifyRawBlockCidV1(expectedCid, rawBytes)).not.toThrow();

    // 2. Exact Ed25519 signature verification of Go-signed OwnershipCertificate & TargetRecord
    const parsed = JSON.parse(rawBytes.toString("utf8"));
    const registerEntry = parsed.records["register.alt"];
    const cert = ownershipCertificateSchema.parse(registerEntry.ownership);
    const target = targetRecordSchema.parse(registerEntry.target);

    const refNow = new Date("2026-11-13T00:00:00Z");
    expect(() =>
      verifyOwnershipCertificateSignature(
        cert,
        authorityPub,
        "alt-dev-demo-v1",
        "alt",
        refNow,
      ),
    ).not.toThrow();

    expect(() =>
      verifyTargetRecordSignature(target, cert, refNow),
    ).not.toThrow();

    // 3. Cross-network replay rejection
    expect(() =>
      verifyOwnershipCertificateSignature(
        cert,
        authorityPub,
        "alt-main-v1",
        "alt",
        refNow,
      ),
    ).toThrow();
  });

  test("signs and verifies ownership, HTTPS/P2P targets, challenge bytes, and deterministic manifest", () => {
    const authority = generateEd25519KeyMaterial();
    const owner = generateEd25519KeyMaterial();
    const p2pPub = generateEd25519KeyMaterial();
    const now = new Date("2026-11-13T14:00:00Z");

    // Key challenge wire format (§4.4)
    const challengePayload = {
      accountId: "gh:123456",
      ownerPublicKey: owner.publicKeyEncoded,
      nonce: "abc123_nonce-xyz",
      purpose: "bind_owner_key" as const,
      expiresAt: "2026-11-13T14:05:00Z",
    };
    const challengeBytes = buildKeyChallengeSigningBytes(
      "alt-main-v1",
      challengePayload,
    );
    expect(challengeBytes.toString("utf8")).toBe(
      `alt.key-challenge.v1\x00alt-main-v1\x00{"accountId":"gh:123456","ownerPublicKey":"${owner.publicKeyEncoded}","nonce":"abc123_nonce-xyz","purpose":"bind_owner_key","expiresAt":"2026-11-13T14:05:00Z"}`,
    );
    const challengeSig = signKeyChallengeWithKey(
      "alt-main-v1",
      challengePayload,
      owner.privateKeyObject,
    );
    expect(() =>
      verifyKeyChallengeSignature(
        "alt-main-v1",
        challengePayload,
        challengeSig,
      ),
    ).not.toThrow();
    expect(() =>
      verifyKeyChallengeSignature(
        "other-net-v1",
        challengePayload,
        challengeSig,
      ),
    ).toThrow();

    // Ownership certificate (§8.1)
    const cert = signOwnershipCertificateWithKey(
      {
        schema: SCHEMA_OWNERSHIP_V1,
        networkId: "alt-main-v1",
        domain: "goker.alt",
        accountId: "gh:123456",
        ownerPublicKey: owner.publicKeyEncoded,
        generation: 1,
        issuedAt: "2026-11-13T14:00:00Z",
        expiresAt: "2036-11-10T14:00:00Z",
        issuerKeyId: "registry-2026",
      },
      authority.privateKeyObject,
    );
    expect(() =>
      verifyOwnershipCertificateSignature(
        cert,
        authority.publicKeyEncoded,
        "alt-main-v1",
        "alt",
        now,
      ),
    ).not.toThrow();

    // HTTPS Target (§8.2)
    const httpsTarget = signTargetRecordWithKey(
      {
        schema: SCHEMA_TARGET_V1,
        networkId: "alt-main-v1",
        domain: "goker.alt",
        ownershipGeneration: 1,
        sequence: 1,
        mode: "https",
        target: "https://alt.goker.dev",
        issuedAt: "2026-11-13T14:00:00Z",
        expiresAt: "2027-11-13T14:00:00Z",
      },
      owner.privateKeyObject,
    );
    expect(() =>
      verifyTargetRecordSignature(httpsTarget, cert, now),
    ).not.toThrow();

    // P2P Target (§8.2)
    const p2pTarget = signTargetRecordWithKey(
      {
        schema: SCHEMA_TARGET_V1,
        networkId: "alt-main-v1",
        domain: "goker.alt",
        ownershipGeneration: 1,
        sequence: 2,
        mode: "p2p",
        publisherIdentity: p2pPub.publicKeyEncoded,
        signalingEndpoints: ["wss://signal.goker.dev/v1"],
        issuedAt: "2026-11-13T14:00:00Z",
        expiresAt: "2027-11-13T14:00:00Z",
      },
      owner.privateKeyObject,
    );
    expect(() =>
      verifyTargetRecordSignature(p2pTarget, cert, now),
    ).not.toThrow();

    // Strict endpoint URL rules matching Go's validateStrictEndpointURL
    expect(() =>
      validateStrictEndpointUrl("https://alt.goker.dev?foo=1", "https"),
    ).toThrow();
    expect(() =>
      validateStrictEndpointUrl("https://user:pass@alt.goker.dev", "https"),
    ).toThrow();
    expect(() =>
      validateStrictEndpointUrl("https://alt.goker.dev#frag", "https"),
    ).toThrow();

    // Deterministic manifest CIDv1 independent of insertion order
    const m1 = serializeDeterministicManifest({
      networkId: "alt-main-v1",
      generatedAt: "2026-11-13T14:00:00Z",
      entries: {
        "z-last.alt": { ownership: cert, target: httpsTarget },
        "a-first.alt": { ownership: cert, target: httpsTarget },
      },
    });
    const m2 = serializeDeterministicManifest({
      networkId: "alt-main-v1",
      generatedAt: "2026-11-13T14:00:00Z",
      entries: {
        "a-first.alt": { ownership: cert, target: httpsTarget },
        "z-last.alt": { ownership: cert, target: httpsTarget },
      },
    });
    expect(m1.equals(m2)).toBe(true);
    expect(computeRawCidV1(m1)).toBe(computeRawCidV1(m2));
  });
});
