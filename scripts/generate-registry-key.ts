#!/usr/bin/env bun
/**
 * Generates an Ed25519 registry authority keypair and optional `register.<tld>` bootstrap
 * manifest + profile OUTSIDE the repository working tree (§9.2, §15 Phase 1.6 & 1.7).
 *
 * Private keys are written with `0600` permissions strictly outside the git repository
 * and are NEVER printed to stdout or stderr.
 *
 * Usage:
 *   bun run scripts/generate-registry-key.ts \
 *     --keys-dir "$HOME/.alt-production-keys" \
 *     --out-dir /tmp/alt-public-bootstrap \
 *     --network-id alt-main-v1 \
 *     --tld alt \
 *     --key-id registry-2026 \
 *     --target https://alt.goker.dev
 */

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import {
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
  formatUtcRfc3339Seconds,
  SCHEMA_OWNERSHIP_V1,
  SCHEMA_TARGET_V1,
} from "../src/lib/records";
import {
  generateEd25519KeyMaterial,
  parseEd25519PrivateKeySecret,
  signOwnershipCertificateWithKey,
  signTargetRecordWithKey,
  verifyOwnershipCertificateSignature,
  verifyTargetRecordSignature,
} from "../src/lib/signing";

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    "keys-dir": { type: "string" },
    "out-dir": { type: "string" },
    "network-id": { type: "string", default: "alt-main-v1" },
    tld: { type: "string", default: "alt" },
    domain: { type: "string", default: "register.alt" },
    "key-id": { type: "string", default: "registry-2026" },
    target: { type: "string", default: "https://alt.goker.dev" },
    "valid-days": { type: "string", default: "3650" },
    "use-env-authority": { type: "boolean", default: false },
    "ipns-root": { type: "string" },
  },
  strict: true,
});

function loadOrCreateSafeKeyFile(filePath: string) {
  if (fs.existsSync(filePath)) {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`Refusing non-regular or symlink key file: ${filePath}`);
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(
        `Refusing key file ${filePath} with insecure permissions ${(stat.mode & 0o777).toString(8)} (expected 0600)`,
      );
    }
    const secretB64 = fs.readFileSync(filePath, "utf8").trim();
    return parseEd25519PrivateKeySecret(secretB64);
  }

  const generated = generateEd25519KeyMaterial();
  const encoded64 = `${generated.rawPrivateKey64.toString("base64")}\n`;
  fs.writeFileSync(filePath, encoded64, { mode: 0o600, flag: "wx" });
  return generated;
}

function main() {
  const keysDirArg = values["keys-dir"]?.trim();
  if (!keysDirArg) {
    console.error(
      "Error: --keys-dir is required and must point OUTSIDE this git repository.",
    );
    process.exit(1);
  }

  const repoRoot = path.resolve(import.meta.dir, "..");
  const absKeysDir = path.resolve(keysDirArg);
  if (
    absKeysDir === repoRoot ||
    absKeysDir.startsWith(`${repoRoot}${path.sep}`)
  ) {
    console.error(
      `Error: Refusing to write private keys inside repository (${absKeysDir}). Choose an external --keys-dir.`,
    );
    process.exit(1);
  }

  fs.mkdirSync(absKeysDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(absKeysDir, 0o700);
  const dirStat = fs.lstatSync(absKeysDir);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new Error(`keys-dir ${absKeysDir} must be a real directory`);
  }

  const networkId = values["network-id"] ?? "alt-main-v1";
  const tld = normalizeTld(values.tld ?? "alt");
  const normalizedBootstrap = normalizeProtocolDomain(
    values.domain ?? `register.${tld}`,
    tld,
  );
  const keyId = values["key-id"] ?? "registry-2026";
  const targetUrl = values.target ?? "https://alt.goker.dev";
  const validDays = Number.parseInt(values["valid-days"] ?? "3650", 10);
  if (!Number.isInteger(validDays) || validDays < 1) {
    throw new Error("--valid-days must be a positive integer");
  }

  const authorityKeyPath = path.join(absKeysDir, `${keyId}-authority.key`);
  const registerOwnerKeyPath = path.join(
    absKeysDir,
    `${normalizedBootstrap.label}-owner.key`,
  );

  let authorityKey: ReturnType<typeof parseEd25519PrivateKeySecret>;
  if (values["use-env-authority"]) {
    const envPriv = process.env.ALT_REGISTRY_PRIVATE_KEY?.trim();
    const envPub = process.env.ALT_REGISTRY_PUBLIC_KEY?.trim();
    if (!envPriv || !envPub) {
      throw new Error(
        "--use-env-authority requires ALT_REGISTRY_PRIVATE_KEY and ALT_REGISTRY_PUBLIC_KEY in environment",
      );
    }
    authorityKey = parseEd25519PrivateKeySecret(envPriv);
    if (authorityKey.publicKeyEncoded !== envPub) {
      throw new Error(
        "ALT_REGISTRY_PRIVATE_KEY does not match ALT_REGISTRY_PUBLIC_KEY",
      );
    }
  } else {
    authorityKey = loadOrCreateSafeKeyFile(authorityKeyPath);
  }
  const bootstrapOwnerKey = loadOrCreateSafeKeyFile(registerOwnerKeyPath);

  const now = new Date();
  const issuedSec = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const expiresSec = new Date(
    issuedSec.getTime() + validDays * 24 * 60 * 60 * 1000,
  );
  const issuedAt = formatUtcRfc3339Seconds(issuedSec);
  const expiresAt = formatUtcRfc3339Seconds(expiresSec);

  const ownership = signOwnershipCertificateWithKey(
    {
      schema: SCHEMA_OWNERSHIP_V1,
      networkId,
      domain: normalizedBootstrap.domain,
      accountId: "system:bootstrap",
      ownerPublicKey: bootstrapOwnerKey.publicKeyEncoded,
      generation: 1,
      issuedAt,
      expiresAt,
      issuerKeyId: keyId,
    },
    authorityKey.privateKeyObject,
  );

  const target = signTargetRecordWithKey(
    {
      schema: SCHEMA_TARGET_V1,
      networkId,
      domain: normalizedBootstrap.domain,
      ownershipGeneration: 1,
      sequence: 1,
      mode: "https",
      target: targetUrl,
      issuedAt,
      expiresAt,
    },
    bootstrapOwnerKey.privateKeyObject,
  );

  verifyOwnershipCertificateSignature(
    ownership,
    authorityKey.publicKeyEncoded,
    networkId,
    tld,
    issuedSec,
  );
  verifyTargetRecordSignature(target, ownership, issuedSec);

  const manifestBytes = serializeDeterministicManifest({
    networkId,
    generatedAt: issuedAt,
    entries: {
      [normalizedBootstrap.domain]: {
        ownership,
        target,
      },
    },
  });
  const manifestCid = computeRawCidV1(manifestBytes);
  verifyRawBlockCidV1(manifestCid, manifestBytes);

  console.log("Generated public registry authority & bootstrap metadata:");
  console.log(`  Network ID:              ${networkId}`);
  console.log(`  Namespace TLD:           .${tld}`);
  console.log(`  ALT_REGISTRY_KEY_ID:     ${keyId}`);
  console.log(`  ALT_REGISTRY_PUBLIC_KEY: ${authorityKey.publicKeyEncoded}`);
  console.log(`  Bootstrap Domain:        ${normalizedBootstrap.domain}`);
  console.log(
    `  Bootstrap Owner PubKey:  ${bootstrapOwnerKey.publicKeyEncoded}`,
  );
  console.log(`  Bootstrap Target URL:    ${targetUrl}`);
  console.log(`  Bootstrap Manifest CID:  ${manifestCid}`);
  console.log(`  Private keys stored in:  ${absKeysDir} (0600, never printed)`);

  if (values["out-dir"]) {
    const absOutDir = path.resolve(values["out-dir"]);
    fs.mkdirSync(absOutDir, { recursive: true, mode: 0o755 });

    const manifestPath = path.join(absOutDir, "manifest.json");
    fs.writeFileSync(manifestPath, manifestBytes, { mode: 0o644 });

    const ipnsRoot = values["ipns-root"]?.trim();
    const profileYaml = [
      "# Official .alt Network Profile (Public keys and content-addressed CID only)",
      "version: 1",
      `networkId: ${networkId}`,
      `tld: ${tld}`,
      "registryKeys:",
      `  - id: ${keyId}`,
      `    publicKey: ${authorityKey.publicKeyEncoded}`,
      "resolver:",
      `  manifestCid: ${manifestCid}`,
      ...(ipnsRoot ? [`  ipnsRoot: ${ipnsRoot}`] : []),
      "  gateways:",
      "    - https://ipfs.filebase.io",
      "    - https://ipfs.io",
      "reservedNames:",
      ...RESERVED_LABELS.map((label) => `  - ${label}`),
      "branding:",
      "  name: ALT",
      "",
    ].join("\n");

    const profilePath = path.join(absOutDir, "profile.yaml");
    fs.writeFileSync(profilePath, profileYaml, { mode: 0o644 });

    console.log(`  Wrote public manifest:   ${manifestPath}`);
    console.log(`  Wrote public profile:    ${profilePath}`);
  }
}

main();
