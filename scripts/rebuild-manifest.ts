#!/usr/bin/env bun
/**
 * Builds a deterministic CIDv1 raw manifest (`0x55` + `sha2-256`) from MongoDB (§11):
 * - Loads the immutable signed `register.<tld>` system record
 * - Queries all `publication_pending` and `active` user domains with both valid ownership & target records
 * - Verifies every record signature and timestamp locally before inclusion
 * - Optionally packages into a single-block CARv1, imports to Filebase/Kubo `/api/v0/dag/import`,
 *   and updates IPNS via `/api/v0/name/publish` when `--publish` is passed.
 *
 * Usage:
 *   bun run scripts/rebuild-manifest.ts [--out ./manifest.json] [--publish] [--create-ipns-key] [--force]
 */

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { getBaseConfig, redactErrorMessage } from "../src/lib/env";
import {
  computeRawCidV1,
  publishRegistryManifest,
  serializeDeterministicManifest,
  verifyRawBlockCidV1,
} from "../src/lib/ipfs";
import { getCollections, getMongoClient } from "../src/lib/mongodb";
import {
  formatUtcRfc3339Seconds,
  type ManifestEntry,
} from "../src/lib/records";
import {
  verifyOwnershipCertificateSignature,
  verifyTargetRecordSignature,
} from "../src/lib/signing";

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    out: { type: "string" },
    publish: { type: "boolean", default: false },
    "create-ipns-key": { type: "boolean", default: false },
    force: { type: "boolean", default: false },
  },
  strict: true,
});

async function main() {
  const base = getBaseConfig();
  const authorityPubKey = process.env.ALT_REGISTRY_PUBLIC_KEY?.trim();
  if (!authorityPubKey) {
    throw new Error(
      "ALT_REGISTRY_PUBLIC_KEY is required to verify manifest records before publication",
    );
  }

  const { domains } = await getCollections();
  const registerFqdn = `register.${base.ALT_TLD}`;

  const bootstrapDoc = await domains.findOne({
    name: registerFqdn,
    kind: "system",
  });

  if (!bootstrapDoc?.ownershipRecord || !bootstrapDoc.targetRecord) {
    throw new Error(
      `Missing signed bootstrap record for ${registerFqdn} in MongoDB. Run scripts/reserve-system-names.ts --bootstrap-manifest first.`,
    );
  }

  const now = new Date();
  verifyOwnershipCertificateSignature(
    bootstrapDoc.ownershipRecord,
    authorityPubKey,
    base.ALT_NETWORK_ID,
    base.ALT_TLD,
    now,
  );
  verifyTargetRecordSignature(
    bootstrapDoc.targetRecord,
    bootstrapDoc.ownershipRecord,
    now,
  );

  const entries = new Map<string, ManifestEntry>();
  entries.set(registerFqdn, {
    ownership: bootstrapDoc.ownershipRecord,
    target: bootstrapDoc.targetRecord,
  });

  const cursor = domains.find({
    kind: "user",
    status: { $in: ["publication_pending", "active"] },
    ownershipRecord: { $exists: true },
    targetRecord: { $exists: true },
  });

  for await (const doc of cursor) {
    if (!doc.ownershipRecord || !doc.targetRecord) {
      continue;
    }
    verifyOwnershipCertificateSignature(
      doc.ownershipRecord,
      authorityPubKey,
      base.ALT_NETWORK_ID,
      base.ALT_TLD,
      now,
    );
    verifyTargetRecordSignature(doc.targetRecord, doc.ownershipRecord, now);
    entries.set(doc.name, {
      ownership: doc.ownershipRecord,
      target: doc.targetRecord,
    });
  }

  const generatedAt = formatUtcRfc3339Seconds(now);
  const rawManifestBytes = serializeDeterministicManifest({
    networkId: base.ALT_NETWORK_ID,
    generatedAt,
    entries,
  });

  const cid = computeRawCidV1(rawManifestBytes);
  verifyRawBlockCidV1(cid, rawManifestBytes);

  console.log(`Built deterministic manifest for ${base.ALT_NETWORK_ID}:`);
  console.log(`  Included domains: ${entries.size}`);
  console.log(`  Manifest size:    ${rawManifestBytes.byteLength} bytes`);
  console.log(`  Raw CIDv1:        ${cid}`);

  if (values.out) {
    const outPath = path.resolve(values.out);
    fs.writeFileSync(outPath, rawManifestBytes, { mode: 0o644 });
    console.log(`  Saved to:         ${outPath}`);
  }

  if (values.publish) {
    const pubResult = await publishRegistryManifest({
      force: values.force,
      createKeyIfMissing: values["create-ipns-key"],
    });
    console.log("IPFS / IPNS Publication:");
    console.log(
      `  Published:        ${pubResult.published}${pubResult.skippedUnchanged ? " (skipped unchanged logical snapshot)" : ""}`,
    );
    console.log(`  Manifest CIDv1:   ${pubResult.manifestCid}`);
    console.log(
      `  IPNS Root:        ${pubResult.ipnsName ?? "(not configured)"}`,
    );
    console.log(`  Published At:     ${pubResult.publishedAt.toISOString()}`);
  }
}

main()
  .catch((err) => {
    console.error("Manifest rebuild failed:", redactErrorMessage(err));
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      const client = await getMongoClient();
      await client.close();
    } catch {
      // Ignore
    }
  });
