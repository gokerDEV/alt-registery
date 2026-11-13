#!/usr/bin/env bun
/**
 * Seeds `register.<tld>` and all reserved system names in MongoDB with `kind: "system"` (§6, §10, §15).
 * Because `domains` uses a partial unique index on `{ accountId: 1 }` filtered to `{ kind: "user" }`,
 * multiple system-owned reserved records share a dedicated system `accountId` cleanly without
 * colliding with user quotas.
 *
 * Optionally accepts `--bootstrap-manifest <path/to/manifest.json>` to attach the signed
 * `register.<tld>` bootstrap `ownershipRecord`, `targetRecord`, and `manifestCid`.
 *
 * Usage:
 *   bun run scripts/reserve-system-names.ts [--bootstrap-manifest /tmp/alt-public-bootstrap/manifest.json]
 */

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { ObjectId } from "mongodb";
import { normalizeProtocolDomain, RESERVED_LABELS } from "../src/lib/domains";
import { getBaseConfig, redactErrorMessage } from "../src/lib/env";
import { computeRawCidV1 } from "../src/lib/ipfs";
import {
  getCollections,
  getMongoClient,
  toMongoLong,
} from "../src/lib/mongodb";
import {
  type OwnershipCertificate,
  ownershipCertificateSchema,
  type TargetRecord,
  targetRecordSchema,
} from "../src/lib/records";

// Deterministic system pseudo-ObjectId (`000000000000000000000001`) for `kind: "system"` records
const SYSTEM_ACCOUNT_OBJECT_ID = new ObjectId("000000000000000000000001");

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    "bootstrap-manifest": { type: "string" },
    suspend: { type: "string" },
  },
  strict: true,
});

async function main() {
  const base = getBaseConfig();
  const { domains } = await getCollections();
  const now = new Date();

  if (values.suspend) {
    const norm = normalizeProtocolDomain(values.suspend, base.ALT_TLD);
    const res = await domains.findOneAndUpdate(
      { name: norm.domain, kind: "user" },
      {
        $set: {
          status: "suspended",
          updatedAt: now,
        },
      },
      { returnDocument: "after" },
    );
    if (!res) {
      console.error(`User domain not found: ${norm.domain}`);
      process.exit(1);
    }
    console.log(`Suspended user domain: ${res.name}`);
    return;
  }

  let bootstrapCert: OwnershipCertificate | undefined;
  let bootstrapTarget: TargetRecord | undefined;
  let bootstrapCid: string | undefined;

  if (values["bootstrap-manifest"]) {
    const manifestPath = path.resolve(values["bootstrap-manifest"]);
    const rawBytes = fs.readFileSync(manifestPath);
    bootstrapCid = computeRawCidV1(rawBytes);
    const parsedJson = JSON.parse(rawBytes.toString("utf8")) as {
      records?: Record<string, { ownership?: unknown; target?: unknown }>;
    };
    const registerFqdn = `register.${base.ALT_TLD}`;
    const entry = parsedJson.records?.[registerFqdn];
    if (!entry) {
      throw new Error(
        `Bootstrap manifest ${manifestPath} does not contain entry for ${registerFqdn}`,
      );
    }
    bootstrapCert = ownershipCertificateSchema.parse(entry.ownership);
    bootstrapTarget = targetRecordSchema.parse(entry.target);
  }

  for (const label of RESERVED_LABELS) {
    const { domain } = normalizeProtocolDomain(label, base.ALT_TLD);
    const isRegisterBootstrap =
      label === "register" && Boolean(bootstrapCert && bootstrapTarget);

    await domains.updateOne(
      { name: domain },
      {
        $set: {
          label,
          kind: "system",
          status: isRegisterBootstrap ? "active" : "suspended",
          publicationStatus: isRegisterBootstrap ? "published" : "not_ready",
          ...(isRegisterBootstrap && bootstrapCert && bootstrapTarget
            ? {
                generation: toMongoLong(bootstrapCert.generation),
                sequence: toMongoLong(bootstrapTarget.sequence),
                ownerPublicKey: bootstrapCert.ownerPublicKey,
                ownershipRecord: bootstrapCert,
                targetRecord: bootstrapTarget,
                manifestCid: bootstrapCid,
                publishedAt: now,
              }
            : {}),
          updatedAt: now,
        },
        $setOnInsert: {
          accountId: SYSTEM_ACCOUNT_OBJECT_ID,
          ...(!isRegisterBootstrap
            ? {
                generation: toMongoLong(0),
                sequence: toMongoLong(0),
              }
            : {}),
          createdAt: now,
        },
      },
      { upsert: true },
    );
    console.log(
      `Reserved system domain: ${domain}${isRegisterBootstrap ? ` (active bootstrap CID: ${bootstrapCid})` : ""}`,
    );
  }
}

main()
  .catch((err) => {
    console.error("Failed to seed system names:", redactErrorMessage(err));
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      const client = await getMongoClient();
      await client.close();
    } catch {
      // Ignore close error if connection was never established
    }
  });
