import crypto from "node:crypto";
import { getBaseConfig, getIpfsConfig, redactErrorMessage } from "@/lib/env";
import { getCollections } from "@/lib/mongodb";
import {
  canonicalizeOwnershipCertificate,
  canonicalizeTargetRecord,
  formatUtcRfc3339Seconds,
  type ManifestEntry,
  SCHEMA_MANIFEST_V1,
  serializeOwnershipCertificate,
  serializeTargetRecord,
} from "@/lib/records";
import {
  verifyOwnershipCertificateSignature,
  verifyTargetRecordSignature,
} from "@/lib/signing";

const RFC4648_BASE32_LOWER = "abcdefghijklmnopqrstuvwxyz234567";

function encodeBase32LowerNoPad(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_BASE32_LOWER[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += RFC4648_BASE32_LOWER[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32LowerNoPad(input: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const ch of input.toLowerCase()) {
    const idx = RFC4648_BASE32_LOWER.indexOf(ch);
    if (idx === -1) {
      throw new Error("ipfs: invalid base32 character in CIDv1");
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * Decodes a base32lower CIDv1 raw + sha2-256 string (`b...`) into its 36-byte binary CID.
 */
export function decodeRawCidV1Binary(cidInput: string): Buffer {
  const cid = cidInput.trim();
  if (!cid.startsWith("b") || cid.length < 10) {
    throw new Error(
      "ipfs: unsupported CID format: expected base32 CIDv1 starting with 'b'",
    );
  }
  const decoded = decodeBase32LowerNoPad(cid.slice(1));
  if (decoded.byteLength !== 36 || decoded[0] !== 0x01) {
    throw new Error(
      "ipfs: unsupported CIDv1 multicodec or multihash length (expected raw + sha2-256)",
    );
  }
  if (decoded[1] !== 0x55) {
    throw new Error(
      `ipfs: unsupported CIDv1 codec 0x${decoded[1]?.toString(16)}: expected raw (0x55)`,
    );
  }
  if (decoded[2] !== 0x12 || decoded[3] !== 0x20) {
    throw new Error("ipfs: unsupported CIDv1 multihash: expected sha2-256");
  }
  return decoded;
}

/**
 * Computes deterministic CIDv1 (raw multicodec 0x55, sha2-256 0x12/0x20, base32lower 'b')
 * matching `dotALT/pkg/resolver.ComputeRawCIDv1` byte-for-byte.
 */
export function computeRawCidV1(data: Uint8Array): string {
  const digest = crypto.createHash("sha256").update(data).digest();
  const cidBinary = Buffer.concat([
    Buffer.from([0x01, 0x55, 0x12, 0x20]),
    digest,
  ]);
  return `b${encodeBase32LowerNoPad(cidBinary)}`;
}

/**
 * Verifies untrusted bytes or an IPFS provider's returned CID against `dotALT/pkg/resolver.VerifyBlockCID`.
 */
export function verifyRawBlockCidV1(
  expectedCid: string,
  data: Uint8Array,
): void {
  const decoded = decodeRawCidV1Binary(expectedCid);
  const actualDigest = crypto.createHash("sha256").update(data).digest();
  if (!crypto.timingSafeEqual(decoded.subarray(4), actualDigest)) {
    throw new Error(
      `ipfs: content-addressing hash mismatch for CID ${expectedCid.trim()}`,
    );
  }
}

/**
 * Encodes an unsigned integer as an unsigned LEB128 varint (used by CARv1 block length prefixes).
 */
export function encodeUvarint(n: number): Buffer {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error("ipfs: invalid uvarint input");
  }
  const bytes: number[] = [];
  let rem = n;
  while (rem >= 0x80) {
    bytes.push((rem & 0x7f) | 0x80);
    rem = Math.floor(rem / 128);
  }
  bytes.push(rem);
  return Buffer.from(bytes);
}

/**
 * Packages a single raw block and its deterministic raw CIDv1 (`0x55` + `sha2-256`)
 * into a spec-compliant IPLD CARv1 archive (`{ roots: [CID], version: 1 }`) per `PLAN.md` §11 step 5.
 *
 * Canonical DAG-CBOR map key order sorts by UTF-8 byte length first (`"roots"` len 5 < `"version"` len 7):
 * - `0xa2`: map(2)
 * - `0x65` + `"roots"`: text(5)
 * - `0x81`: array(1)
 * - `0xd8 0x2a`: CBOR tag(42) (IPLD Link)
 * - `0x58 0x25` + `0x00` + `<36-byte CIDv1>`: bytes(37) with `0x00` multibase identity prefix
 * - `0x67` + `"version"`: text(7)
 * - `0x01`: unsigned(1)
 */
export function buildSingleBlockCarV1(
  rawBlock: Uint8Array,
  expectedCid?: string,
): { carBytes: Buffer; cid: string } {
  const computedCid = computeRawCidV1(rawBlock);
  if (expectedCid && expectedCid.trim() !== computedCid) {
    throw new Error(
      `ipfs: CARv1 root CID mismatch (expected ${expectedCid.trim()}, computed ${computedCid})`,
    );
  }
  const cidBinary = decodeRawCidV1Binary(computedCid); // 36 bytes

  const dagCborHeader = Buffer.concat([
    Buffer.from([0xa2]), // map(2)
    Buffer.from("65726f6f7473", "hex"), // "roots"
    Buffer.from([0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00]), // [ tag(42), bytes(37), 0x00
    cidBinary, // 36-byte binary CIDv1
    Buffer.from("6776657273696f6e", "hex"), // "version"
    Buffer.from([0x01]), // 1
  ]);

  const headerLengthPrefix = encodeUvarint(dagCborHeader.byteLength);
  const sectionLengthPrefix = encodeUvarint(
    cidBinary.byteLength + rawBlock.byteLength,
  );

  return {
    cid: computedCid,
    carBytes: Buffer.concat([
      headerLengthPrefix,
      dagCborHeader,
      sectionLengthPrefix,
      cidBinary,
      Buffer.from(rawBlock),
    ]),
  };
}

export const MAX_MANIFEST_BYTES = 1 << 20; // 1 MiB (`dotALT/pkg/resolver.MaxManifestBytes`)

/**
 * Builds deterministic manifest JSON bytes sorted by canonical domain name (§11),
 * enforcing canonical field ordering for nested ownership and target records and the 1 MiB limit.
 */
export function serializeDeterministicManifest(params: {
  networkId: string;
  generatedAt: string;
  entries: ReadonlyMap<string, ManifestEntry> | Record<string, ManifestEntry>;
}): Buffer {
  const map =
    params.entries instanceof Map
      ? params.entries
      : new Map(Object.entries(params.entries));

  const sortedDomains = [...map.keys()].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );

  const recordEntriesJson = sortedDomains.map((domain) => {
    const entry = map.get(domain);
    if (!entry) {
      throw new Error(`ipfs: missing manifest entry for ${domain}`);
    }
    const ownJson = serializeOwnershipCertificate(
      canonicalizeOwnershipCertificate(entry.ownership),
    );
    const tgtJson = serializeTargetRecord(
      canonicalizeTargetRecord(entry.target),
    );
    return `${JSON.stringify(domain)}:{"ownership":${ownJson},"target":${tgtJson}}`;
  });

  const compact = `{"schema":${JSON.stringify(SCHEMA_MANIFEST_V1)},"networkId":${JSON.stringify(params.networkId)},"generatedAt":${JSON.stringify(params.generatedAt)},"records":{${recordEntriesJson.join(",")}}}\n`;
  const rawBytes = Buffer.from(compact, "utf8");

  if (rawBytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new Error(
      `ipfs: manifest size (${rawBytes.byteLength} bytes) exceeds 1 MiB client limit`,
    );
  }
  return rawBytes;
}

/**
 * Computes a logical digest of the sorted manifest entries (excluding `generatedAt`)
 * so unchanged logical snapshots avoid redundant IPFS/IPNS publication (§11).
 */
export function computeLogicalManifestHash(params: {
  networkId: string;
  entries: ReadonlyMap<string, ManifestEntry> | Record<string, ManifestEntry>;
}): string {
  const normalizedBytes = serializeDeterministicManifest({
    networkId: params.networkId,
    generatedAt: "1970-01-01T00:00:00Z",
    entries: params.entries,
  });
  return crypto.createHash("sha256").update(normalizedBytes).digest("hex");
}

function buildRpcAuthHeaders(apiToken?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "alt-registry/0.1",
  };
  if (apiToken) {
    headers.Authorization = `Bearer ${apiToken}`;
  }
  return headers;
}

/**
 * Imports a single-block raw manifest CARv1 archive via Kubo/Filebase `/api/v0/dag/import`
 * and verifies that the provider's imported root CID equals our locally computed CIDv1 (§11 steps 5 & 6).
 */
export async function importRawManifestCarToIpfs(
  rawManifestBytes: Uint8Array,
  options?: {
    apiUrl?: string;
    apiToken?: string;
    fetchImpl?: typeof fetch;
  },
): Promise<{ cid: string }> {
  const cfg = options?.apiUrl
    ? { apiUrl: options.apiUrl.replace(/\/+$/, ""), apiToken: options.apiToken }
    : getIpfsConfig();
  const fetchFn = options?.fetchImpl ?? fetch;

  verifyRawBlockCidV1(computeRawCidV1(rawManifestBytes), rawManifestBytes);
  const { carBytes, cid: expectedCid } =
    buildSingleBlockCarV1(rawManifestBytes);

  const form = new FormData();
  form.append(
    "file",
    new Blob([new Uint8Array(carBytes)], {
      type: "application/vnd.ipld.car",
    }),
    "manifest.car",
  );

  const importUrl = `${cfg.apiUrl}/api/v0/dag/import?pin-roots=true`;
  const response = await fetchFn(importUrl, {
    method: "POST",
    headers: buildRpcAuthHeaders(cfg.apiToken),
    body: form,
    signal: AbortSignal.timeout(20_000),
  });

  const bodyText = await response.text();
  if (!response.ok) {
    throw new Error(
      `IPFS /api/v0/dag/import failed with HTTP ${response.status}: ${redactErrorMessage(bodyText).slice(0, 240)}`,
    );
  }

  // Parse NDJSON lines returned by `/api/v0/dag/import`
  const lines = bodyText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  let importedCid: string | null = null;
  for (const line of lines) {
    let parsed: {
      Root?: {
        Cid?: { "/"?: string };
        PinErrorMsg?: string;
        PinError?: string;
      };
      Message?: string;
    };
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error("IPFS /api/v0/dag/import returned malformed JSON");
    }
    if (parsed.Message && !parsed.Root) {
      throw new Error(
        `IPFS /api/v0/dag/import error: ${redactErrorMessage(parsed.Message)}`,
      );
    }
    const pinErr = parsed.Root?.PinErrorMsg || parsed.Root?.PinError;
    if (pinErr) {
      throw new Error(
        `IPFS /api/v0/dag/import pin error: ${redactErrorMessage(pinErr)}`,
      );
    }
    const candidate = parsed.Root?.Cid?.["/"];
    if (typeof candidate === "string" && candidate.length > 0) {
      importedCid = candidate.trim();
    }
  }

  if (!importedCid) {
    throw new Error(
      "IPFS /api/v0/dag/import response did not include an imported Root CID",
    );
  }
  if (importedCid !== expectedCid) {
    throw new Error(
      `IPFS provider returned unexpected root CID ${importedCid} (expected ${expectedCid})`,
    );
  }

  // Re-verify returned CID against our local bytes (§11 step 6)
  verifyRawBlockCidV1(importedCid, rawManifestBytes);

  return { cid: importedCid };
}

/**
 * Lists or creates a named Ed25519 IPNS key on the Kubo/Filebase RPC keychain.
 */
export async function ensureIpnsKeyOnRpc(options?: {
  apiUrl?: string;
  apiToken?: string;
  keyName?: string;
  createIfMissing?: boolean;
  fetchImpl?: typeof fetch;
}): Promise<{ name: string; id: string }> {
  const envCfg = options?.apiUrl ? null : getIpfsConfig();
  const apiUrl = (options?.apiUrl ?? envCfg?.apiUrl ?? "").replace(/\/+$/, "");
  const apiToken = options?.apiToken ?? envCfg?.apiToken;
  const keyName = options?.keyName ?? envCfg?.ipnsKeyReference;
  const fetchFn = options?.fetchImpl ?? fetch;

  if (!keyName) {
    throw new Error(
      "IPNS_KEY_REFERENCE is required to resolve or create an IPNS key",
    );
  }

  const listRes = await fetchFn(`${apiUrl}/api/v0/key/list`, {
    method: "POST",
    headers: buildRpcAuthHeaders(apiToken),
    signal: AbortSignal.timeout(15_000),
  });
  if (!listRes.ok) {
    throw new Error(`IPFS /api/v0/key/list failed with HTTP ${listRes.status}`);
  }
  const listData = (await listRes.json()) as {
    Keys?: Array<{ Name?: string; Id?: string }>;
  };
  const existing = (listData.Keys ?? []).find(
    (k) => k.Name === keyName || k.Id === keyName,
  );
  if (existing?.Name && existing.Id) {
    return { name: existing.Name, id: existing.Id };
  }

  if (!options?.createIfMissing) {
    throw new Error(
      `IPNS key "${keyName}" was not found in Filebase/Kubo RPC keychain (/api/v0/key/list)`,
    );
  }

  const genUrl = `${apiUrl}/api/v0/key/gen?arg=${encodeURIComponent(keyName)}&type=ed25519&ipns-base=base36`;
  const genRes = await fetchFn(genUrl, {
    method: "POST",
    headers: buildRpcAuthHeaders(apiToken),
    signal: AbortSignal.timeout(15_000),
  });
  const genText = await genRes.text();
  if (!genRes.ok) {
    throw new Error(
      `IPFS /api/v0/key/gen failed with HTTP ${genRes.status}: ${redactErrorMessage(genText).slice(0, 240)}`,
    );
  }
  const created = JSON.parse(genText) as { Name?: string; Id?: string };
  if (!created.Name || !created.Id) {
    throw new Error("IPFS /api/v0/key/gen returned incomplete key metadata");
  }
  return { name: created.Name, id: created.Id };
}

/**
 * Publishes `/ipfs/<manifestCid>` to the configured IPNS key via `/api/v0/name/publish` (§11 step 8).
 */
export async function publishCidToIpns(
  manifestCid: string,
  options?: {
    apiUrl?: string;
    apiToken?: string;
    ipnsKeyReference?: string;
    expectedIpnsRoot?: string;
    fetchImpl?: typeof fetch;
  },
): Promise<{ ipnsName: string; value: string }> {
  const envCfg = options?.apiUrl ? null : getIpfsConfig();
  const apiUrl = (options?.apiUrl ?? envCfg?.apiUrl ?? "").replace(/\/+$/, "");
  const apiToken = options?.apiToken ?? envCfg?.apiToken;
  const keyRef = options?.ipnsKeyReference ?? envCfg?.ipnsKeyReference;
  const expectedRoot = options?.expectedIpnsRoot ?? envCfg?.expectedIpnsRoot;
  const fetchFn = options?.fetchImpl ?? fetch;

  if (!keyRef) {
    throw new Error("IPNS_KEY_REFERENCE is not configured");
  }

  const params = new URLSearchParams({
    arg: `/ipfs/${manifestCid}`,
    key: keyRef,
    "ipns-base": "base36",
  });

  const publishRes = await fetchFn(
    `${apiUrl}/api/v0/name/publish?${params.toString()}`,
    {
      method: "POST",
      headers: buildRpcAuthHeaders(apiToken),
      signal: AbortSignal.timeout(30_000),
    },
  );
  const bodyText = await publishRes.text();
  if (!publishRes.ok) {
    throw new Error(
      `IPFS /api/v0/name/publish failed with HTTP ${publishRes.status}: ${redactErrorMessage(bodyText).slice(0, 240)}`,
    );
  }

  let parsed: { Name?: string; Value?: string; Message?: string };
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new Error("IPFS /api/v0/name/publish returned malformed JSON");
  }

  if (!parsed.Name || !parsed.Value) {
    throw new Error(
      `IPFS /api/v0/name/publish error: ${redactErrorMessage(parsed.Message ?? "missing Name or Value")}`,
    );
  }

  if (expectedRoot && parsed.Name !== expectedRoot) {
    throw new Error(
      `IPNS publish key mismatch: got ${parsed.Name}, expected pinned ipnsRoot ${expectedRoot}`,
    );
  }

  const normalizedValue = parsed.Value.startsWith("/ipfs/")
    ? parsed.Value.slice("/ipfs/".length).trim()
    : parsed.Value.trim();
  if (normalizedValue !== manifestCid) {
    throw new Error(
      `IPNS publish value mismatch: got ${parsed.Value}, expected /ipfs/${manifestCid}`,
    );
  }

  return {
    ipnsName: parsed.Name,
    value: `/ipfs/${normalizedValue}`,
  };
}

const PUBLICATION_LOCK_SUBJECT = "manifest_publisher_singleton";
const PUBLICATION_LOCK_ACTION = "manifest_publish_lock";
const PUBLICATION_STATE_ACTION = "manifest_publish_state";
const PUBLICATION_LOCK_TTL_MS = 45_000;

export interface ManifestPublicationResult {
  published: boolean;
  skippedUnchanged: boolean;
  manifestCid: string;
  ipnsName: string | null;
  includedDomainCount: number;
  publishedAt: Date;
}

/**
 * Acquires a short-lived MongoDB lock (stored in `rateLimits` with TTL expiry so MVP stays strictly
 * on the five collections in `PLAN.md` §5), builds the deterministic manifest from `register.<tld>`
 * plus all `publication_pending` and `active` user domains, imports the CARv1 to IPFS, updates IPNS,
 * and marks included domains `published` / `active` (§11).
 */
export async function publishRegistryManifest(options?: {
  force?: boolean;
  createKeyIfMissing?: boolean;
  fetchImpl?: typeof fetch;
}): Promise<ManifestPublicationResult> {
  const base = getBaseConfig();
  const ipfsCfg = getIpfsConfig();
  const authorityPubKey = process.env.ALT_REGISTRY_PUBLIC_KEY?.trim();
  if (!authorityPubKey) {
    throw new Error(
      "ALT_REGISTRY_PUBLIC_KEY is required to verify manifest records before publication",
    );
  }

  const { domains, rateLimits } = await getCollections();
  const lockWindowStart = new Date(0);
  const lockOwnerToken = crypto.randomBytes(16).toString("hex");

  // Retry lock acquisition briefly if another concurrent request is finishing publication (§11)
  let lockAcquired = false;
  for (let attempt = 0; attempt < 4; attempt++) {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + PUBLICATION_LOCK_TTL_MS);
    try {
      const lockRes = await rateLimits.findOneAndUpdate(
        {
          subjectHash: PUBLICATION_LOCK_SUBJECT,
          action: PUBLICATION_LOCK_ACTION,
          windowStartedAt: lockWindowStart,
          $or: [{ expiresAt: { $lte: now } }, { count: 0 }],
        },
        {
          $set: {
            count: 1,
            expiresAt,
            lockOwner: lockOwnerToken,
          },
          $setOnInsert: {
            subjectHash: PUBLICATION_LOCK_SUBJECT,
            action: PUBLICATION_LOCK_ACTION,
            windowStartedAt: lockWindowStart,
          },
        },
        {
          upsert: true,
          returnDocument: "after",
        },
      );
      if (lockRes?.lockOwner === lockOwnerToken) {
        lockAcquired = true;
        break;
      }
    } catch {
      // Lock currently held (`count: 1` and `expiresAt > now` caused duplicate key on upsert)
    }
    await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
  }

  if (!lockAcquired) {
    throw new Error(
      "Another manifest publication is currently in progress; retry shortly",
    );
  }

  const assertAndExtendLockLease = async (): Promise<void> => {
    const leaseNow = new Date();
    const renewed = await rateLimits.findOneAndUpdate(
      {
        subjectHash: PUBLICATION_LOCK_SUBJECT,
        action: PUBLICATION_LOCK_ACTION,
        windowStartedAt: lockWindowStart,
        count: 1,
        lockOwner: lockOwnerToken,
        expiresAt: { $gt: leaseNow },
      },
      {
        $set: {
          expiresAt: new Date(leaseNow.getTime() + PUBLICATION_LOCK_TTL_MS),
        },
      },
      { returnDocument: "after" },
    );
    if (!renewed) {
      throw new Error("LOCK_LEASE_LOST");
    }
  };

  const includedUserDomainIds: Array<import("mongodb").ObjectId> = [];
  const pendingFirstPublishIds: Array<import("mongodb").ObjectId> = [];
  let lostLockLease = false;

  try {
    const registerFqdn = `register.${base.ALT_TLD}`;
    const bootstrapDoc = await domains.findOne({
      name: registerFqdn,
      kind: "system",
    });

    if (!bootstrapDoc?.ownershipRecord || !bootstrapDoc.targetRecord) {
      throw new Error(
        `Missing signed bootstrap record for ${registerFqdn} in MongoDB`,
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

    const userDocs = await domains
      .find({
        kind: "user",
        status: { $in: ["publication_pending", "active"] },
        ownershipRecord: { $exists: true },
        targetRecord: { $exists: true },
      })
      .toArray();

    let hasUnpublishedDomain = false;
    for (const doc of userDocs) {
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
      includedUserDomainIds.push(doc._id);
      if (doc.status === "publication_pending") {
        pendingFirstPublishIds.push(doc._id);
        hasUnpublishedDomain = true;
      }
      if (doc.publicationStatus !== "published") {
        hasUnpublishedDomain = true;
      }
    }

    const logicalHash = computeLogicalManifestHash({
      networkId: base.ALT_NETWORK_ID,
      entries,
    });

    const prevState = await rateLimits.findOne({
      subjectHash: PUBLICATION_LOCK_SUBJECT,
      action: PUBLICATION_STATE_ACTION,
      windowStartedAt: lockWindowStart,
    });

    if (
      !options?.force &&
      !hasUnpublishedDomain &&
      prevState?.logicalHash === logicalHash &&
      prevState.manifestCid
    ) {
      return {
        published: false,
        skippedUnchanged: true,
        manifestCid: prevState.manifestCid,
        ipnsName: prevState.ipnsName ?? null,
        includedDomainCount: entries.size,
        publishedAt: prevState.publishedAt ?? now,
      };
    }

    const generatedAt = formatUtcRfc3339Seconds(now);
    const rawManifestBytes = serializeDeterministicManifest({
      networkId: base.ALT_NETWORK_ID,
      generatedAt,
      entries,
    });

    const { cid: manifestCid } = await importRawManifestCarToIpfs(
      rawManifestBytes,
      {
        apiUrl: ipfsCfg.apiUrl,
        apiToken: ipfsCfg.apiToken,
        fetchImpl: options?.fetchImpl,
      },
    );

    // Ensure our lock lease is still owned before mutating IPNS or MongoDB state
    await assertAndExtendLockLease();

    let ipnsName: string | null = null;
    if (ipfsCfg.ipnsKeyReference) {
      const resolvedKey = await ensureIpnsKeyOnRpc({
        apiUrl: ipfsCfg.apiUrl,
        apiToken: ipfsCfg.apiToken,
        keyName: ipfsCfg.ipnsKeyReference,
        createIfMissing: Boolean(options?.createKeyIfMissing),
        fetchImpl: options?.fetchImpl,
      });

      const expectedRoot =
        ipfsCfg.expectedIpnsRoot ??
        (prevState?.ipnsName?.startsWith("k51")
          ? prevState.ipnsName
          : undefined);
      if (expectedRoot && resolvedKey.id !== expectedRoot) {
        throw new Error(
          `IPNS key ID mismatch: keychain returned ${resolvedKey.id}, expected pinned ipnsRoot ${expectedRoot}`,
        );
      }

      await assertAndExtendLockLease();

      await publishCidToIpns(manifestCid, {
        apiUrl: ipfsCfg.apiUrl,
        apiToken: ipfsCfg.apiToken,
        ipnsKeyReference: ipfsCfg.ipnsKeyReference,
        fetchImpl: options?.fetchImpl,
      });
      ipnsName = resolvedKey.id;
    }

    await assertAndExtendLockLease();
    const publishedAt = new Date();

    // Persist latest CID, logical snapshot hash, and IPNS name (§11 step 7)
    await rateLimits.updateOne(
      {
        subjectHash: PUBLICATION_LOCK_SUBJECT,
        action: PUBLICATION_STATE_ACTION,
        windowStartedAt: lockWindowStart,
      },
      {
        $set: {
          count: entries.size,
          logicalHash,
          manifestCid,
          ipnsName,
          publishedAt,
          // Far-future TTL so MongoDB keeps the latest manifest metadata across restarts
          expiresAt: new Date(
            publishedAt.getTime() + 10 * 365 * 24 * 60 * 60 * 1000,
          ),
        },
        $setOnInsert: {
          subjectHash: PUBLICATION_LOCK_SUBJECT,
          action: PUBLICATION_STATE_ACTION,
          windowStartedAt: lockWindowStart,
        },
      },
      { upsert: true },
    );

    // Step 9: Update included user domains (`publicationStatus: "published"`, `manifestCid`, `publishedAt`)
    if (includedUserDomainIds.length > 0) {
      await domains.updateMany(
        { _id: { $in: includedUserDomainIds } },
        {
          $set: {
            publicationStatus: "published",
            manifestCid,
            publishedAt,
            updatedAt: publishedAt,
          },
        },
      );
    }

    // Transition ONLY first-publication domains from `publication_pending` -> `active`
    if (pendingFirstPublishIds.length > 0) {
      await domains.updateMany(
        {
          _id: { $in: pendingFirstPublishIds },
          status: "publication_pending",
        },
        {
          $set: {
            status: "active",
            updatedAt: publishedAt,
          },
        },
      );
    }

    return {
      published: true,
      skippedUnchanged: false,
      manifestCid,
      ipnsName,
      includedDomainCount: entries.size,
      publishedAt,
    };
  } catch (err) {
    if (err instanceof Error && err.message === "LOCK_LEASE_LOST") {
      lostLockLease = true;
      throw new Error(
        "Manifest publication lock lease expired while another publisher took over; retry shortly",
      );
    }

    // Only mark pending domains `failed` if we still own the publication lock
    const lockCheckNow = new Date();
    const stillOwnsLock = await rateLimits
      .findOne({
        subjectHash: PUBLICATION_LOCK_SUBJECT,
        action: PUBLICATION_LOCK_ACTION,
        windowStartedAt: lockWindowStart,
        count: 1,
        lockOwner: lockOwnerToken,
        expiresAt: { $gt: lockCheckNow },
      })
      .catch(() => null);

    if (stillOwnsLock && includedUserDomainIds.length > 0) {
      await domains.updateMany(
        {
          _id: { $in: includedUserDomainIds },
          publicationStatus: "pending",
        },
        {
          $set: {
            publicationStatus: "failed",
            updatedAt: new Date(),
          },
        },
      );
    }
    throw err;
  } finally {
    // Release publication lock ONLY if still owned by this publisher (`lockOwner: lockOwnerToken`)
    if (!lostLockLease) {
      await rateLimits
        .updateOne(
          {
            subjectHash: PUBLICATION_LOCK_SUBJECT,
            action: PUBLICATION_LOCK_ACTION,
            windowStartedAt: lockWindowStart,
            lockOwner: lockOwnerToken,
          },
          {
            $set: {
              count: 0,
              lockOwner: "",
              expiresAt: new Date(Date.now() + 60_000),
            },
          },
        )
        .catch(() => undefined);
    }
  }
}
