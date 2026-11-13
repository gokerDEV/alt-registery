import {
  type ClientSession,
  type Collection,
  type Db,
  Long,
  MongoClient,
  MongoServerError,
  type ObjectId,
} from "mongodb";
import { getMongoConfig, redactErrorMessage } from "@/lib/env";
import type { OwnershipCertificate, TargetRecord } from "@/lib/records";

export type DomainKind = "user" | "system";

export type DomainStatus =
  | "pending_key"
  | "pending_target"
  | "publication_pending"
  | "active"
  | "suspended";

export type PublicationStatus =
  | "not_ready"
  | "pending"
  | "published"
  | "failed";

export interface AccountDoc {
  _id: ObjectId;
  githubId: Long;
  githubLogin: string;
  avatarUrl?: string;
  ownerPublicKey?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface DomainDoc {
  _id: ObjectId;
  name: string;
  label: string;
  accountId: ObjectId;
  generation: Long;
  sequence: Long;
  kind: DomainKind;
  status: DomainStatus;
  ownerPublicKey?: string;
  ownershipRecord?: OwnershipCertificate;
  targetRecord?: TargetRecord;
  publicationStatus: PublicationStatus;
  manifestCid?: string;
  publishedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CliSessionDoc {
  _id: ObjectId;
  accountId: ObjectId;
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt?: Date;
  revokedAt?: Date;
}

export interface KeyChallengeDoc {
  _id: ObjectId;
  accountId: ObjectId;
  nonceHash: string;
  purpose: "bind_owner_key";
  expiresAt: Date;
  consumedAt?: Date;
  createdAt: Date;
}

export interface RateLimitDoc {
  _id: ObjectId;
  subjectHash: string;
  action: string;
  count: number;
  windowStartedAt: Date;
  expiresAt: Date;
  lockOwner?: string;
  logicalHash?: string;
  manifestCid?: string;
  ipnsName?: string | null;
  publishedAt?: Date;
}

declare global {
  // Preserve singleton client across HMR reloads in Next.js dev server
  var __altMongoClientPromise: Promise<MongoClient> | undefined;
  var __altMongoIndexesPromise: Promise<void> | undefined;
}

function createMongoClient(): Promise<MongoClient> {
  const { MONGODB_URI } = getMongoConfig();
  const client = new MongoClient(MONGODB_URI, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    connectTimeoutMS: 5000,
  });
  return client.connect().catch((err) => {
    globalThis.__altMongoClientPromise = undefined;
    throw new Error(`Database connection failed: ${redactErrorMessage(err)}`);
  });
}

export function getMongoClient(): Promise<MongoClient> {
  if (!globalThis.__altMongoClientPromise) {
    globalThis.__altMongoClientPromise = createMongoClient();
  }
  return globalThis.__altMongoClientPromise;
}

export async function getDb(): Promise<Db> {
  const { MONGODB_DB } = getMongoConfig();
  const client = await getMongoClient();
  return client.db(MONGODB_DB);
}

/**
 * Ensures all five MVP collections and their unique/partial/TTL indexes exist (§5).
 * Idempotent and cached per Node.js process after first completion.
 */
export function ensureIndexes(): Promise<void> {
  if (!globalThis.__altMongoIndexesPromise) {
    globalThis.__altMongoIndexesPromise = runEnsureIndexes().catch((err) => {
      globalThis.__altMongoIndexesPromise = undefined;
      throw new Error(
        `Failed to initialize MongoDB indexes: ${redactErrorMessage(err)}`,
      );
    });
  }
  return globalThis.__altMongoIndexesPromise;
}

async function runEnsureIndexes(): Promise<void> {
  const db = await getDb();

  await Promise.all([
    db
      .collection<AccountDoc>("accounts")
      .createIndex({ githubId: 1 }, { unique: true, name: "uniq_githubId" }),
    db.collection<DomainDoc>("domains").createIndexes([
      { key: { name: 1 }, unique: true, name: "uniq_domain_name" },
      {
        key: { accountId: 1 },
        unique: true,
        partialFilterExpression: { kind: "user" },
        name: "uniq_user_domain_per_account",
      },
    ]),
    db.collection<CliSessionDoc>("cliSessions").createIndexes([
      { key: { tokenHash: 1 }, unique: true, name: "uniq_cli_tokenHash" },
      {
        key: { expiresAt: 1 },
        expireAfterSeconds: 0,
        name: "ttl_cli_expiresAt",
      },
    ]),
    db.collection<KeyChallengeDoc>("keyChallenges").createIndexes([
      { key: { nonceHash: 1 }, unique: true, name: "uniq_challenge_nonceHash" },
      {
        key: { expiresAt: 1 },
        expireAfterSeconds: 0,
        name: "ttl_challenge_expiresAt",
      },
    ]),
    db.collection<RateLimitDoc>("rateLimits").createIndexes([
      {
        key: { subjectHash: 1, action: 1, windowStartedAt: 1 },
        unique: true,
        name: "uniq_rateLimit_bucket",
      },
      {
        key: { expiresAt: 1 },
        expireAfterSeconds: 0,
        name: "ttl_rateLimit_expiresAt",
      },
    ]),
  ]);
}

export async function getCollections(): Promise<{
  db: Db;
  accounts: Collection<AccountDoc>;
  domains: Collection<DomainDoc>;
  cliSessions: Collection<CliSessionDoc>;
  keyChallenges: Collection<KeyChallengeDoc>;
  rateLimits: Collection<RateLimitDoc>;
}> {
  await ensureIndexes();
  const db = await getDb();
  return {
    db,
    accounts: db.collection<AccountDoc>("accounts"),
    domains: db.collection<DomainDoc>("domains"),
    cliSessions: db.collection<CliSessionDoc>("cliSessions"),
    keyChallenges: db.collection<KeyChallengeDoc>("keyChallenges"),
    rateLimits: db.collection<RateLimitDoc>("rateLimits"),
  };
}

export async function withTransaction<T>(
  fn: (session: ClientSession) => Promise<T>,
): Promise<T> {
  const client = await getMongoClient();
  const session = client.startSession();
  try {
    let result!: T;
    await session.withTransaction(async () => {
      result = await fn(session);
    });
    return result;
  } finally {
    await session.endSession();
  }
}

export function isDuplicateKeyError(err: unknown): err is MongoServerError {
  return err instanceof MongoServerError && err.code === 11000;
}

export function toMongoLong(value: number | bigint | string): Long {
  return Long.fromString(String(value));
}

export function fromMongoLong(value: Long | number | bigint): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    return BigInt(Math.trunc(value));
  }
  return value.toBigInt();
}
