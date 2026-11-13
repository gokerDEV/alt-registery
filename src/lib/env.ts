import { z } from "zod";

const nonEmptyTrimmed = z.string().trim().min(1);

const baseConfigSchema = z.object({
  APP_URL: z
    .string()
    .trim()
    .default("http://localhost:3000")
    .transform((val) => val.replace(/\/+$/, ""))
    .refine((val) => {
      try {
        const parsed = new URL(val);
        return (
          (parsed.protocol === "https:" || parsed.protocol === "http:") &&
          parsed.pathname === "/" &&
          !parsed.search &&
          !parsed.hash
        );
      } catch {
        return false;
      }
    }, "APP_URL must be a bare http:// or https:// origin without path, query, or hash"),
  REGISTRATION_ENABLED: z
    .enum(["true", "false"])
    .default("true")
    .transform((val) => val === "true"),
  ALT_NETWORK_ID: z
    .string()
    .trim()
    .default("alt-main-v1")
    .refine(
      (val) => /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/.test(val),
      "ALT_NETWORK_ID must be 3-63 lowercase ASCII alphanumeric characters or hyphens",
    ),
  ALT_TLD: z
    .string()
    .trim()
    .default("alt")
    .transform((val) => val.toLowerCase().replace(/^\.+/, ""))
    .refine(
      (val) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(val),
      "ALT_TLD must be a valid DNS label",
    ),
  ALT_REGISTRY_KEY_ID: z
    .string()
    .trim()
    .default("registry-2026")
    .refine(
      (val) => /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(val),
      "ALT_REGISTRY_KEY_ID has an invalid format",
    ),
});

const mongoEnvSchema = z.object({
  MONGODB_URI: nonEmptyTrimmed.refine(
    (val) => val.startsWith("mongodb://") || val.startsWith("mongodb+srv://"),
    "MONGODB_URI must start with mongodb:// or mongodb+srv://",
  ),
  MONGODB_DB: z
    .string()
    .trim()
    .default("alt_registry")
    .refine(
      (val) => val.length > 0 && !/[/\\. "$]/.test(val),
      "Invalid MONGODB_DB name",
    ),
});

const webAuthEnvSchema = z.object({
  GITHUB_CLIENT_ID: nonEmptyTrimmed,
  GITHUB_CLIENT_SECRET: nonEmptyTrimmed,
  SESSION_SECRET: z
    .string()
    .min(
      32,
      "SESSION_SECRET must be at least 32 characters of high-entropy secret material",
    ),
});

const cliPepperEnvSchema = z.object({
  CLI_TOKEN_PEPPER: z
    .string()
    .min(
      32,
      "CLI_TOKEN_PEPPER must be at least 32 characters of high-entropy secret material",
    ),
});

const signingEnvSchema = z.object({
  ALT_REGISTRY_PUBLIC_KEY: nonEmptyTrimmed.refine(
    (val) => val.startsWith("ed25519:"),
    "ALT_REGISTRY_PUBLIC_KEY must start with ed25519:",
  ),
  ALT_REGISTRY_PRIVATE_KEY: nonEmptyTrimmed,
});

const ipfsEnvSchema = z.object({
  IPFS_API_URL: z
    .string()
    .trim()
    .min(1, "IPFS_API_URL is required")
    .transform((val) => val.replace(/\/+$/, ""))
    .refine((val) => {
      try {
        const parsed = new URL(val);
        return (
          parsed.protocol === "https:" ||
          (parsed.protocol === "http:" &&
            (parsed.hostname === "localhost" ||
              parsed.hostname === "127.0.0.1" ||
              parsed.hostname === "::1" ||
              parsed.hostname === "[::1]"))
        );
      } catch {
        return false;
      }
    }, "IPFS_API_URL must be an https:// URL (or http:// on loopback)"),
  IPFS_API_TOKEN: z.string().trim().optional(),
  IPNS_KEY_REFERENCE: z
    .string()
    .trim()
    .optional()
    .refine(
      (val) => !val || /^[A-Za-z0-9._-]+$/.test(val),
      "IPNS_KEY_REFERENCE has an invalid format",
    ),
  IPNS_EXPECTED_ROOT: z
    .string()
    .trim()
    .optional()
    .refine(
      (val) => !val || /^k51[a-z0-9]{50,}$/.test(val),
      "IPNS_EXPECTED_ROOT must be a valid base36 k51... IPNS root",
    ),
});

export type BaseConfig = z.infer<typeof baseConfigSchema>;

let cachedBaseConfig: BaseConfig | null = null;

export function getBaseConfig(): BaseConfig {
  if (cachedBaseConfig) {
    return cachedBaseConfig;
  }
  const parsed = baseConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid base environment configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  cachedBaseConfig = parsed.data;
  return cachedBaseConfig;
}

export function isHttpsAppUrl(): boolean {
  return getBaseConfig().APP_URL.startsWith("https://");
}

export function getMongoConfig() {
  const parsed = mongoEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid MongoDB environment configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  return parsed.data;
}

export function getWebAuthConfig() {
  const base = getBaseConfig();
  const parsed = webAuthEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid GitHub OAuth / Session environment configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  return {
    ...base,
    ...parsed.data,
  };
}

export function getSessionSecretString(): string | null {
  const raw = process.env.SESSION_SECRET;
  if (!raw || raw.length < 32) {
    return null;
  }
  return raw;
}

export function getCliPepper(): string {
  const parsed = cliPepperEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid CLI_TOKEN_PEPPER configuration: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
    );
  }
  return parsed.data.CLI_TOKEN_PEPPER;
}

export function getRegistrySigningConfig() {
  const base = getBaseConfig();
  const parsed = signingEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid registry signing key configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  return {
    networkId: base.ALT_NETWORK_ID,
    tld: base.ALT_TLD,
    keyId: base.ALT_REGISTRY_KEY_ID,
    publicKey: parsed.data.ALT_REGISTRY_PUBLIC_KEY,
    privateKey: parsed.data.ALT_REGISTRY_PRIVATE_KEY,
  };
}

export function getIpfsConfig() {
  const parsed = ipfsEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(
      `Invalid IPFS/IPNS environment configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`,
    );
  }
  return {
    apiUrl: parsed.data.IPFS_API_URL,
    apiToken:
      parsed.data.IPFS_API_TOKEN && parsed.data.IPFS_API_TOKEN.length > 0
        ? parsed.data.IPFS_API_TOKEN
        : undefined,
    ipnsKeyReference:
      parsed.data.IPNS_KEY_REFERENCE &&
      parsed.data.IPNS_KEY_REFERENCE.length > 0
        ? parsed.data.IPNS_KEY_REFERENCE
        : undefined,
    expectedIpnsRoot:
      parsed.data.IPNS_EXPECTED_ROOT &&
      parsed.data.IPNS_EXPECTED_ROOT.length > 0
        ? parsed.data.IPNS_EXPECTED_ROOT
        : undefined,
  };
}

/**
 * Redacts MongoDB URIs, bearer tokens, and base64 secrets from error messages before logging.
 */
export function redactErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw
    .replace(/mongodb(?:\+srv)?:\/\/[^\s"']+/gi, "mongodb://[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]");
}
