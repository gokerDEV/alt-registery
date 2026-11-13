# register.alt Implementation Plan

**Public Internet origin:** `https://alt.goker.dev`  
**ALT origin:** `https://register.alt`  
**Repository:** `alt-registry`, a separate public repository owned and published from the same personal account as `dotALT`  
**Scope:** one Next.js application, one MongoDB database, one deployment

## 1. Goal

Build the smallest useful registry for the official `.alt` network:

- users sign in with GitHub;
- each GitHub account can register one `.alt` domain initially;
- users can see their registered domain and its status;
- the `alt` CLI authenticates with GitHub and calls the same registry API;
- the website reserves a name to the authenticated GitHub account;
- the CLI generates the owner's Ed25519 key and proves possession before the registry issues the ownership certificate;
- the registry publishes the updated signed manifest to IPFS;
- `register.alt` is reserved for the registry itself and can never be registered by a user.

This is not a monorepo and does not need separate web, API, signing, or infrastructure services for the MVP.

## 2. Technology

- **Next.js:** latest stable Active LTS release at implementation time. As of November 13, 2026, this means Next.js 16.x; do not use canary builds in production.
- **React and TypeScript:** versions selected by the latest stable `create-next-app`.
- **UI:** latest official `shadcn` CLI and components.
- **Component base:** keep the existing shadcn `base-luma` / `@base-ui/react` setup; do not rewrite generated components to Radix examples.
- **Tooling:** Bun and Biome, matching the initialized repository. Do not add ESLint unless a concrete rule is unavailable in Biome.
- **Authentication:** direct GitHub OAuth route handlers with `jose` for the website; GitHub OAuth Device Flow for the CLI.
- **Database:** MongoDB Atlas using the official MongoDB Node.js driver.
- **Deployment:** Vercel, serving `alt.goker.dev`.
- **Record signing:** Node.js Ed25519 using the canonical byte format defined by `dotALT`.
- **Record distribution:** Filebase hosts the production IPFS RPC and IPNS publisher. A fixed CID bootstraps `register.alt`; a Filebase-managed IPNS pointer distributes the changing user-domain manifest from the first public registration.

Bootstrap commands:

```bash
bun create next-app@latest alt-registry --ts --tailwind --app --src-dir --import-alias "@/*"
cd alt-registry
bunx shadcn@latest init
bunx shadcn@latest add button card input label field alert dialog table badge
bun add mongodb zod jose
```

The application has already been initialized locally as `alt-registery`; Phase 1 renames its package metadata to `alt-registry` before publication. The commands above document a clean-room setup for contributors. Pin exact dependency versions in `bun.lock`. “Latest” means the latest stable release selected when the repository is created, not an unbounded production dependency policy. Prefer shadcn's current `field` component or native React 19 forms with Zod over the legacy React Hook Form-based `form` component.

## 3. Repository layout

```text
alt-registry/
├── src/
│   ├── app/
│   │   ├── page.tsx
│   │   ├── dashboard/page.tsx
│   │   ├── api/auth/github/route.ts
│   │   ├── api/auth/callback/github/route.ts
│   │   ├── api/auth/logout/route.ts
│   │   ├── api/cli/session/
│   │   ├── api/account/key/challenge/
│   │   ├── api/account/key/verify/
│   │   ├── api/account/
│   │   ├── api/domains/check/
│   │   ├── api/domains/
│   │   └── api/domains/[name]/target/
│   ├── components/
│   │   └── ui/
│   └── lib/
│       ├── auth.ts
│       ├── mongodb.ts
│       ├── domains.ts
│       ├── signing.ts
│       ├── records.ts
│       ├── ipfs.ts
│       └── session.ts
├── scripts/
│   ├── generate-registry-key.ts
│   ├── reserve-system-names.ts
│   └── rebuild-manifest.ts
├── public/
├── .env.example
├── LICENSE
├── README.md
└── package.json
```

Use route handlers inside the Next.js application. Do not create another API service.

## 4. Authentication

### 4.1 Website login

Use one GitHub OAuth App initially.

- Homepage button: **Continue with GitHub**.
- OAuth callback URL: `https://alt.goker.dev/api/auth/callback/github`.
- Request the minimum identity scope needed.
- Use GitHub's immutable numeric user ID as the account identity.
- Store the current login name and avatar only as display metadata; never use the login name as the unique account key.
- Create an encrypted, HTTP-only, `SameSite=Lax` session cookie; set `Secure` whenever `APP_URL` uses HTTPS, including production.
- Regenerate the session after login; logout deletes the session cookie.

Implement GitHub OAuth directly in three small Node.js route handlers using authorization code flow, `state`, and PKCE where supported. Use `jose` to create an encrypted and authenticated JWT session cookie. Do not add Auth.js, Better Auth, or a MongoDB-backed web-session collection for the MVP. Global web-session revocation is outside the MVP unless a server-side session-version field is added later.

`APP_URL` is the canonical authenticated web origin: `https://alt.goker.dev` in production and normally `http://localhost:3000` in local development. `register.alt` is a bootstrap/discovery address and redirects browser navigation to the configured production `APP_URL`; it does not attempt to share cookies across the two origins. OAuth callbacks and authenticated form submissions occur only on `APP_URL`. Browser mutation endpoints accept only an `Origin` that exactly matches `APP_URL`.

When `dotALT` proxies `https://register.alt`, it rewrites `Host` to the target origin, removes `X-Forwarded-Host`, and adds `X-Alt-Domain: register.alt`. Therefore, a browser navigation request carrying that exact header receives a `307` redirect to the fixed, server-configured `APP_URL`. The redirect destination must never be derived from `X-Alt-Domain` or any other request header; the header is an untrusted routing signal that can also be sent directly by a client.

### 4.2 CLI login

The CLI uses GitHub's Device Flow:

```text
alt login github
    → request device_code and user_code from GitHub
    → display github.com/login/device and the user code
    → poll GitHub at the required interval
    → receive a GitHub access token
    → POST /api/cli/session to alt.goker.dev
    → registry verifies the token with GitHub GET /user
    → registry returns an ALT CLI session token
```

Rules:

- Enable Device Flow on the same GitHub OAuth App.
- Respect GitHub's returned polling interval and expiry.
- The CLI sends the GitHub token once to exchange it for an ALT token.
- The registry validates the token directly with GitHub and keys the account by numeric GitHub ID.
- Store only a hash of the ALT CLI token in MongoDB.
- Show the raw ALT token only once to the CLI.
- Give CLI tokens an explicit expiry, initially 30 days.
- `alt logout` deletes the local token and revokes the server session.
- Store the local token in the OS credential store when available; a `0600` file is only a fallback.

### 4.3 Owner key binding

GitHub authentication proves account identity, but it does not provide the Ed25519 owner key required by the `dotALT` ownership and target-record protocol.

The registry never stores an owner private key. The binding flow is:

```text
web user reserves a domain
    → domain status is pending_key
    → alt CLI generates or loads the account owner Ed25519 key locally
    → CLI requests a short-lived, single-use challenge
    → CLI signs networkId + accountId + ownerPublicKey + challenge + expiry
    → registry verifies the signature
    → registry binds ownerPublicKey to the account
    → registry issues the authority-signed ownership certificate
    → domain moves to pending_target
```

Rules:

- One owner key is bound to an account initially and may control its single domain.
- The private key stays on the user's device and is stored in the OS credential store or a `0600` fallback file.
- Challenges expire after five minutes and are consumed exactly once.
- Challenge signatures are domain-separated and include the configured network ID, account ID, public key, nonce, purpose, and expiry.
- Binding requires a valid ALT CLI session belonging to the same GitHub account that reserved the domain.
- Key replacement/recovery is outside the first MVP and must not be implemented as an unauthenticated overwrite.
- If an account has already bound its owner key before reserving a domain, `POST /api/domains` issues the ownership certificate immediately and returns `pending_target` instead of `pending_key`.

### 4.4 Challenge signature wire format

The Go CLI and TypeScript registry sign and verify exactly these bytes:

```text
alt.key-challenge.v1\x00<networkId>\x00<compact-json>
```

The compact JSON object has this exact key order and no whitespace:

```json
{"accountId":"gh:123456","ownerPublicKey":"ed25519:...","nonce":"base64url...","purpose":"bind_owner_key","expiresAt":"2026-11-13T14:00:00Z"}
```

`networkId` is `ALT_NETWORK_ID`; its production value is `alt-main-v1`, while local or forked profiles may use another value. Timestamps use UTC RFC3339 with whole-second precision. Golden Go/TypeScript vectors are required before the endpoint is implemented.

## 5. MongoDB model

Use five collections for the MVP.

### `accounts`

```ts
{
  _id: ObjectId,
  githubId: Long,             // unique, immutable GitHub numeric ID
  githubLogin: string,        // display only
  avatarUrl?: string,
  ownerPublicKey?: string,   // set only after challenge proof
  createdAt: Date,
  updatedAt: Date
}
```

Indexes:

```js
{ githubId: 1 } unique
```

### `domains`

```ts
{
  _id: ObjectId,
  name: string,               // canonical full name, e.g. goker.alt
  label: string,              // e.g. goker
  accountId: ObjectId,
  generation: Long,           // 0 until ownership is issued, then starts at 1
  sequence: Long,             // 0 until a target is accepted, then starts at 1
  kind: "user" | "system",
  status: "pending_key" | "pending_target" | "publication_pending" | "active" | "suspended",
  ownerPublicKey?: string,
  ownershipRecord?: object,
  targetRecord?: object,
  publicationStatus: "not_ready" | "pending" | "published" | "failed",
  manifestCid?: string,
  publishedAt?: Date,
  createdAt: Date,
  updatedAt: Date
}
```

Indexes:

```js
{ name: 1 } unique
{ accountId: 1 } unique with partialFilterExpression: { kind: "user" }
```

### `cliSessions`

```ts
{
  _id: ObjectId,
  accountId: ObjectId,
  tokenHash: string,          // HMAC-SHA256(CLI_TOKEN_PEPPER, 256-bit random token)
  createdAt: Date,
  expiresAt: Date,
  lastUsedAt?: Date,
  revokedAt?: Date
}
```

Indexes:

```js
{ tokenHash: 1 } unique
{ expiresAt: 1 } expireAfterSeconds: 0
```

The partial unique `accountId` index in `domains` is the authoritative one-domain limit for user domains. System records such as `register.alt` use `kind: "system"` and do not collide with the one-domain user policy. `githubId` remains unique only in `accounts`; UI checks are not security controls.

### `keyChallenges`

```ts
{
  _id: ObjectId,
  accountId: ObjectId,
  nonceHash: string,
  purpose: "bind_owner_key",
  expiresAt: Date,
  consumedAt?: Date,
  createdAt: Date
}
```

Indexes:

```js
{ nonceHash: 1 } unique
{ expiresAt: 1 } expireAfterSeconds: 0
```

### `rateLimits`

```ts
{
  _id: ObjectId,
  subjectHash: string,         // HMAC/hashed IP or account identifier; excludes action
  action: string,
  count: number,
  windowStartedAt: Date,
  expiresAt: Date
}
```

Indexes:

```js
{ subjectHash: 1, action: 1, windowStartedAt: 1 } unique
{ expiresAt: 1 } expireAfterSeconds: 0
```

## 6. Domain rules

- Accept one lowercase ASCII label under `.alt`.
- Normalize before checking availability.
- Use the same protocol-validity rules and test vectors as `dotALT/pkg/names`.
- Reject uppercase input after normalization only if the API contract requires canonical input; otherwise normalize and return the canonical result.
- Reject labels shorter than 2 characters as an explicit registry allocation policy; the underlying `dotALT` protocol still permits one-character labels.
- Reject labels longer than 63 characters.
- Allow lowercase letters, digits, and interior hyphens.
- Reject leading/trailing hyphens.
- Reject labels beginning with `xn--` until IDN policy is deliberately introduced.
- Reserve at least: `register`, `www`, `api`, `admin`, `status`, `search`, `support`, `mail`, `ns`, `root`, `alt`.
- Keep the reserved-name list in `src/lib/domains.ts`, synchronized with the official `dotALT` profile, and enforce it before every insert.

`register.alt` must be created as a system-owned bootstrap record, not as a normal user domain.

## 7. API

All JSON endpoints use strict schemas, stable error codes, and rate limits.

```text
GET  /api/account
GET  /api/domains/check?name=goker
POST /api/domains
POST /api/cli/session
DELETE /api/cli/session
POST /api/account/key/challenge
POST /api/account/key/verify
PUT  /api/domains/:name/target
```

### `GET /api/domains/check`

Returns canonical name, availability, reserved status, and whether the current account already owns a domain. It does not reserve the name.

### `POST /api/domains`

Request:

```json
{ "name": "goker" }
```

Transaction:

1. Authenticate the web session or ALT CLI bearer token.
2. Normalize and validate the label.
3. Reject reserved names.
4. Insert the user-domain document with unique `name` and partial-unique `accountId` indexes.
5. If a duplicate-key error occurs, return `NAME_TAKEN` or `DOMAIN_LIMIT_REACHED`.
6. If the account has no owner key, commit and return `pending_key`.
7. If the account already has a verified owner key, create and store the ownership certificate in the same transaction and return `pending_target`.

MongoDB deployment must support transactions. External signing and IPFS calls do not run inside a MongoDB transaction.

After successful owner-key verification, the registry creates the ownership record, signs it, stores it, and changes the domain to `pending_target`. Ownership-only domains are not added to an IPFS manifest because the current `dotALT` resolver requires both ownership and target records.

### Owner-key endpoints

`POST /api/account/key/challenge` returns a short-lived random challenge for the authenticated CLI account. `POST /api/account/key/verify` accepts the public key, challenge, expiry, and signature; consumes the challenge atomically; binds the key; and issues the ownership certificate for an existing `pending_key` reservation.

### `PUT /api/domains/:name/target`

This endpoint is used by `alt publish`, not by ordinary web registration. It accepts an owner-signed `alt.target.v1` record and:

1. authenticates the account;
2. loads the stored ownership certificate;
3. strictly decodes the target record;
4. verifies network ID, domain, ownership generation, owner signature, timestamps, target mode, and URL rules exactly as `dotALT/pkg/records` does;
5. requires a sequence strictly greater than the stored target sequence, except an identical idempotent retry of the same signed record;
6. stores the target and sets `publicationStatus: "pending"`; for the first target it also changes `status` from `pending_target` to `publication_pending`, while an already `active` domain remains `active` during sequence 2+ updates;
7. triggers manifest publication after the database commit.

If publication fails, the domain remains allocated with `publicationStatus: "failed"`; a retry republishes it. Never roll back ownership merely because IPFS is unavailable.

## 8. Protocol wire formats

### 8.1 Ownership certificate

The TypeScript implementation must reproduce `dotALT/pkg/records` exactly. Ownership signing bytes are:

```text
alt.ownership.v1\x00<networkId>\x00<compact-json>
```

The compact JSON object has this exact key order and no whitespace:

```text
schema, networkId, domain, accountId, ownerPublicKey,
generation, issuedAt, expiresAt, issuerKeyId
```

Decisions:

- `accountId` is the stable string `gh:<githubNumericId>`; MongoDB ObjectIds never appear in signed protocol records.
- `generation` starts at `1`.
- `issuedAt` and `expiresAt` use UTC RFC3339 whole-second precision.
- Ownership certificates initially expire ten years after issuance.
- The registry never relies on JavaScript object insertion order implicitly; `records.ts` constructs the canonical object explicitly.

### 8.2 Target record

Target signing bytes are:

```text
alt.target.v1\x00<networkId>\x00<compact-json>
```

The exact key order is:

```text
schema, networkId, domain, ownershipGeneration, sequence, mode,
target, publisherIdentity, signalingEndpoints, issuedAt, expiresAt
```

The order above follows Go struct order, but `target`, `publisherIdentity`, and `signalingEndpoints` use Go `omitempty` semantics and are absent—not serialized as empty values—when unused. Ed25519 public keys and signatures use standard padded Base64 exactly as `dotALT/pkg/records` does; challenge nonces and opaque web tokens may use Base64url. Target records start at sequence `1`, are signed by the owner key rather than the registry authority key, and initially use a one-year validity window. Cross-language golden fixtures generated by Go and verified by TypeScript—and vice versa—are a release requirement.

## 9. Registry signing keys

There are two distinct key types:

1. **Registry authority Ed25519 key** — signs ownership records. This is the actual `.alt` ownership trust root.
2. **IPNS publishing key** — updates the pointer to the latest manifest. This controls freshness and availability, but cannot create a valid ownership record without the registry authority key.

Do not reuse one key for both purposes.

### 9.1 MVP storage decision

For the first personal deployment:

- Generate the registry authority key outside both repositories on a trusted local machine.
- Store the production private key in a Vercel **Production Secret** named `ALT_REGISTRY_PRIVATE_KEY`.
- Do not expose it through any `NEXT_PUBLIC_*` variable.
- Do not add it to Preview or Development environments.
- Restrict Vercel project membership to the owner.
- Store one offline encrypted backup in a password manager or encrypted removable storage.
- Put only the public key and key ID in the public `dotALT` network profile.
- Keep the IPNS private key separate, preferably in the IPFS/pinning publisher rather than the Next.js application.

This is acceptable for the MVP, but it means a full compromise of the production Next.js runtime could use the online key to issue ownership records. Before adding other administrators or meaningful scale, move signing to a managed Ed25519 signer such as Google Cloud KMS and give the application only permission to request signatures. Google Cloud KMS supports Ed25519 asymmetric signing.

### 9.2 Key generation

Use the `dotALT` bootstrap/key generator or a small audited script that uses the operating system CSPRNG. Do not invent key bytes manually.

Recommended flow:

```bash
umask 077
mkdir -p "$HOME/.alt-production-keys"
chmod 700 "$HOME/.alt-production-keys"

# The final command should use the audited dotALT generator.
go run ./cmd/alt-bootstrap-gen \
  --keys-dir "$HOME/.alt-production-keys" \
  --out-dir /tmp/alt-public-bootstrap \
  --network-id alt-main-v1 \
  --tld alt \
  --domain register.alt \
  --key-id registry-2026 \
  --target https://alt.goker.dev
```

Before using this for production, change the generator branding and defaults so it does not mark the production key as a demo key. Inspect the generated public profile and record before publishing.

Load the private key into Vercel interactively as a Secret. Do not pipe it through shell history and do not commit `.env` files.

Required variables:

```text
ALT_REGISTRY_KEY_ID=registry-2026
ALT_REGISTRY_PUBLIC_KEY=ed25519:...
ALT_REGISTRY_PRIVATE_KEY=<secret>
ALT_NETWORK_ID=alt-main-v1
ALT_TLD=alt
```

### 9.3 Rotation and emergency response

- The public network profile supports multiple registry public keys.
- Add the new public key to the profile before using its private key.
- Publish clients/profile updates containing both old and new keys.
- Start signing new records with the new key ID.
- Remove the old public key only after the supported client population has updated.
- If the private key is compromised, stop registration immediately, remove the compromised key from the official profile, publish a new profile/release, generate a new authority key, and reissue ownership records.

Never silently replace the trust key at the same key ID.

## 10. Why `.alt` cannot be captured on IPFS

IPFS has no authority over the `.alt` namespace. Anyone can upload files that contain names such as `goker.alt`, but official clients accept a record only when all of the following match:

- official `networkId` (`alt-main-v1`);
- `.alt` TLD policy;
- authority signature from a public key pinned in the official network profile;
- canonical domain and ownership generation;
- valid record time window;
- monotonic generation/sequence rules;
- expected manifest CID or authenticated IPNS root.

An attacker publishing another `.alt` manifest or IPNS name does not capture `.alt`; official clients do not trust arbitrary IPFS content or arbitrary IPNS names.

The real capture risks are:

- registry authority private-key compromise;
- malicious modification of the official network profile distributed with clients;
- IPNS key compromise combined with access to already valid signed records;
- database allocation races or reserved-name mistakes.

Controls:

- unique MongoDB indexes for names and account limits;
- `register.alt` and system names seeded before public registration;
- registry public key pinned in `dotALT`;
- separate authority and IPNS keys;
- content-address verification plus Ed25519 verification in clients;
- monotonic record versions;
- signed/reviewed profile updates;
- no private keys in Git, MongoDB, IPFS, logs, or browser bundles.

## 11. Manifest publication

There are two distribution layers:

1. **Bootstrap manifest:** a fixed CID bundled in the official `dotALT` profile. It contains the complete ownership and target pair for `register.alt`, pointing to `https://alt.goker.dev`.
2. **Registry manifest:** the changing set of user domains plus the same immutable `register.alt` entry. Its latest CID is published through the official IPNS root from the first public registration.

Publishing a new fixed CID in the client profile after every registration is not viable and must not be used for user domains.

Registry publication:

1. Load the immutable signed `register.alt` entry and query all `publication_pending` or active user domains that have both valid ownership and target records.
2. Build a deterministic manifest sorted by canonical domain.
3. Include only signed public records.
4. Serialize deterministically.
5. Package the single raw manifest block into a CAR whose root is the already computed raw CIDv1, import it through Filebase `/api/v0/dag/import`, and require Filebase's imported root to equal that CID.
6. Verify the returned CID locally.
7. Store the latest CID and publication timestamp in MongoDB.
8. Update the Filebase-managed `alt-registry` IPNS key through `/api/v0/name/publish` and require the response IPNS name to match the public `ipnsRoot` pinned in the `dotALT` profile.
9. Set included domains to `publicationStatus: "published"`, store the CID and timestamp, and change only first-publication domains from `publication_pending` to `active`; domains that were already `active` remain `active`.

Concurrent registrations should enqueue/retry manifest publication rather than publishing competing snapshots blindly. A MongoDB publication lock with an expiry is sufficient for the initial single deployment. A registration is not advertised as active until its record is reachable through the current IPNS root.

Manifest compatibility requirements:

- Output must be a CIDv1 raw block using multicodec `0x55`, SHA-256 multihash `0x12/0x20`, and lowercase base32 beginning with `b`.
- Do not publish a UnixFS/DAG-PB wrapper. With Kubo, use `ipfs block put --cid-codec raw` or an exactly equivalent API.
- The current `dotALT` resolver rejects manifests larger than 1 MiB. Add sharding before the flat manifest approaches that limit.
- Sort record keys and construct nested records canonically.
- `generatedAt` may reflect the publication run, but rebuilding an unchanged logical snapshot should avoid publication unless the bytes intentionally change.

Cross-repository blocker: `dotALT` currently parses `ipnsRoot` but only implements fixed-CID `GatewaySource`. Before the first public user-domain publication, `dotALT` must implement and wire an IPNS/DNSLink or equivalent verifiable IPNS record source into `buildRecordSource`. Until that lands, only the bundled `register.alt` bootstrap record is resolvable.

## 12. Pages

### Public homepage

- short explanation of `.alt`;
- GitHub login button;
- link to install `dotALT`;
- clear statement: one domain per GitHub account during the initial phase.

### Dashboard

- GitHub identity;
- domain search field;
- availability result;
- register confirmation dialog;
- registered domain and status;
- owner-key setup instructions when status is `pending_key`;
- current ownership-record generation;
- IPFS publication state and CID.

No admin dashboard is needed initially. Use a protected script for reserved-name seeding and emergency suspension.

## 13. Security requirements

- Validate OAuth `state` and use PKCE where supported.
- Use the immutable GitHub numeric ID.
- Never trust account or domain information supplied by the CLI without verifying its bearer token.
- Rate-limit OAuth callbacks, availability checks, CLI exchanges, and registration attempts.
- Back rate limits with MongoDB TTL window documents for the MVP; do not rely on in-memory counters in Vercel functions.
- Enforce `REGISTRATION_ENABLED` in the registration mutation before any allocation or signing work; availability checks may remain readable while registration is disabled.
- Use CSRF protection for cookie-authenticated mutations.
- Validate `Origin` for browser POST requests.
- Do not log OAuth tokens, ALT session tokens, cookies, private keys, or full authorization headers.
- Redact MongoDB connection strings from errors.
- Use constant-time comparisons for token hashes where applicable.
- Validate every environment variable at startup.
- Run signing and database code only in the Node.js runtime, not Edge middleware.
- Set CSP, HSTS, `X-Content-Type-Options`, and a strict referrer policy.
- Put static security headers in `next.config.ts`; use Next.js 16 `proxy.ts` only if request-time proxy logic is actually required.

## 14. Environment variables

```text
APP_URL=https://alt.goker.dev
MONGODB_URI=<secret>
MONGODB_DB=alt_registry

GITHUB_CLIENT_ID=<config>
GITHUB_CLIENT_SECRET=<secret>

SESSION_SECRET=<secret, at least 32 random bytes>
CLI_TOKEN_PEPPER=<secret, at least 32 random bytes>
REGISTRATION_ENABLED=true

ALT_NETWORK_ID=alt-main-v1
ALT_TLD=alt
ALT_REGISTRY_KEY_ID=registry-2026
ALT_REGISTRY_PUBLIC_KEY=ed25519:...
ALT_REGISTRY_PRIVATE_KEY=<production secret>

IPFS_API_URL=https://rpc.filebase.io
IPFS_API_TOKEN=<bucket-scoped Filebase RPC bearer token>
IPNS_KEY_REFERENCE=alt-registry
```

Only non-sensitive values may appear in `.env.example`.

## 15. Implementation order

### Phase 1 — Working registration

1. Rename the existing package metadata from `alt-registery` to `alt-registry`, finalize the Next.js and shadcn/ui shell, and replace the generated README.
2. Connect MongoDB and create unique indexes.
3. Implement direct GitHub OAuth route handlers and `jose` session cookies.
4. Implement account/dashboard pages.
5. Implement domain normalization, reserved names, availability, partial unique indexes, and atomic `pending_key`/`pending_target` reservation.
6. Generate the production authority key and configure Vercel Production Secrets.
7. Generate and publish the fixed-CID `register.alt` bootstrap record.

### Phase 2 — CLI and distribution

1. Enable GitHub Device Flow.
2. Implement `/api/cli/session` exchange and ALT CLI bearer tokens.
3. Implement owner-key generation, challenge, proof, and binding.
4. Implement `alt login github`, `alt register`, and `alt account` against `https://alt.goker.dev`.
5. Issue ownership certificates only after owner-key proof.
6. Implement owner-signed target upload and verification for `alt publish`.
7. Implement the IPNS record source in `dotALT`.
8. Build raw-CID deterministic manifests containing `register.alt`, publish to IPFS, and update IPNS.
9. Verify end-to-end resolution in `dotALT`.

### Phase 3 — Hardening

1. Add rate limiting and audit events.
2. Add publication retry and status reporting.
3. Add key-rotation documentation and a registration kill switch.
4. Move registry signing to managed KMS before expanding administration or scale.
5. Harden IPNS publication, retry, and recovery after the initial working implementation.

## 16. MVP completion checklist

- [ ] `alt.goker.dev` serves the Next.js application.
- [ ] GitHub web login works.
- [ ] GitHub numeric ID is the unique account identity.
- [ ] MongoDB unique indexes enforce one domain per account and one owner per domain.
- [ ] Reserved names, including `register.alt`, cannot be registered.
- [ ] Web registration creates a `pending_key` reservation rather than a server-owned owner key.
- [ ] CLI proves possession of the locally generated owner key with a single-use challenge.
- [ ] An allocated domain remains `pending_target` and outside the manifest until `alt publish` submits a valid owner-signed target record.
- [ ] Owner private keys never enter the registry, MongoDB, Vercel, IPFS, or browser bundle.
- [ ] Ownership records match `dotALT` canonical signing test vectors.
- [ ] Production authority private key exists only in the production secret store and offline encrypted backup.
- [ ] No private key is present in Git, MongoDB, IPFS, logs, or client bundles.
- [ ] `alt login github` completes Device Flow and receives an ALT session token.
- [ ] `alt register goker.alt` calls `alt.goker.dev` and returns the signed ownership record.
- [ ] Manifest publication returns a verified CID.
- [ ] Manifest entries always contain both ownership and target records and include `register.alt`.
- [ ] Manifest bytes use CIDv1 raw + SHA-256 and remain below the current 1 MiB client limit.
- [ ] The official IPNS root resolves to the latest verified user-domain manifest.
- [ ] `dotALT` has a working IPNS source wired into runtime resolution.
- [ ] `register.alt` resolves through the official profile.
- [ ] Duplicate domain and second-domain attempts fail atomically.
- [ ] Registration can be disabled immediately with a server-side kill switch.

## 17. Official references

- [Next.js releases](https://nextjs.org/blog)
- [Next.js support policy](https://nextjs.org/support-policy)
- [shadcn/ui Next.js installation](https://ui.shadcn.com/docs/installation/next)
- [GitHub OAuth Device Flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow)
- [GitHub authenticated user endpoint](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
- [MongoDB deployment options](https://www.mongodb.com/docs/deployment/)
- [Vercel Secrets](https://vercel.com/docs/environment-variables/sensitive-environment-variables)
- [Google Cloud KMS signing algorithms](https://cloud.google.com/kms/docs/algorithms)

