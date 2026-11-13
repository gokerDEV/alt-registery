# alt-registry (`register.alt`)

Official domain registry for the **`.alt`** network (`alt-main-v1`).

- **Public Internet origin:** `https://alt.goker.dev`
- **ALT bootstrap origin:** `https://register.alt`
- **Network ID / TLD:** `alt-main-v1` / `.alt`
- **Authority Public Key (`registry-2026`):** `ed25519:dYbt6Mh+nnb1wYq4NfDY7FeMbQ84QnpOxRnibXy7/0w=`
- **Bootstrap Manifest CID (`register.alt`):** `bafkreidw3acn7s3vy6xmuyn2fui4sp3fxjfpnzm6m5mm6f76kueq3janra`
- **Official IPNS Root:** `k51qzi5uqu5dggi62jp2mtv4rx8jahmzt8qh4o2bpnnxb4podywa89lwl8r71b`
- **Protocol & client repository:** [`dotALT`](https://github.com/gokerdev/dotALT)

## Overview

`alt-registry` allocates `.alt` names to authenticated GitHub accounts, binds locally generated Ed25519 owner keys via single-use challenges, signs `alt.ownership.v1` certificates, ingests owner-signed `alt.target.v1` routing records, and builds verifiable CIDv1 raw manifests (`0x55` + `sha2-256`) for IPFS/IPNS distribution.

Key security invariants:

- **Immutable identity:** Accounts are keyed strictly by GitHub's immutable numeric user ID (`Long`), never by mutable login handle.
- **Non-custodial owner keys:** Owner Ed25519 private keys are generated on the user's device by the `alt` CLI and never enter this repository, MongoDB, Vercel, IPFS, or browser bundles.
- **Database-enforced quota:** MongoDB unique and partial-unique indexes enforce global domain uniqueness and the initial one-domain-per-account limit (`kind: "user"`), while allowing reserved `kind: "system"` records such as `register.alt`.
- **Single authenticated web origin:** Browser authentication and mutations run strictly on `APP_URL` (`https://alt.goker.dev` in production). Requests arriving through `dotALT` with `X-Alt-Domain: register.alt` receive a `307` redirect to `APP_URL`.

## Tech Stack

- **Framework:** Next.js 16 (App Router, Cache Components, Node.js Route Handlers & `src/proxy.ts`)
- **UI:** React 19, Tailwind CSS v4, `shadcn` (`base-luma` / `@base-ui/react`)
- **Auth:** Direct GitHub OAuth (PKCE + `state`) with `jose` `A256GCM` encrypted HTTP-only cookies for web; GitHub Device Flow + HMAC-SHA256 bearer tokens for CLI
- **Database:** MongoDB Node.js driver (`mongodb`) with transactions and TTL rate-limit buckets
- **Signing:** Node.js `node:crypto` Ed25519 matching `dotALT/pkg/records` canonical byte layout
- **Tooling:** Bun & Biome

## Local Development

1. Install dependencies:

   ```bash
   bun install
   ```

2. Copy `.env.example` to `.env.local` and populate local credentials (never commit `.env*` files):

   ```bash
   cp .env.example .env.local
   ```

   Generate random secrets for `SESSION_SECRET` and `CLI_TOKEN_PEPPER` (at least 32 bytes):

   ```bash
   openssl rand -base64 36
   ```

3. Seed reserved system names (`register.alt`, `www.alt`, `api.alt`, etc.) in MongoDB:

   ```bash
   bun run seed:reserved
   ```

4. Start the development server:

   ```bash
   bun dev
   ```

## Scripts

- `bun dev` — Start Next.js 16 development server
- `bun run build` — Production build check
- `bun run lint` — Run Biome linter & formatter check
- `bun run typecheck` — Run TypeScript compiler check
- `bun test` — Run unit and cross-language protocol vector tests
- `bun run key:generate -- --keys-dir "$HOME/.alt-dev-keys" --out-dir /tmp/alt-bootstrap` — Generate external `0600` Ed25519 keys + signed `register.alt` bootstrap manifest & profile
- `bun run seed:reserved` — Seed reserved system names (and optional `--bootstrap-manifest`) into MongoDB
- `bun run manifest:rebuild` — Build and verify a deterministic CIDv1 raw manifest from MongoDB (`--publish` to import CARv1 to Filebase IPFS and update IPNS)

## CLI Workflow (`dotALT`)

1. Authenticate via GitHub Device Flow and receive a 30-day CLI bearer session:

   ```bash
   alt login github --client-id <GITHUB_CLIENT_ID>
   ```

2. Generate a local `0600` Ed25519 owner keypair, complete the single-use key challenge, and claim a `.alt` domain:

   ```bash
   alt register yourname.alt
   ```

3. Sign an `alt.target.v1` record locally and publish the updated raw CIDv1 manifest to IPFS/IPNS:

   ```bash
   alt publish yourname.alt --target https://your-origin.example
   ```

## License

Apache-2.0 — see [LICENSE](LICENSE).
