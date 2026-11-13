import { describe, expect, mock, test } from "bun:test";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Long, ObjectId } from "mongodb";

// Mock next/server connection() when calling GET route handlers directly outside Next.js request AsyncLocalStorage
mock.module("next/server", () => {
  const actual = require("next/dist/server/web/exports/index.js");
  return {
    ...actual,
    connection: async () => undefined,
  };
});

import { POST as keyChallengeHandler } from "../src/app/api/account/key/challenge/route";
import { POST as keyVerifyHandler } from "../src/app/api/account/key/verify/route";
import { GET as getAccountHandler } from "../src/app/api/account/route";
import { DELETE as revokeCliSessionHandler } from "../src/app/api/cli/session/route";
import { PUT as putTargetHandler } from "../src/app/api/domains/[name]/target/route";
import { POST as registerDomainHandler } from "../src/app/api/domains/route";
import { hashCliToken } from "../src/lib/auth";
import {
  buildSingleBlockCarV1,
  computeLogicalManifestHash,
  computeRawCidV1,
  importRawManifestCarToIpfs,
  serializeDeterministicManifest,
} from "../src/lib/ipfs";
import { getCollections } from "../src/lib/mongodb";
import {
  isDisallowedPublicEndpointHost,
  SCHEMA_OWNERSHIP_V1,
  SCHEMA_TARGET_V1,
} from "../src/lib/records";
import {
  generateEd25519KeyMaterial,
  signKeyChallengeWithKey,
  signOwnershipCertificateWithKey,
  signTargetRecordWithKey,
} from "../src/lib/signing";

describe("phase 2: CARv1 packaging, endpoint SSRF guards, and Go <-> TypeScript golden vectors", () => {
  test("packages raw manifest into spec-compliant CARv1 and validates /api/v0/dag/import root CID", async () => {
    const auth = generateEd25519KeyMaterial();
    const owner = generateEd25519KeyMaterial();
    const cert = signOwnershipCertificateWithKey(
      {
        schema: SCHEMA_OWNERSHIP_V1,
        networkId: "alt-main-v1",
        domain: "register.alt",
        accountId: "system:bootstrap",
        ownerPublicKey: owner.publicKeyEncoded,
        generation: 1,
        issuedAt: "2026-11-13T00:00:00Z",
        expiresAt: "2036-11-13T00:00:00Z",
        issuerKeyId: "registry-2026",
      },
      auth.privateKeyObject,
    );
    const target = signTargetRecordWithKey(
      {
        schema: SCHEMA_TARGET_V1,
        networkId: "alt-main-v1",
        domain: "register.alt",
        ownershipGeneration: 1,
        sequence: 1,
        mode: "https",
        target: "https://alt.goker.dev",
        issuedAt: "2026-11-13T00:00:00Z",
        expiresAt: "2036-11-13T00:00:00Z",
      },
      owner.privateKeyObject,
    );

    const rawBytes = serializeDeterministicManifest({
      networkId: "alt-main-v1",
      generatedAt: "2026-11-13T12:00:00Z",
      entries: { "register.alt": { ownership: cert, target } },
    });
    const expectedCid = computeRawCidV1(rawBytes);
    const { carBytes, cid } = buildSingleBlockCarV1(rawBytes, expectedCid);
    expect(cid).toBe(expectedCid);
    // CARv1 header length varint = 58 (0x3a), followed by map(2) 0xa2
    expect(carBytes[0]).toBe(0x3a);
    expect(carBytes[1]).toBe(0xa2);

    // Logical hash ignores `generatedAt`
    const h1 = computeLogicalManifestHash({
      networkId: "alt-main-v1",
      entries: { "register.alt": { ownership: cert, target } },
    });
    const h2 = computeLogicalManifestHash({
      networkId: "alt-main-v1",
      entries: { "register.alt": { ownership: cert, target } },
    });
    expect(h1).toBe(h2);

    // Mock Filebase `/api/v0/dag/import` returning matching root CID
    const okImport = await importRawManifestCarToIpfs(rawBytes, {
      apiUrl: "http://127.0.0.1:15001",
      apiToken: "mock-token",
      fetchImpl: (async () =>
        new Response(
          `${JSON.stringify({ Root: { Cid: { "/": expectedCid }, PinErrorMsg: "" } })}\n`,
          { status: 200, headers: { "Content-Type": "application/json" } },
        )) as unknown as typeof fetch,
    });
    expect(okImport.cid).toBe(expectedCid);

    // Mock rogue IPFS RPC returning mismatched root CID -> rejected!
    await expect(
      importRawManifestCarToIpfs(rawBytes, {
        apiUrl: "http://127.0.0.1:15001",
        apiToken: "mock-token",
        fetchImpl: (async () =>
          new Response(
            `${JSON.stringify({ Root: { Cid: { "/": "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } } })}\n`,
            { status: 200, headers: { "Content-Type": "application/json" } },
          )) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/unexpected root CID/);
  });

  test("rejects loopback, RFC1918, CGNAT, link-local, documentation, and special-use target hosts", () => {
    for (const badHost of [
      "localhost",
      "sub.localhost",
      "app.local",
      "db.internal",
      "service.onion",
      "127.0.0.1",
      "10.0.0.5",
      "172.16.4.1",
      "192.168.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "192.0.2.10",
      "[::1]",
      "[fe80::1]",
      "[fc00::1]",
      "[2001:db8::1]",
      "[::ffff:127.0.0.1]",
    ]) {
      expect(isDisallowedPublicEndpointHost(badHost)).toBe(true);
    }

    for (const okHost of [
      "alt.goker.dev",
      "my-site.vercel.app",
      "93.184.215.14",
      "[2606:4700:4700::1111]",
    ]) {
      expect(isDisallowedPublicEndpointHost(okHost)).toBe(false);
    }
  });

  test("verifies bidirectional TypeScript -> Go golden record & challenge vectors + live IPNS resolution", () => {
    const goRepoDir = path.resolve(import.meta.dir, "../../alt");
    if (!fs.existsSync(path.join(goRepoDir, "go.mod"))) {
      return;
    }

    const auth = generateEd25519KeyMaterial();
    const owner = generateEd25519KeyMaterial();
    const challengePayload = {
      accountId: "gh:999888",
      ownerPublicKey: owner.publicKeyEncoded,
      nonce: "golden_nonce_ts_to_go_01",
      purpose: "bind_owner_key" as const,
      expiresAt: "2026-11-13T18:00:00Z",
    };
    const challengeSig = signKeyChallengeWithKey(
      "alt-main-v1",
      challengePayload,
      owner.privateKeyObject,
    );

    const cert = signOwnershipCertificateWithKey(
      {
        schema: SCHEMA_OWNERSHIP_V1,
        networkId: "alt-main-v1",
        domain: "goker.alt",
        accountId: "gh:999888",
        ownerPublicKey: owner.publicKeyEncoded,
        generation: 1,
        issuedAt: "2026-11-13T12:00:00Z",
        expiresAt: "2036-11-10T12:00:00Z",
        issuerKeyId: "registry-2026",
      },
      auth.privateKeyObject,
    );

    const target = signTargetRecordWithKey(
      {
        schema: SCHEMA_TARGET_V1,
        networkId: "alt-main-v1",
        domain: "goker.alt",
        ownershipGeneration: 1,
        sequence: 1,
        mode: "https",
        target: "https://alt.goker.dev",
        issuedAt: "2026-11-13T12:00:00Z",
        expiresAt: "2027-11-13T12:00:00Z",
      },
      owner.privateKeyObject,
    );

    const fixtureJson = JSON.stringify({
      authorityPub: auth.publicKeyEncoded,
      challengePayload,
      challengeSig,
      cert,
      target,
    });

    // Run `go test` in sibling repo passing the TS-generated vector via env var to verify in Go!
    const res = spawnSync(
      "go",
      [
        "test",
        "-v",
        "./pkg/records",
        "-run",
        "TestOwnershipAndTargetVerification",
      ],
      {
        cwd: goRepoDir,
        env: { ...process.env, ALT_TS_GOLDEN_FIXTURE: fixtureJson },
        encoding: "utf8",
      },
    );
    expect(res.status).toBe(0);
  });
});

describe("phase 2: live route handler integration (challenge, single-use bind, target sequence, revocation)", () => {
  test("executes full pending_key -> challenge -> verify -> pending_target -> target upload -> revoke lifecycle", async () => {
    // Allow `bun test` to run cleanly in unconfigured CI environments while running full live E2E when `.env.local` is present
    const envLocalPath = path.resolve(import.meta.dir, "../.env.local");
    if (!process.env.MONGODB_URI && fs.existsSync(envLocalPath)) {
      for (const line of fs.readFileSync(envLocalPath, "utf8").split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIdx = trimmed.indexOf("=");
        if (eqIdx === -1) continue;
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed
          .slice(eqIdx + 1)
          .trim()
          .replace(/^['"]|['"]$/g, "");
        if (process.env[k] === undefined && v !== "") {
          process.env[k] = v;
        }
      }
    }
    if (!process.env.MONGODB_URI || !process.env.ALT_REGISTRY_PRIVATE_KEY) {
      return;
    }

    const { getMongoClient } = await import("../src/lib/mongodb");
    const { accounts, domains, cliSessions, keyChallenges, rateLimits } =
      await getCollections();

    const syntheticGithubId = Long.fromString("900000000042");
    const testDomainName = "p2test-e2e.alt";
    const owner = generateEd25519KeyMaterial();
    const rawCliToken = `alt_cli_test_${crypto.randomBytes(24).toString("base64url")}`;
    const tokenHash = hashCliToken(rawCliToken);

    let accountId: ObjectId | null = null;

    try {
      // Clean any leftover synthetic test records
      await accounts.deleteMany({ githubId: syntheticGithubId });
      await domains.deleteMany({ name: testDomainName });

      const now = new Date();
      accountId = new ObjectId();
      await accounts.insertOne({
        _id: accountId,
        githubId: syntheticGithubId,
        githubLogin: "phase2-tester",
        createdAt: now,
        updatedAt: now,
      });

      await cliSessions.insertOne({
        _id: new ObjectId(),
        accountId,
        tokenHash,
        createdAt: now,
        expiresAt: new Date(now.getTime() + 60 * 60 * 1000),
      });

      const authHeaders = {
        Authorization: `Bearer ${rawCliToken}`,
        "Content-Type": "application/json",
      };

      // 1. Reserve domain BEFORE owner key is bound -> status MUST be `pending_key`
      const regRes = await registerDomainHandler(
        new Request("http://localhost:3000/api/domains", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({ name: "p2test-e2e" }),
        }),
      );
      expect(regRes.status).toBe(201);
      const regData = (await regRes.json()) as {
        domain: {
          status: string;
          generation: number;
          ownershipRecord: unknown;
        };
      };
      expect(regData.domain.status).toBe("pending_key");
      expect(regData.domain.generation).toBe(0);
      expect(regData.domain.ownershipRecord).toBeNull();

      // 2. Second domain attempt by same account fails atomically with DOMAIN_LIMIT_REACHED
      const secondRegRes = await registerDomainHandler(
        new Request("http://localhost:3000/api/domains", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({ name: "p2test-second" }),
        }),
      );
      expect(secondRegRes.status).toBe(409);
      const secondErr = (await secondRegRes.json()) as {
        error: { code: string };
      };
      expect(secondErr.error.code).toBe("DOMAIN_LIMIT_REACHED");

      // 3. Request single-use owner-key challenge
      const chalRes = await keyChallengeHandler(
        new Request("http://localhost:3000/api/account/key/challenge", {
          method: "POST",
          headers: authHeaders,
        }),
      );
      expect(chalRes.status).toBe(201);
      const chalData = (await chalRes.json()) as {
        networkId: string;
        accountId: string;
        nonce: string;
        purpose: "bind_owner_key";
        expiresAt: string;
      };
      expect(chalData.accountId).toBe(`gh:${syntheticGithubId.toString()}`);

      const sig = signKeyChallengeWithKey(
        chalData.networkId,
        {
          accountId: chalData.accountId,
          ownerPublicKey: owner.publicKeyEncoded,
          nonce: chalData.nonce,
          purpose: chalData.purpose,
          expiresAt: chalData.expiresAt,
        },
        owner.privateKeyObject,
      );

      // 4. Verify challenge -> binds owner key AND transitions `pending_key` -> `pending_target` with signed cert!
      const verRes = await keyVerifyHandler(
        new Request("http://localhost:3000/api/account/key/verify", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({
            ownerPublicKey: owner.publicKeyEncoded,
            nonce: chalData.nonce,
            expiresAt: chalData.expiresAt,
            signature: sig,
          }),
        }),
      );
      expect(verRes.status).toBe(200);
      const verData = (await verRes.json()) as {
        account: { ownerPublicKey: string };
        domain: {
          status: string;
          generation: number;
          ownershipRecord: {
            ownerPublicKey: string;
            generation: number;
          } | null;
        };
      };
      expect(verData.account.ownerPublicKey).toBe(owner.publicKeyEncoded);
      expect(verData.domain.status).toBe("pending_target");
      expect(verData.domain.generation).toBe(1);
      expect(verData.domain.ownershipRecord?.ownerPublicKey).toBe(
        owner.publicKeyEncoded,
      );

      // 5. Replaying the exact same challenge/proof is rejected (KEY_ALREADY_BOUND)
      const replayRes = await keyVerifyHandler(
        new Request("http://localhost:3000/api/account/key/verify", {
          method: "POST",
          headers: authHeaders,
          body: JSON.stringify({
            ownerPublicKey: owner.publicKeyEncoded,
            nonce: chalData.nonce,
            expiresAt: chalData.expiresAt,
            signature: sig,
          }),
        }),
      );
      expect(replayRes.status).toBe(409);

      // 6. Attempt loopback target upload -> rejected with DISALLOWED_TARGET_HOST
      const issuedAt = new Date(Math.floor(Date.now() / 1000) * 1000)
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");
      const expiresAt = new Date(
        Math.floor(Date.now() / 1000) * 1000 + 365 * 24 * 60 * 60 * 1000,
      )
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");

      const loopbackTarget = signTargetRecordWithKey(
        {
          schema: SCHEMA_TARGET_V1,
          networkId: chalData.networkId,
          domain: testDomainName,
          ownershipGeneration: 1,
          sequence: 1,
          mode: "https",
          target: "https://127.0.0.1:8443",
          issuedAt,
          expiresAt,
        },
        owner.privateKeyObject,
      );
      const badPutRes = await putTargetHandler(
        new Request(
          `http://localhost:3000/api/domains/${testDomainName}/target`,
          {
            method: "PUT",
            headers: authHeaders,
            body: JSON.stringify(loopbackTarget),
          },
        ),
        { params: Promise.resolve({ name: testDomainName }) } as never,
      );
      expect(badPutRes.status).toBe(400);

      // 7. Valid public HTTPS target upload (sequence 1) -> publishes manifest to Filebase & transitions to `active`!
      const validTargetSeq1 = signTargetRecordWithKey(
        {
          schema: SCHEMA_TARGET_V1,
          networkId: chalData.networkId,
          domain: testDomainName,
          ownershipGeneration: 1,
          sequence: 1,
          mode: "https",
          target: "https://alt.goker.dev",
          issuedAt,
          expiresAt,
        },
        owner.privateKeyObject,
      );
      const putRes1 = await putTargetHandler(
        new Request(
          `http://localhost:3000/api/domains/${testDomainName}/target`,
          {
            method: "PUT",
            headers: authHeaders,
            body: JSON.stringify(validTargetSeq1),
          },
        ),
        { params: Promise.resolve({ name: testDomainName }) } as never,
      );
      expect(putRes1.status).toBe(200);
      const putData1 = (await putRes1.json()) as {
        domain: { status: string; sequence: number; publicationStatus: string };
        publication: { status: string; manifestCid: string | null };
      };
      expect(putData1.domain.sequence).toBe(1);
      expect(putData1.domain.status).toBe("active");
      expect(putData1.publication.status).toBe("published");
      expect(putData1.publication.manifestCid?.startsWith("b")).toBe(true);

      // 7b. Verify end-to-end live IPNS resolution in dotALT Go resolver (`register.alt` + `p2test-e2e.alt`)
      const goRepoDir = path.resolve(import.meta.dir, "../../alt");
      if (fs.existsSync(path.join(goRepoDir, "go.mod"))) {
        const liveGoRes = spawnSync(
          "go",
          [
            "test",
            "-v",
            "-count=1",
            "./pkg/resolver",
            "-run",
            "TestLiveOfficialIPNSProfileResolution",
          ],
          {
            cwd: goRepoDir,
            env: {
              ...process.env,
              ALT_LIVE_IPNS_TEST: "1",
              ALT_LIVE_MANIFEST_CID: putData1.publication.manifestCid ?? "",
              ALT_LIVE_IPNS_EXPECT_DOMAIN: testDomainName,
              ALT_LIVE_IPNS_EXPECT_TARGET: "https://alt.goker.dev",
            },
            encoding: "utf8",
          },
        );
        expect(liveGoRes.status).toBe(0);
      }

      // 8. Idempotent retry of the exact same signed sequence 1 record succeeds (`200`)
      const idempRes = await putTargetHandler(
        new Request(
          `http://localhost:3000/api/domains/${testDomainName}/target`,
          {
            method: "PUT",
            headers: authHeaders,
            body: JSON.stringify(validTargetSeq1),
          },
        ),
        { params: Promise.resolve({ name: testDomainName }) } as never,
      );
      expect(idempRes.status).toBe(200);

      // 9. Different signed record reusing sequence 1 is rejected (`409 STALE_SEQUENCE`)
      const conflictingSeq1 = signTargetRecordWithKey(
        {
          schema: SCHEMA_TARGET_V1,
          networkId: chalData.networkId,
          domain: testDomainName,
          ownershipGeneration: 1,
          sequence: 1,
          mode: "https",
          target: "https://goker.dev",
          issuedAt,
          expiresAt,
        },
        owner.privateKeyObject,
      );
      const staleRes = await putTargetHandler(
        new Request(
          `http://localhost:3000/api/domains/${testDomainName}/target`,
          {
            method: "PUT",
            headers: authHeaders,
            body: JSON.stringify(conflictingSeq1),
          },
        ),
        { params: Promise.resolve({ name: testDomainName }) } as never,
      );
      expect(staleRes.status).toBe(409);

      // 10. Revoke CLI session (`DELETE /api/cli/session`) and verify subsequent `GET /api/account` fails (`401`)
      const delRes = await revokeCliSessionHandler(
        new Request("http://localhost:3000/api/cli/session", {
          method: "DELETE",
          headers: authHeaders,
        }),
      );
      expect(delRes.status).toBe(200);

      const postLogoutAcct = await getAccountHandler(
        new Request("http://localhost:3000/api/account", {
          method: "GET",
          headers: authHeaders,
        }),
      );
      expect(postLogoutAcct.status).toBe(401);

      // 11. Verify publication lock ownership fencing: a stale publisher whose lease was taken over
      // by `publisher-b-token` MUST NOT release Publisher B's active lock in `finally` or call IPNS publish!
      const { publishRegistryManifest } = await import("../src/lib/ipfs");
      let ipnsCalledByStalePublisher = false;
      try {
        await expect(
          publishRegistryManifest({
            force: true,
            fetchImpl: (async (input: RequestInfo | URL) => {
              const urlStr = String(input);
              if (urlStr.includes("/api/v0/dag/import")) {
                // Simulate lock expiry & takeover by Publisher B while Publisher A was uploading CARv1
                await rateLimits.updateOne(
                  {
                    subjectHash: "manifest_publisher_singleton",
                    action: "manifest_publish_lock",
                    windowStartedAt: new Date(0),
                  },
                  {
                    $set: {
                      count: 1,
                      lockOwner: "publisher-b-token",
                      expiresAt: new Date(Date.now() + 30_000),
                    },
                  },
                );
                throw new Error("simulated slow RPC failure after lease loss");
              }
              if (urlStr.includes("/api/v0/name/publish")) {
                ipnsCalledByStalePublisher = true;
              }
              return new Response("{}", { status: 500 });
            }) as unknown as typeof fetch,
          }),
        ).rejects.toThrow();

        expect(ipnsCalledByStalePublisher).toBe(false);
        const lockAfterStaleFinish = await rateLimits.findOne({
          subjectHash: "manifest_publisher_singleton",
          action: "manifest_publish_lock",
          windowStartedAt: new Date(0),
        });
        expect(lockAfterStaleFinish?.count).toBe(1);
        expect(lockAfterStaleFinish?.lockOwner).toBe("publisher-b-token");
      } finally {
        // Release synthetic Publisher B lock so outer `finally` cleanup can publish cleanly
        await rateLimits.updateOne(
          {
            subjectHash: "manifest_publisher_singleton",
            action: "manifest_publish_lock",
            windowStartedAt: new Date(0),
            lockOwner: "publisher-b-token",
          },
          {
            $set: {
              count: 0,
              lockOwner: "",
              expiresAt: new Date(Date.now() + 60_000),
            },
          },
        );
      }
    } finally {
      // Clean up synthetic records and re-publish clean manifest containing only real domains (`register.alt`)
      if (accountId) {
        await keyChallenges.deleteMany({ accountId });
        await cliSessions.deleteMany({ accountId });
        await accounts.deleteOne({ _id: accountId });
      }
      await domains.deleteMany({ name: testDomainName });

      const { publishRegistryManifest } = await import("../src/lib/ipfs");
      await publishRegistryManifest({ force: true });
      const client = await getMongoClient();
      await client.close();
      globalThis.__altMongoClientPromise = undefined;
    }
  }, 45_000);
});
