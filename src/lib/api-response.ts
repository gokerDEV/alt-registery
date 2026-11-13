import { NextResponse } from "next/server";
import { type AccountDoc, type DomainDoc, fromMongoLong } from "@/lib/mongodb";

export function jsonError(
  status: number,
  code: string,
  message: string,
  headers?: HeadersInit,
) {
  return NextResponse.json(
    {
      error: {
        code,
        message,
      },
    },
    {
      status,
      headers: {
        "Cache-Control": "no-store",
        ...headers,
      },
    },
  );
}

export function jsonOk<T>(data: T, status = 200, headers?: HeadersInit) {
  return NextResponse.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

export function serializePublicAccount(account: AccountDoc) {
  return {
    id: `gh:${account.githubId.toString()}`,
    githubId: account.githubId.toString(),
    githubLogin: account.githubLogin,
    avatarUrl: account.avatarUrl ?? null,
    ownerPublicKey: account.ownerPublicKey ?? null,
    createdAt: account.createdAt.toISOString(),
    updatedAt: account.updatedAt.toISOString(),
  };
}

export function serializePublicDomain(domain: DomainDoc) {
  return {
    name: domain.name,
    label: domain.label,
    kind: domain.kind,
    status: domain.status,
    generation: Number(fromMongoLong(domain.generation)),
    sequence: Number(fromMongoLong(domain.sequence)),
    ownerPublicKey: domain.ownerPublicKey ?? null,
    ownershipRecord: domain.ownershipRecord ?? null,
    targetRecord: domain.targetRecord ?? null,
    publicationStatus: domain.publicationStatus,
    manifestCid: domain.manifestCid ?? null,
    publishedAt: domain.publishedAt ? domain.publishedAt.toISOString() : null,
    createdAt: domain.createdAt.toISOString(),
    updatedAt: domain.updatedAt.toISOString(),
  };
}
