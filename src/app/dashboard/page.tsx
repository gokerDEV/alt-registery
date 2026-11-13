import {
  CheckCircle2Icon,
  ClockIcon,
  KeyRoundIcon,
  LogOutIcon,
  ShieldAlertIcon,
  TerminalIcon,
} from "lucide-react";
import { ObjectId } from "mongodb";
import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Suspense } from "react";
import { DomainSearchRegister } from "@/components/domain-search-register";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getBaseConfig } from "@/lib/env";
import {
  type DomainStatus,
  fromMongoLong,
  getCollections,
} from "@/lib/mongodb";
import { readWebSessionFromCookies } from "@/lib/session";

export const metadata: Metadata = {
  title: "Dashboard",
};

function renderStatusBadge(status: DomainStatus) {
  switch (status) {
    case "active":
      return (
        <Badge variant="default">
          <CheckCircle2Icon aria-hidden="true" data-icon="inline-start" />
          active
        </Badge>
      );
    case "publication_pending":
      return (
        <Badge variant="secondary">
          <ClockIcon aria-hidden="true" data-icon="inline-start" />
          publication_pending
        </Badge>
      );
    case "pending_target":
      return (
        <Badge variant="secondary">
          <TerminalIcon aria-hidden="true" data-icon="inline-start" />
          pending_target
        </Badge>
      );
    case "pending_key":
      return (
        <Badge variant="outline">
          <KeyRoundIcon aria-hidden="true" data-icon="inline-start" />
          pending_key
        </Badge>
      );
    case "suspended":
      return (
        <Badge variant="destructive">
          <ShieldAlertIcon aria-hidden="true" data-icon="inline-start" />
          suspended
        </Badge>
      );
  }
}

async function DashboardView() {
  const session = await readWebSessionFromCookies();
  if (!session || !ObjectId.isValid(session.accountId)) {
    redirect("/");
  }

  const base = getBaseConfig();
  const { accounts, domains } = await getCollections();
  const accountObjectId = new ObjectId(session.accountId);

  const [account, userDomain] = await Promise.all([
    accounts.findOne({ _id: accountObjectId }),
    domains.findOne({ accountId: accountObjectId, kind: "user" }),
  ]);

  if (!account || account.githubId.toString() !== session.githubId) {
    redirect("/");
  }

  const generation = userDomain
    ? Number(fromMongoLong(userDomain.generation))
    : 0;
  const sequence = userDomain ? Number(fromMongoLong(userDomain.sequence)) : 0;

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b border-border/60 bg-background/80 backdrop-blur-sm">
        <div className="mx-auto flex h-16 max-w-5xl items-center justify-between px-6">
          <div className="flex items-center gap-2.5">
            <Link
              href="/"
              className="font-heading text-lg font-semibold tracking-tight"
            >
              register<span className="text-muted-foreground">.alt</span>
            </Link>
            <Badge variant="secondary">{base.ALT_NETWORK_ID}</Badge>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-sm">
              {account.avatarUrl ? (
                <Image
                  src={account.avatarUrl}
                  alt=""
                  width={24}
                  height={24}
                  className="size-6 rounded-full ring-1 ring-border"
                />
              ) : null}
              <span className="font-medium">@{account.githubLogin}</span>
            </div>

            <form action="/api/auth/logout" method="POST">
              <input type="hidden" name="csrfToken" value={session.csrfToken} />
              <Button type="submit" variant="outline" size="sm">
                <LogOutIcon aria-hidden="true" data-icon="inline-start" />
                Sign out
              </Button>
            </form>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-6 py-10">
        {/* GitHub Identity & Key Card */}
        <Card size="sm">
          <CardHeader>
            <CardTitle>Account Identity</CardTitle>
            <CardDescription>
              Keyed by immutable numeric GitHub ID. Owner private keys never
              leave your local device.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">GitHub Account</TableHead>
                  <TableHead scope="col">Account ID</TableHead>
                  <TableHead scope="col">Bound Owner Key</TableHead>
                  <TableHead scope="col">Quota</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium">
                    @{account.githubLogin}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    gh:{account.githubId.toString()}
                  </TableCell>
                  <TableCell className="max-w-xs truncate font-mono text-xs">
                    {account.ownerPublicKey ? (
                      account.ownerPublicKey
                    ) : (
                      <span className="text-muted-foreground">
                        Not bound yet (use alt CLI)
                      </span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={userDomain ? "secondary" : "outline"}>
                      {userDomain ? "1 / 1 used" : "0 / 1 used"}
                    </Badge>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Registered Domain Status Card */}
        {userDomain ? (
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-col gap-1">
                  <CardTitle className="font-mono text-xl">
                    {userDomain.name}
                  </CardTitle>
                  <CardDescription>
                    Registered `.{base.ALT_TLD}` domain state, ownership
                    generation, and IPFS manifest publication status.
                  </CardDescription>
                </div>
                {renderStatusBadge(userDomain.status)}
              </div>
            </CardHeader>

            <CardContent className="flex flex-col gap-5">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Ownership Generation</TableHead>
                    <TableHead scope="col">Target Sequence</TableHead>
                    <TableHead scope="col">IPFS Publication</TableHead>
                    <TableHead scope="col">Manifest CID</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-mono">
                      {generation > 0
                        ? `gen ${generation}`
                        : "0 (awaiting key)"}
                    </TableCell>
                    <TableCell className="font-mono">
                      {sequence > 0 ? `seq ${sequence}` : "0 (awaiting target)"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {userDomain.publicationStatus}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-xs truncate font-mono text-xs">
                      {userDomain.manifestCid ?? "—"}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>

              {userDomain.status === "pending_key" ? (
                <Alert role="status">
                  <KeyRoundIcon aria-hidden="true" />
                  <AlertTitle>
                    Next step: Bind your local Ed25519 owner key
                  </AlertTitle>
                  <AlertDescription className="flex flex-col gap-3">
                    <p>
                      <strong>{userDomain.name}</strong> is reserved to your
                      GitHub account, but the registry never generates or holds
                      your owner private key. Run the{" "}
                      <code className="font-mono text-xs">alt</code> CLI locally
                      to generate your Ed25519 keypair, complete a single-use
                      challenge proof, and receive your signed ownership
                      certificate:
                    </p>
                    <pre className="overflow-x-auto rounded-2xl bg-muted/60 p-3 font-mono text-xs text-foreground ring-1 ring-border">
                      <code>{`alt login github
alt register ${userDomain.name}`}</code>
                    </pre>
                  </AlertDescription>
                </Alert>
              ) : null}

              {userDomain.status === "pending_target" ? (
                <Alert role="status">
                  <TerminalIcon aria-hidden="true" />
                  <AlertTitle>
                    Ownership certificate issued — publish a signed target
                  </AlertTitle>
                  <AlertDescription className="flex flex-col gap-3">
                    <p>
                      Your ownership certificate (generation {generation}) is
                      signed. Ownership-only domains stay outside the IPFS
                      manifest until you publish an owner-signed{" "}
                      <code className="font-mono text-xs">alt.target.v1</code>{" "}
                      record:
                    </p>
                    <pre className="overflow-x-auto rounded-2xl bg-muted/60 p-3 font-mono text-xs text-foreground ring-1 ring-border">
                      <code>{`alt publish ${userDomain.name} --target https://your-origin.example`}</code>
                    </pre>
                  </AlertDescription>
                </Alert>
              ) : null}

              {userDomain.publicationStatus === "failed" ? (
                <Alert variant="destructive">
                  <ShieldAlertIcon aria-hidden="true" />
                  <AlertTitle>
                    IPFS/IPNS manifest publication needs retry
                  </AlertTitle>
                  <AlertDescription className="flex flex-col gap-3">
                    <p>
                      Your signed target record (sequence {sequence}) is saved,
                      but the latest IPFS/IPNS publication attempt did not
                      complete. Re-run{" "}
                      <code className="font-mono text-xs">alt publish</code> to
                      retry manifest publication:
                    </p>
                    <pre className="overflow-x-auto rounded-2xl bg-muted/60 p-3 font-mono text-xs text-foreground ring-1 ring-border">
                      <code>{`alt publish ${userDomain.name} --target ${userDomain.targetRecord?.target ?? "https://your-origin.example"}`}</code>
                    </pre>
                  </AlertDescription>
                </Alert>
              ) : null}
            </CardContent>
          </Card>
        ) : null}

        {/* Domain Availability Search & Registration Confirmation Dialog */}
        <DomainSearchRegister
          csrfToken={session.csrfToken}
          tld={base.ALT_TLD}
          registrationEnabled={base.REGISTRATION_ENABLED}
          accountOwnsDomain={Boolean(userDomain)}
          ownedDomainName={userDomain?.name ?? null}
          hasBoundOwnerKey={Boolean(account.ownerPublicKey)}
        />
      </main>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col gap-6 px-6 py-10">
          <div className="h-16 w-full animate-pulse rounded-4xl bg-muted" />
          <div className="h-44 w-full animate-pulse rounded-4xl bg-muted" />
          <div className="h-64 w-full animate-pulse rounded-4xl bg-muted" />
        </div>
      }
    >
      <DashboardView />
    </Suspense>
  );
}
