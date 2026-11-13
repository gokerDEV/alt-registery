import {
  ArrowRightIcon,
  CheckCircle2Icon,
  KeyRoundIcon,
  ShieldCheckIcon,
  TerminalIcon,
} from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { readWebSessionFromCookies } from "@/lib/session";

const AUTH_ERROR_MESSAGES: Record<string, string> = {
  oauth_denied: "GitHub authorization was cancelled.",
  invalid_oauth_state:
    "Your sign-in session expired or failed state verification. Please try again.",
  login_failed:
    "Unable to complete GitHub sign-in right now. Verify OAuth & database configuration.",
  auth_unconfigured:
    "GitHub OAuth environment variables are not configured on this server yet.",
  rate_limited: "Too many sign-in attempts. Please wait a minute and retry.",
};

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
    >
      <path d="M12 0.297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385 0.6 0.113 0.82-0.258 0.82-0.577 0-0.285-0.01-1.04-0.015-2.04-3.338 0.724-4.042-1.61-4.042-1.61-0.546-1.385-1.335-1.755-1.335-1.755-1.087-0.744 0.084-0.729 0.084-0.729 1.205 0.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495 0.998 0.108-0.776 0.417-1.305 0.76-1.605-2.665-0.3-5.466-1.332-5.466-5.93 0-1.31 0.465-2.38 1.235-3.22-0.135-0.303-0.54-1.523 0.105-3.176 0 0 1.005-0.322 3.3 1.23 0.96-0.267 1.98-0.399 3-0.405 1.02 0.006 2.04 0.138 3 0.405 2.28-1.552 3.285-1.23 3.285-1.23 0.645 1.653 0.24 2.873 0.12 3.176 0.765 0.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92 0.42 0.36 0.81 1.096 0.81 2.22 0 1.606-0.015 2.896-0.015 3.286 0 0.315 0.21 0.69 0.825 0.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

async function HeaderAuthAction() {
  const session = await readWebSessionFromCookies();
  if (session) {
    return (
      <Button
        nativeButton={false}
        variant="secondary"
        size="sm"
        render={<Link href="/dashboard" />}
      >
        Dashboard (@{session.githubLogin})
        <ArrowRightIcon data-icon="inline-end" />
      </Button>
    );
  }
  return (
    <a
      href="/api/auth/github"
      className={buttonVariants({ variant: "outline", size: "sm" })}
    >
      <GitHubIcon className="size-4" />
      Sign in
    </a>
  );
}

async function HeroCta({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const [session, resolvedSearch] = await Promise.all([
    readWebSessionFromCookies(),
    searchParams,
  ]);

  const errorMessage = resolvedSearch.error
    ? (AUTH_ERROR_MESSAGES[resolvedSearch.error] ?? "Authentication failed.")
    : null;

  return (
    <div className="flex flex-col gap-4">
      {errorMessage ? (
        <Alert variant="destructive" className="max-w-xl">
          <AlertTitle>Sign-in notice</AlertTitle>
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        {session ? (
          <Button
            nativeButton={false}
            size="lg"
            render={<Link href="/dashboard" />}
          >
            Open Dashboard
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
        ) : (
          <a
            href="/api/auth/github"
            className={buttonVariants({ variant: "default", size: "lg" })}
          >
            <GitHubIcon className="size-4" />
            Continue with GitHub
          </a>
        )}

        <a
          href="https://github.com/gokerdev/dotALT"
          target="_blank"
          rel="noopener noreferrer"
          className={buttonVariants({ variant: "outline", size: "lg" })}
        >
          <TerminalIcon data-icon="inline-start" />
          Install dotALT CLI
        </a>
      </div>
    </div>
  );
}

export default function HomePage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b border-border/60 bg-background/80 backdrop-blur-sm">
        <div className="mx-auto flex h-16 max-w-5xl items-center justify-between px-6">
          <div className="flex items-center gap-2.5">
            <span className="font-heading text-lg font-semibold tracking-tight">
              register<span className="text-muted-foreground">.alt</span>
            </span>
            <Badge variant="secondary">alt-main-v1</Badge>
          </div>

          <Suspense
            fallback={
              <div className="h-8 w-24 animate-pulse rounded-4xl bg-muted" />
            }
          >
            <HeaderAuthAction />
          </Suspense>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col justify-center gap-12 px-6 py-16">
        <section className="flex flex-col gap-6">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">Official .alt Registry</Badge>
            <span className="text-xs text-muted-foreground">
              One domain per GitHub account during the initial phase
            </span>
          </div>

          <h1 className="max-w-3xl font-heading text-4xl font-semibold tracking-tight sm:text-5xl">
            Cryptographically verified names for an alternative web.
          </h1>

          <p className="max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            <strong>.alt</strong> provides local-first HTTPS development and
            signed name resolution without relying on public DNS authorities or
            trusted gateways. Reserve your name with GitHub, generate your
            Ed25519 owner key locally with{" "}
            <code className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-sm text-foreground">
              dotALT
            </code>
            , and publish signed records distributed over IPFS.
          </p>

          <Suspense
            fallback={
              <div className="flex gap-3">
                <div className="h-10 w-48 animate-pulse rounded-4xl bg-muted" />
                <div className="h-10 w-44 animate-pulse rounded-4xl bg-muted" />
              </div>
            }
          >
            <HeroCta searchParams={searchParams} />
          </Suspense>
        </section>

        <section
          aria-label="How registration works"
          className="grid gap-4 sm:grid-cols-3"
        >
          <Card size="sm">
            <CardHeader>
              <div className="mb-1 flex size-8 items-center justify-center rounded-2xl bg-secondary text-secondary-foreground">
                <CheckCircle2Icon className="size-4" />
              </div>
              <CardTitle>1. Reserve with GitHub</CardTitle>
              <CardDescription>
                Each GitHub account can reserve one{" "}
                <code className="font-mono text-xs">.alt</code> domain during
                the initial rollout, keyed to your immutable numeric GitHub ID.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card size="sm">
            <CardHeader>
              <div className="mb-1 flex size-8 items-center justify-center rounded-2xl bg-secondary text-secondary-foreground">
                <KeyRoundIcon className="size-4" />
              </div>
              <CardTitle>2. Bind Local Owner Key</CardTitle>
              <CardDescription>
                Your Ed25519 private key never leaves your machine. The{" "}
                <code className="font-mono text-xs">alt</code> CLI proves key
                possession via a single-use challenge before ownership is
                signed.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card size="sm">
            <CardHeader>
              <div className="mb-1 flex size-8 items-center justify-center rounded-2xl bg-secondary text-secondary-foreground">
                <ShieldCheckIcon className="size-4" />
              </div>
              <CardTitle>3. Signed IPFS Manifests</CardTitle>
              <CardDescription>
                Once you sign a target record with{" "}
                <code className="font-mono text-xs">alt publish</code>, the
                registry publishes a verified CIDv1 raw manifest to IPFS/IPNS.
              </CardDescription>
            </CardHeader>
          </Card>
        </section>

        <Card size="sm" className="bg-muted/30">
          <CardHeader>
            <CardTitle>Fair Allocation Policy</CardTitle>
            <CardDescription>
              During the initial phase, each GitHub account may register{" "}
              <strong className="font-medium text-foreground">
                exactly one .alt domain
              </strong>{" "}
              (2–63 lowercase ASCII letters, digits, and interior hyphens).
              System names such as{" "}
              <code className="font-mono text-xs text-foreground">
                register.alt
              </code>{" "}
              are permanently reserved for network bootstrap.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-2xl bg-background p-4 font-mono text-xs leading-relaxed ring-1 ring-border">
              <code>{`# Authenticate the dotALT CLI and bind your local Ed25519 owner key:
alt login github
alt register yourname.alt
alt publish yourname.alt --target https://your-origin.example`}</code>
            </pre>
          </CardContent>
        </Card>
      </main>

      <footer className="border-t border-border/60 py-6 text-xs text-muted-foreground">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-6">
          <span>
            Public origin: <code className="font-mono">alt.goker.dev</code> ·
            ALT origin: <code className="font-mono">register.alt</code>
          </span>
          <a
            href="https://github.com/gokerdev/dotALT"
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-4 hover:text-foreground"
          >
            dotALT Protocol &amp; Client
          </a>
        </div>
      </footer>
    </div>
  );
}
