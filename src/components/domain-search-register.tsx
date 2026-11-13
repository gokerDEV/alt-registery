"use client";

import {
  AlertCircleIcon,
  CheckCircle2Icon,
  Loader2Icon,
  SearchIcon,
  ShieldAlertIcon,
} from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";

interface CheckResponse {
  name: string;
  label: string;
  available: boolean;
  reserved: boolean;
  reason: string | null;
  message: string;
  accountOwnsDomain: boolean;
  ownedDomainName: string | null;
  registrationEnabled: boolean;
}

interface DomainSearchRegisterProps {
  csrfToken: string;
  tld: string;
  registrationEnabled: boolean;
  accountOwnsDomain: boolean;
  ownedDomainName: string | null;
  hasBoundOwnerKey: boolean;
}

export function DomainSearchRegister({
  csrfToken,
  tld,
  registrationEnabled,
  accountOwnsDomain,
  ownedDomainName,
  hasBoundOwnerKey,
}: DomainSearchRegisterProps) {
  const router = useRouter();
  const inputId = React.useId();
  const hintId = React.useId();
  const errorId = React.useId();
  const formHeadingId = React.useId();
  const inputRef = React.useRef<HTMLInputElement>(null);

  const [query, setQuery] = React.useState("");
  const [fieldError, setFieldError] = React.useState<string | null>(null);
  const [hasBlurred, setHasBlurred] = React.useState(false);
  const [isChecking, setIsChecking] = React.useState(false);
  const [checkResult, setCheckResult] = React.useState<CheckResponse | null>(
    null,
  );

  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [isRegistering, setIsRegistering] = React.useState(false);
  const [registerError, setRegisterError] = React.useState<string | null>(null);

  function validateClientLabel(raw: string): string | null {
    const trimmed = raw.trim().toLowerCase().replace(/\.$/, "");
    if (!trimmed) {
      return `Enter a domain label between 2 and 63 characters (for example, goker.${tld}).`;
    }
    const withoutTld = trimmed.endsWith(`.${tld}`)
      ? trimmed.slice(0, -(tld.length + 1))
      : trimmed;

    if (withoutTld.includes(".")) {
      return `Enter a single label under .${tld} without subdomains (for example, goker).`;
    }
    if (withoutTld.length < 2) {
      return "Labels must be at least 2 characters long.";
    }
    if (withoutTld.length > 63) {
      return "Labels must be 63 characters or fewer.";
    }
    if (withoutTld.startsWith("-") || withoutTld.endsWith("-")) {
      return "Labels cannot start or end with a hyphen.";
    }
    if (!/^[a-z0-9-]+$/.test(withoutTld)) {
      return "Use lowercase ASCII letters (a-z), digits (0-9), and interior hyphens only.";
    }
    if (withoutTld.startsWith("xn--")) {
      return "Punycode (xn--) prefixes are not permitted.";
    }
    return null;
  }

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const nextVal = e.target.value;
    setQuery(nextVal);
    setCheckResult(null);
    setRegisterError(null);
    // Clear existing error immediately on input once valid (Forms Validation Timing Matrix)
    if (fieldError && validateClientLabel(nextVal) === null) {
      setFieldError(null);
    }
  }

  function handleBlur() {
    setHasBlurred(true);
    if (query.trim().length > 0) {
      setFieldError(validateClientLabel(query));
    }
  }

  async function handleCheckSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setRegisterError(null);

    const validationMessage = validateClientLabel(query);
    if (validationMessage) {
      setHasBlurred(true);
      setFieldError(validationMessage);
      inputRef.current?.focus();
      return;
    }

    setFieldError(null);
    setIsChecking(true);
    try {
      const response = await fetch(
        `/api/domains/check?name=${encodeURIComponent(query.trim())}`,
        {
          method: "GET",
          headers: { Accept: "application/json" },
        },
      );
      const payload = await response.json();
      if (!response.ok) {
        setFieldError(
          payload?.error?.message ?? "Unable to check domain availability.",
        );
        return;
      }
      setCheckResult(payload as CheckResponse);
    } catch {
      setFieldError("Network error while checking domain availability.");
    } finally {
      setIsChecking(false);
    }
  }

  async function handleConfirmRegister() {
    if (!checkResult?.available || isRegistering) {
      return;
    }
    setIsRegistering(true);
    setRegisterError(null);
    try {
      const response = await fetch("/api/domains", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify({ name: checkResult.label }),
      });

      const payload = await response.json();
      if (!response.ok) {
        setRegisterError(
          payload?.error?.message ?? "Registration failed. Please try again.",
        );
        return;
      }

      setConfirmOpen(false);
      setCheckResult(null);
      setQuery("");
      router.refresh();
    } catch {
      setRegisterError("Network error while submitting domain reservation.");
    } finally {
      setIsRegistering(false);
    }
  }

  const canReserveResult =
    Boolean(checkResult?.available) &&
    !accountOwnsDomain &&
    !checkResult?.accountOwnsDomain &&
    registrationEnabled &&
    checkResult?.registrationEnabled !== false;

  const describedBy =
    fieldError && hasBlurred ? `${hintId} ${errorId}` : hintId;

  return (
    <Card>
      <CardHeader>
        <CardTitle id={formHeadingId}>Check `.{tld}` Availability</CardTitle>
        <CardDescription>
          Search any 2–63 character lowercase ASCII name under{" "}
          <code className="font-mono text-xs">.{tld}</code>. Checking a name
          does not reserve it.
        </CardDescription>
      </CardHeader>

      <CardContent className="flex flex-col gap-5">
        <search>
          <form
            aria-labelledby={formHeadingId}
            action="/api/domains/check"
            method="GET"
            noValidate
            onSubmit={handleCheckSubmit}
            className="flex flex-col gap-4"
          >
            <Field data-invalid={Boolean(fieldError && hasBlurred)}>
              <FieldLabel htmlFor={inputId}>Domain name</FieldLabel>
              <FieldDescription id={hintId}>
                2–63 characters: lowercase letters (a–z), digits (0–9), and
                interior hyphens (for example,{" "}
                <code className="font-mono text-xs">goker</code> or{" "}
                <code className="font-mono text-xs">goker.{tld}</code>).
              </FieldDescription>

              <div className="flex flex-col gap-2 sm:flex-row">
                <Input
                  ref={inputRef}
                  id={inputId}
                  name="name"
                  type="text"
                  value={query}
                  onChange={handleInputChange}
                  onBlur={handleBlur}
                  placeholder={`yourname.${tld}`}
                  required
                  minLength={2}
                  maxLength={67}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  enterKeyHint="search"
                  aria-invalid={fieldError && hasBlurred ? "true" : "false"}
                  aria-describedby={describedBy}
                  className="h-10 font-mono text-base sm:flex-1"
                />

                <Button
                  type="submit"
                  size="lg"
                  disabled={isChecking}
                  className="sm:w-40"
                >
                  {isChecking ? (
                    <>
                      <Loader2Icon
                        className="animate-spin"
                        data-icon="inline-start"
                      />
                      Checking…
                    </>
                  ) : (
                    <>
                      <SearchIcon data-icon="inline-start" />
                      Check Name
                    </>
                  )}
                </Button>
              </div>

              {fieldError && hasBlurred ? (
                <FieldError id={errorId}>
                  <span className="inline-flex items-center gap-1.5">
                    <AlertCircleIcon
                      className="size-4 shrink-0"
                      aria-hidden="true"
                    />
                    <span>Error: {fieldError}</span>
                  </span>
                </FieldError>
              ) : null}
            </Field>
          </form>
        </search>

        <div aria-live="polite" className="flex flex-col gap-3">
          {!registrationEnabled ? (
            <Alert>
              <ShieldAlertIcon />
              <AlertTitle>Registrations paused</AlertTitle>
              <AlertDescription>
                New domain allocations are temporarily paused by the registry
                operator. Availability search remains open.
              </AlertDescription>
            </Alert>
          ) : null}

          {checkResult ? (
            <div className="flex flex-col justify-between gap-4 rounded-3xl border border-border bg-muted/30 p-4 sm:flex-row sm:items-center">
              <div className="flex flex-col gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-base font-semibold">
                    {checkResult.name}
                  </span>
                  {checkResult.available ? (
                    <Badge variant="default">
                      <CheckCircle2Icon data-icon="inline-start" />
                      Available
                    </Badge>
                  ) : checkResult.reserved ? (
                    <Badge variant="secondary">Reserved System Name</Badge>
                  ) : (
                    <Badge variant="outline">Unavailable</Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  {checkResult.message}
                  {checkResult.available && accountOwnsDomain && ownedDomainName
                    ? ` — Your GitHub account already owns ${ownedDomainName} (1-domain limit).`
                    : ""}
                </p>
              </div>

              {canReserveResult ? (
                <Button
                  type="button"
                  onClick={() => {
                    setRegisterError(null);
                    setConfirmOpen(true);
                  }}
                >
                  Reserve {checkResult.name}
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>

        <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                Reserve{" "}
                <span className="font-mono">{checkResult?.name ?? ""}</span>?
              </DialogTitle>
              <DialogDescription>
                Each GitHub account can allocate{" "}
                <strong className="text-foreground">one .{tld} domain</strong>{" "}
                during the initial phase.{" "}
                {hasBoundOwnerKey
                  ? "Your verified Ed25519 owner key is already bound, so your signed ownership certificate will be issued immediately."
                  : "This reserves the name in pending_key state until you bind your locally generated Ed25519 owner key from the alt CLI."}
              </DialogDescription>
            </DialogHeader>

            {registerError ? (
              <Alert variant="destructive">
                <AlertCircleIcon />
                <AlertTitle>Could not reserve domain</AlertTitle>
                <AlertDescription>{registerError}</AlertDescription>
              </Alert>
            ) : null}

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={isRegistering}
                onClick={() => setConfirmOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                disabled={isRegistering}
                onClick={handleConfirmRegister}
              >
                {isRegistering ? (
                  <>
                    <Loader2Icon
                      className="animate-spin"
                      data-icon="inline-start"
                    />
                    Reserving…
                  </>
                ) : (
                  `Confirm Reservation`
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
