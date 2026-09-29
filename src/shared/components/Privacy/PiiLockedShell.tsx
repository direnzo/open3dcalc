import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Lock, ShieldAlert } from "lucide-react";
import {
  getPiiStoreAccessState,
  getPiiStoreRuntimeOptions,
  hasExistingPiiProfile,
  installPiiStoreRuntimeEnvironment,
  rehydratePiiStoresIfUnlocked,
  unlockPiiStoresAndRehydrate,
  type PiiVaultAccessState,
} from "@/shared/lib/crypto/piiStoreHydration";
import type { PiiStoreDenialReason } from "@/shared/lib/crypto/piiStoreCapability";
import { migrateLegacyPlaintextPiiToVault } from "@/shared/lib/migration/legacyPiiRehome";

/**
 * T3.3 — the visible half of the locked PII vault.
 *
 * After Wave 3 the three migrated browser stores (`open3dcalc_customers_v1`,
 * `open3dcalc_quotes_v1`, `open3dcalc_history_v2`) set `skipHydration: true` and
 * wait for an explicit rehydrate. Nothing in production called it, so the app
 * rendered EMPTY customer, quote and history surfaces — safe (a locked store
 * cannot overwrite itself) but indistinguishable from data loss.
 *
 * This is the missing shell. It renders as a non-chrome banner beside the demo
 * and update notices, so it survives Focus Mode and every tab switch, and it is
 * honest about which state the vault is in:
 *
 *  - `locked`, no record (CREATE): this profile has never had a passphrase.
 *    The form asks for one TWICE and states up front that there is no reset;
 *    the first passphrase typed on a prior build "worked" silently and could
 *    never be typed again, which is the bug MEDIUM-1 fixes.
 *  - `locked`, record present (UNLOCK): the passphrase is entered once and
 *    verified against the sealed record. A wrong passphrase fails at unlock and
 *    changes nothing; the data is still recoverable.
 *  - `unavailable`: the environment can never protect PII (no Web Crypto, an
 *    insecure context, no IndexedDB) or the user declined persistence. No form
 *    is offered — a passphrase could not help — and the reason code is shown
 *    verbatim because that is what support diagnoses from.
 *  - `demo_session`: intentional and already explained by `DemoModeIndicator`,
 *    so the shell stays silent rather than nagging about ephemeral data.
 *
 * It reads no store: the state comes from the gate's own hydration map and the
 * single capability predicate, so rendering the shell can never itself hydrate
 * from — or write over — a locked vault.
 *
 * The passphrase is memory-only: it lives in React state for the length of the
 * submit and is handed straight to the vault, which derives a non-extractable
 * key and keeps a copy in `passphraseSession`. It is never persisted.
 */

const PASSPHRASE_INPUT_ID = "pii-vault-passphrase";
const CONFIRM_INPUT_ID = "pii-vault-passphrase-confirm";
const NOTE_ID = "pii-vault-note";
const IRRECOVERABLE_ID = "pii-vault-irrecoverable";

/**
 * Which locked form to show. `detecting` is the brief moment before the vault
 * has answered "is there a record?"; controls are disabled so a new profile is
 * never handed an unlock form it cannot fail, nor an existing one a "create"
 * form that would overwrite what it cannot see.
 */
type ProfileMode = "detecting" | "create" | "unlock";

/** The typed refusal code a failed unlock carries, or a safe fallback. */
function refusalCode(error: unknown): string {
  const reason = (error as { reason?: unknown } | null)?.reason;
  return typeof reason === "string" && reason.length > 0 ? reason : "unknown";
}

/** A validation or unlock failure, kept typed so the message matches the cause. */
type FormError = { kind: "mismatch" } | { kind: "unlock"; reason: string };

/**
 * Re-home legacy plaintext PII now that the vault is unlocked and hydrated.
 *
 * This is the production caller HIGH-3 was missing: a profile that predates the
 * vault unlocks to EMPTY stores (the vault is empty), while its real data is
 * still plaintext. Running the migration here writes that residue into the
 * encrypted destination and verifies it, without deleting the source. It is
 * fire-and-forget and never turns a migration problem into an unlock error;
 * refusals (no consent, unavailable vault) are reported to the console by name
 * only, never with PII.
 */
function rehomeLegacyPii(): void {
  void migrateLegacyPlaintextPiiToVault().catch(() => {
    console.warn("[PiiLockedShell] legacy PII re-home did not complete");
  });
}

export function PiiLockedShell(): ReactElement | null {
  const { t } = useTranslation();
  const [access, setAccess] = useState<PiiVaultAccessState>(() => {
    // Install the capability snapshot before the first read, or a capable
    // browser would render as `capability_unknown`.
    installPiiStoreRuntimeEnvironment();
    return getPiiStoreAccessState();
  });
  const [mode, setMode] = useState<ProfileMode>("detecting");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<FormError | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // The startup wake: if some other path already unlocked the vault, rehydrate
  // now. A locked profile resolves to null and is left untouched for the form.
  useEffect(() => {
    let cancelled = false;
    void rehydratePiiStoresIfUnlocked().then((outcomes) => {
      if (cancelled || outcomes === null) return;
      // A resumed session (or a platform adapter) already holds the key: the
      // stores are hydrated, so this is the moment to re-home any legacy
      // plaintext residue.
      rehomeLegacyPii();
      const next = getPiiStoreAccessState();
      setAccess((current) => (current.status === next.status ? current : next));
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Is there a profile to unlock, or one to create? This is metadata, readable
  // while locked, and it decides which form is honest. It runs only for a
  // locked vault: an unavailable environment has no form at all.
  useEffect(() => {
    if (access.status !== "locked") return;
    let cancelled = false;
    void hasExistingPiiProfile().then((exists) => {
      if (!cancelled) setMode(exists ? "unlock" : "create");
    });
    return () => {
      cancelled = true;
    };
  }, [access.status]);

  // Same rule as DemoModeIndicator: take focus on FIRST appearance only, when
  // nothing else owns it. A user mid-interaction keeps their focus. Waiting for
  // the mode keeps focus off the disabled placeholder controls.
  useEffect(() => {
    if (
      access.status === "locked" &&
      mode !== "detecting" &&
      document.activeElement === document.body
    ) {
      inputRef.current?.focus();
    }
  }, [access.status, mode]);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (busy || mode === "detecting" || passphrase.length === 0) return;
    // Create mode is the only path that asks twice; a mismatch is caught here,
    // before any key is derived, so the vault is untouched.
    if (mode === "create" && passphrase !== confirmation) {
      setFormError({ kind: "mismatch" });
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      // The passphrase is passed straight through, never stored: the vault
      // derives a non-extractable key and `passphraseSession` keeps a copy in
      // memory only. On an empty vault this CREATES the record with a fresh
      // salt; on an existing one it verifies before accepting. The fields are
      // cleared on BOTH outcomes.
      await unlockPiiStoresAndRehydrate(
        passphrase,
        getPiiStoreRuntimeOptions(),
      );
      setPassphrase("");
      setConfirmation("");
      setAccess(getPiiStoreAccessState());
      // The vault is now hydrated: re-home any legacy plaintext residue so a
      // pre-vault profile's stores are not left looking empty.
      rehomeLegacyPii();
    } catch (caught) {
      setPassphrase("");
      setConfirmation("");
      setFormError({ kind: "unlock", reason: refusalCode(caught) });
      setAccess(getPiiStoreAccessState());
    } finally {
      setBusy(false);
    }
  }

  if (access.status === "hydrated") return null;
  if (access.status === "unavailable" && access.reason === "demo_session") {
    return null;
  }

  const unavailableReason: PiiStoreDenialReason | null =
    access.status === "unavailable" ? access.reason : null;
  const creating = unavailableReason === null && mode === "create";
  // The form appears only once the create-vs-unlock question is answered, so
  // the user is never shown a control labelled for the wrong mode.
  const ready = unavailableReason === null && mode !== "detecting";
  const canSubmit =
    ready &&
    !busy &&
    passphrase.length > 0 &&
    (mode !== "create" || confirmation.length > 0);

  const title =
    unavailableReason !== null
      ? t("privacy.vault.unavailableTitle")
      : creating
        ? t("privacy.vault.createTitle")
        : t("privacy.vault.lockedTitle");
  const message =
    unavailableReason !== null
      ? t("privacy.vault.unavailableMessage")
      : creating
        ? t("privacy.vault.createMessage")
        : t("privacy.vault.lockedMessage");

  const inputClassName =
    "min-h-[36px] w-40 sm:w-52 px-3 py-1.5 rounded-lg text-sm bg-[var(--color-bg-primary)] text-[var(--color-text-primary)] border border-[var(--color-border)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none disabled:opacity-60";

  return (
    <section
      aria-label={t("privacy.vault.ariaLabel")}
      className="w-full border-b bg-[var(--color-warning-muted)] border-[var(--color-warning)]/30"
    >
      <div className="max-w-[1600px] 2xl:max-w-[1920px] mx-auto w-full px-4 sm:px-6 lg:px-12 py-2.5 flex flex-col sm:flex-row sm:items-center gap-3">
        {unavailableReason !== null || creating ? (
          <ShieldAlert
            className="w-5 h-5 shrink-0 text-[var(--color-warning)]"
            aria-hidden="true"
          />
        ) : (
          <Lock
            className="w-5 h-5 shrink-0 text-[var(--color-warning)]"
            aria-hidden="true"
          />
        )}

        <div className="min-w-0 flex-1">
          <strong className="text-sm font-bold text-[var(--color-warning)]">
            {title}
          </strong>
          <p className="text-xs sm:text-[13px] text-[var(--color-warning)]">
            {message}
          </p>
          {unavailableReason !== null ? (
            <p className="text-[11px] font-mono text-[var(--color-warning)] opacity-90">
              {t("privacy.vault.unavailableDetail", {
                reason: unavailableReason,
              })}
            </p>
          ) : (
            <>
              <p
                id={NOTE_ID}
                className="text-[11px] text-[var(--color-warning)] opacity-90"
              >
                {t("privacy.vault.memoryNote")}
              </p>
              {creating && (
                <p
                  id={IRRECOVERABLE_ID}
                  className="text-[11px] font-semibold text-[var(--color-warning)]"
                >
                  {t("privacy.vault.irrecoverableNotice")}
                </p>
              )}
            </>
          )}
        </div>

        {ready && (
          <form
            onSubmit={(event) => void handleSubmit(event)}
            className="flex flex-wrap items-center gap-2 shrink-0"
          >
            <label htmlFor={PASSPHRASE_INPUT_ID} className="sr-only">
              {t("privacy.vault.passphraseLabel")}
            </label>
            <input
              ref={inputRef}
              id={PASSPHRASE_INPUT_ID}
              type="password"
              autoComplete="off"
              aria-describedby={NOTE_ID}
              aria-invalid={formError !== null ? true : undefined}
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              placeholder={t(
                creating
                  ? "privacy.vault.createPassphrasePlaceholder"
                  : "privacy.vault.passphrasePlaceholder",
              )}
              className={inputClassName}
            />
            {creating && (
              <>
                <label htmlFor={CONFIRM_INPUT_ID} className="sr-only">
                  {t("privacy.vault.confirmPassphraseLabel")}
                </label>
                <input
                  id={CONFIRM_INPUT_ID}
                  type="password"
                  autoComplete="off"
                  aria-describedby={IRRECOVERABLE_ID}
                  aria-invalid={
                    formError?.kind === "mismatch" ? true : undefined
                  }
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  placeholder={t("privacy.vault.confirmPassphrasePlaceholder")}
                  className={inputClassName}
                />
              </>
            )}
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex items-center min-h-[36px] px-3 py-1.5 text-xs font-bold rounded-lg bg-[var(--color-warning-fill)] text-[var(--color-warning-fill-fg)] hover:bg-[var(--color-warning-fill-hover)] transition-colors focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none disabled:opacity-60"
            >
              {busy
                ? t(
                    creating
                      ? "privacy.vault.creating"
                      : "privacy.vault.unlocking",
                  )
                : t(creating ? "privacy.vault.create" : "privacy.vault.unlock")}
            </button>
          </form>
        )}
      </div>

      {formError !== null && (
        <div className="max-w-[1600px] 2xl:max-w-[1920px] mx-auto w-full px-4 sm:px-6 lg:px-12 pb-2">
          <p
            role="alert"
            className="text-xs font-semibold text-[var(--color-warning)]"
          >
            {formError.kind === "mismatch" ? (
              t("privacy.vault.mismatchError")
            ) : (
              <>
                {t("privacy.vault.unlockError")}{" "}
                {t("privacy.vault.unlockErrorDetail", {
                  reason: formError.reason,
                })}
              </>
            )}
          </p>
        </div>
      )}
    </section>
  );
}
