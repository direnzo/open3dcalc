import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Lock, ShieldAlert } from "lucide-react";
import {
  getPiiStoreAccessState,
  getPiiStoreRuntimeOptions,
  installPiiStoreRuntimeEnvironment,
  rehydratePiiStoresIfUnlocked,
  unlockPiiStoresAndRehydrate,
  type PiiVaultAccessState,
} from "@/shared/lib/crypto/piiStoreHydration";
import type { PiiStoreDenialReason } from "@/shared/lib/crypto/piiStoreCapability";

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
 * honest about which of three states the vault is in:
 *
 *  - `locked`: the environment is capable but no key is held. The user types a
 *    passphrase, which is held in memory only (`passphraseSession`) and never
 *    written anywhere, and the stores rehydrate. A wrong passphrase fails at
 *    unlock and changes nothing.
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
 */

const PASSPHRASE_INPUT_ID = "pii-vault-passphrase";
const NOTE_ID = "pii-vault-note";

/** The typed refusal code a failed unlock carries, or a safe fallback. */
function refusalCode(error: unknown): string {
  const reason = (error as { reason?: unknown } | null)?.reason;
  return typeof reason === "string" && reason.length > 0 ? reason : "unknown";
}

export function PiiLockedShell(): ReactElement | null {
  const { t } = useTranslation();
  const [access, setAccess] = useState<PiiVaultAccessState>(() => {
    // Install the capability snapshot before the first read, or a capable
    // browser would render as `capability_unknown`.
    installPiiStoreRuntimeEnvironment();
    return getPiiStoreAccessState();
  });
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // The startup wake: if some other path already unlocked the vault, rehydrate
  // now. A locked profile resolves to null and is left untouched for the form.
  useEffect(() => {
    let cancelled = false;
    void rehydratePiiStoresIfUnlocked().then((outcomes) => {
      if (cancelled || outcomes === null) return;
      const next = getPiiStoreAccessState();
      setAccess((current) => (current.status === next.status ? current : next));
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Same rule as DemoModeIndicator: take focus on FIRST appearance only, when
  // nothing else owns it. A user mid-interaction keeps their focus.
  useEffect(() => {
    if (
      access.status === "locked" &&
      document.activeElement === document.body
    ) {
      inputRef.current?.focus();
    }
  }, [access.status]);

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (busy || passphrase.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      // The passphrase is passed straight through, never stored: the vault
      // derives a non-extractable key and `passphraseSession` keeps a copy in
      // memory only. The field is cleared on BOTH outcomes.
      await unlockPiiStoresAndRehydrate(
        passphrase,
        getPiiStoreRuntimeOptions(),
      );
      setPassphrase("");
      setAccess(getPiiStoreAccessState());
    } catch (caught) {
      setPassphrase("");
      setError(refusalCode(caught));
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

  return (
    <section
      aria-label={t("privacy.vault.ariaLabel")}
      className="w-full border-b bg-[var(--color-warning-muted)] border-[var(--color-warning)]/30"
    >
      <div className="max-w-[1600px] 2xl:max-w-[1920px] mx-auto w-full px-4 sm:px-6 lg:px-12 py-2.5 flex flex-col sm:flex-row sm:items-center gap-3">
        {unavailableReason !== null ? (
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
            {unavailableReason !== null
              ? t("privacy.vault.unavailableTitle")
              : t("privacy.vault.lockedTitle")}
          </strong>
          <p className="text-xs sm:text-[13px] text-[var(--color-warning)]">
            {unavailableReason !== null
              ? t("privacy.vault.unavailableMessage")
              : t("privacy.vault.lockedMessage")}
          </p>
          {unavailableReason !== null ? (
            <p className="text-[11px] font-mono text-[var(--color-warning)] opacity-90">
              {t("privacy.vault.unavailableDetail", {
                reason: unavailableReason,
              })}
            </p>
          ) : (
            <p
              id={NOTE_ID}
              className="text-[11px] text-[var(--color-warning)] opacity-90"
            >
              {t("privacy.vault.memoryNote")}
            </p>
          )}
        </div>

        {unavailableReason === null && (
          <form
            onSubmit={(event) => void handleSubmit(event)}
            className="flex items-center gap-2 shrink-0"
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
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              placeholder={t("privacy.vault.passphrasePlaceholder")}
              className="min-h-[36px] w-40 sm:w-52 px-3 py-1.5 rounded-lg text-sm bg-[var(--color-bg-primary)] text-[var(--color-text-primary)] border border-[var(--color-border)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            />
            <button
              type="submit"
              disabled={busy || passphrase.length === 0}
              className="inline-flex items-center min-h-[36px] px-3 py-1.5 text-xs font-bold rounded-lg bg-[var(--color-warning-fill)] text-[var(--color-warning-fill-fg)] hover:bg-[var(--color-warning-fill-hover)] transition-colors focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none disabled:opacity-60"
            >
              {busy ? t("privacy.vault.unlocking") : t("privacy.vault.unlock")}
            </button>
          </form>
        )}
      </div>

      {error !== null && (
        <div className="max-w-[1600px] 2xl:max-w-[1920px] mx-auto w-full px-4 sm:px-6 lg:px-12 pb-2">
          <p
            role="alert"
            className="text-xs font-semibold text-[var(--color-warning)]"
          >
            {t("privacy.vault.unlockError")}{" "}
            {t("privacy.vault.unlockErrorDetail", { reason: error })}
          </p>
        </div>
      )}
    </section>
  );
}
