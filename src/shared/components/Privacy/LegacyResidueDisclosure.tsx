import { useMemo } from "react";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Database, HardDrive, History, Lock, ShieldCheck } from "lucide-react";
import {
  getLegacyPiiDisclosure,
  type HistoryMarkerState,
  type LegacyPiiDisclosure,
  type RehomeDisclosureState,
} from "@/shared/lib/migration/legacyPiiDisclosure";
import {
  installPiiStoreRuntimeEnvironment,
  type PiiVaultAccessState,
} from "@/shared/lib/crypto/piiStoreHydration";

/**
 * T5.3 — the honest, value-free legacy-residue disclosure panel.
 *
 * ADR-002 §2.2 requires the plaintext residue to be surfaced, never silently
 * migrated and never silently deleted. This panel states, in one place:
 *
 *  (a) which legacy plaintext PII keys still hold data and how many records,
 *  (b) the vault access state (`hydrated | locked | unavailable`),
 *  (c) the re-home state (`migrated | pending | incomplete`) and the
 *      history-migration marker state.
 *
 * It renders KEY NAMES, COUNTS and STATES only. No record value and no marker
 * value is ever read into — or rendered by — this component: the derivation
 * (`getLegacyPiiDisclosure`) is value-free by construction, and the marker is
 * exposed as a key name plus a state.
 *
 * The section is a labelled `region` with `aria-live="polite"`, so a screen
 * reader announces the disclosure when it is reached or updated.
 */

const VAULT_LABEL_KEYS: Record<PiiVaultAccessState["status"], string> = {
  hydrated: "privacy.residue.vaultHydrated",
  locked: "privacy.residue.vaultLocked",
  unavailable: "privacy.residue.vaultUnavailable",
};

const REHOME_LABEL_KEYS: Record<RehomeDisclosureState, string> = {
  migrated: "privacy.residue.rehomeMigrated",
  pending: "privacy.residue.rehomePending",
  incomplete: "privacy.residue.rehomeIncomplete",
};

const HISTORY_LABEL_KEYS: Record<HistoryMarkerState, string> = {
  absent: "privacy.residue.historyAbsent",
  complete: "privacy.residue.historyComplete",
  resumable: "privacy.residue.historyResumable",
};

const HEADING_ID = "privacy-residue-heading";

export interface LegacyResidueDisclosureProps {
  /** Injectable derived disclosure (tests); defaults to a live derivation. */
  disclosure?: LegacyPiiDisclosure;
}

function deriveLiveDisclosure(): LegacyPiiDisclosure {
  // Install the capability snapshot before the first read, or a capable
  // browser would report `capability_unknown` and read as unavailable.
  installPiiStoreRuntimeEnvironment();
  return getLegacyPiiDisclosure();
}

export function LegacyResidueDisclosure({
  disclosure,
}: LegacyResidueDisclosureProps = {}): ReactElement {
  const { t } = useTranslation();
  const data = useMemo(
    () => (disclosure ? disclosure : deriveLiveDisclosure()),
    [disclosure],
  );

  const presentKeys = data.residue.keys.filter((entry) => entry.present);

  return (
    <section
      role="region"
      aria-labelledby={HEADING_ID}
      aria-live="polite"
      className="surface rounded-xl p-4 space-y-3"
    >
      <h3
        id={HEADING_ID}
        className="text-sm font-bold text-[var(--color-text-primary)] flex items-center gap-2"
      >
        <ShieldCheck
          className="w-4 h-4 text-[var(--color-accent)]"
          aria-hidden="true"
        />
        {t("privacy.residue.title")}
      </h3>
      <p className="text-xs text-[var(--color-text-secondary)]">
        {t("privacy.residue.subtitle")}
      </p>

      {/* (a) plaintext residue — key NAMES + counts only */}
      <div className="space-y-1">
        <p className="text-xs font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
          <Database className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
          {t("privacy.residue.residueHeading")}
        </p>
        {presentKeys.length === 0 ? (
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t("privacy.residue.residueNone")}
          </p>
        ) : (
          <>
            <p className="text-xs text-[var(--color-text-secondary)]">
              {t("privacy.residue.residueTotal", {
                count: data.residue.total,
              })}
            </p>
            <ul className="text-xs text-[var(--color-text-secondary)] space-y-0.5">
              {presentKeys.map((entry) => (
                <li key={entry.key}>
                  {t("privacy.residue.residueKey", {
                    key: entry.key,
                    count: entry.count,
                  })}
                </li>
              ))}
            </ul>
            <p className="text-[11px] text-[var(--color-text-muted)]">
              {t("privacy.residue.residueKeptNote")}
            </p>
          </>
        )}
      </div>

      {/* (b) vault access state */}
      <div className="space-y-1">
        <p className="text-xs font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
          <HardDrive
            className="w-3.5 h-3.5 text-[var(--color-accent)]"
            aria-hidden="true"
          />
          {t("privacy.residue.vaultHeading")}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)] flex items-center gap-2">
          {data.vault.status === "locked" && (
            <Lock className="w-3.5 h-3.5" aria-hidden="true" />
          )}
          {t(VAULT_LABEL_KEYS[data.vault.status])}
        </p>
        {data.vault.status === "unavailable" && (
          <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
            {t("privacy.residue.vaultUnavailableDetail", {
              reason: data.vault.reason,
            })}
          </p>
        )}
      </div>

      {/* (c) re-home state */}
      <div className="space-y-1">
        <p className="text-xs font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
          <History
            className="w-3.5 h-3.5 text-[var(--color-accent)]"
            aria-hidden="true"
          />
          {t("privacy.residue.rehomeHeading")}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)]">
          {t(REHOME_LABEL_KEYS[data.rehome.state])}
        </p>
        <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
          {t("privacy.residue.markerNote", { key: data.rehome.markerKey })}
        </p>
      </div>

      {/* (c cont.) history-migration marker state */}
      <div className="space-y-1">
        <p className="text-xs font-semibold text-[var(--color-text-primary)]">
          {t("privacy.residue.historyHeading")}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)]">
          {t(HISTORY_LABEL_KEYS[data.historyMarker.state])}
        </p>
        <p className="text-[11px] font-mono text-[var(--color-text-muted)]">
          {t("privacy.residue.markerNote", {
            key: data.historyMarker.markerKey,
          })}
        </p>
      </div>

      <p className="text-[11px] text-[var(--color-text-muted)]">
        {t("privacy.residue.valueFreeNote")}
      </p>
    </section>
  );
}
