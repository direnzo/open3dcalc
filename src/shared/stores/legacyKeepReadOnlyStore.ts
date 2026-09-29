import { create } from "zustand";
import { guardedStorage } from "@/shared/lib/manifestStorage";
import type { LegacyPiiPlaintextReport } from "@/shared/lib/legacyPiiPlaintext";

/**
 * Persisted "keep read-only" decision for the legacy plaintext residue.
 *
 * T5.2 left the choice session-only: `LegacyMigrationDialog.handleKeepReadOnly`
 * set local state and the prompt reappeared on EVERY new session, because
 * nothing remembered the answer. This store persists it — VALUE-FREE and
 * non-PII: it holds a SIGNATURE of the residue (each legacy key's name and
 * record COUNT), never a record and never a value. Storing counts is what lets
 * the decision expire HONESTLY: if the residue changes (an old client writes
 * again, or the user migrates), the signature no longer matches and the prompt
 * returns. A stored decision therefore means exactly "the residue has not
 * changed since the user chose to keep it read-only".
 *
 * `reopen()` forgets the decision so the choice can be offered again — the
 * Privacy screen path that satisfies "always offer a way back to the choice".
 *
 * The key is declared in SPEC-01 as a non-PII `onboarding_flag`
 * (`open3dcalc_legacy_keep_readonly_v1`): plaintext allowed, never synced,
 * never exported, erased on delete-all.
 */

/** The SPEC-01 key holding the persisted keep-read-only decision. */
export const LEGACY_KEEP_READONLY_KEY = "open3dcalc_legacy_keep_readonly_v1";

const KEEP_READONLY_TYPE = "open3dcalc-legacy-keep-readonly";
const KEEP_READONLY_VERSION = 1;

/**
 * A value-free signature of the residue: the key NAME and its record COUNT
 * (or `absent`). Two calls with the same residue produce the same string; any
 * change in presence or count changes it. No record value is ever included.
 */
export function residueSignature(report: LegacyPiiPlaintextReport): string {
  return report.keys
    .map((entry) => `${entry.key}=${entry.present ? entry.count : "absent"}`)
    .join("|");
}

interface PersistedDecision {
  type?: unknown;
  v?: unknown;
  signature?: unknown;
}

/** Read the persisted signature, or null when absent/unreadable. */
function readStoredSignature(): string | null {
  const raw = guardedStorage.getItem(LEGACY_KEEP_READONLY_KEY);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PersistedDecision;
    if (
      parsed.type === KEEP_READONLY_TYPE &&
      parsed.v === KEEP_READONLY_VERSION &&
      typeof parsed.signature === "string"
    ) {
      return parsed.signature;
    }
  } catch {
    /* a malformed value is treated as "no decision" */
  }
  return null;
}

interface LegacyKeepReadOnlyState {
  /** The signature of the residue the user chose to keep read-only, if any. */
  signature: string | null;
  /** Persist the keep-read-only choice for this residue signature. */
  keep(signature: string): void;
  /** Forget the choice so it can be offered again. */
  reopen(): void;
}

export const useLegacyKeepReadOnlyStore = create<LegacyKeepReadOnlyState>(
  (set) => ({
    signature: readStoredSignature(),
    keep: (signature) => {
      guardedStorage.setItem(
        LEGACY_KEEP_READONLY_KEY,
        JSON.stringify({
          type: KEEP_READONLY_TYPE,
          v: KEEP_READONLY_VERSION,
          signature,
        }),
      );
      set({ signature });
    },
    reopen: () => {
      guardedStorage.removeItem(LEGACY_KEEP_READONLY_KEY);
      set({ signature: null });
    },
  }),
);
