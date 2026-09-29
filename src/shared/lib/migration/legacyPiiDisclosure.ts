/**
 * Value-free disclosure of the legacy plaintext PII residue and the migration
 * markers (T5.3, ADR-002 §2.2).
 *
 * The Privacy screen must be HONEST about three things at once, without ever
 * rendering a record value:
 *
 *  (a) whether legacy plaintext PII still sits under the three replaced
 *      `localStorage` keys — key NAMES and record counts only, from
 *      `detectLegacyPlaintextPii`;
 *  (b) the vault access state — `hydrated | locked | unavailable` — from the
 *      gate's own `getPiiStoreAccessState`;
 *  (c) the re-home / migration-marker state — whether the residue was already
 *      re-homed, is still pending, or belongs to an interrupted migration.
 *
 * ## Why this is a separate module, not component logic
 *
 * The three sources are read-only and already exist. Keeping the derivation
 * pure and injectable means the disclosure can be asserted (including the
 * "no value leaks" contract) without a DOM, and the component stays a dumb
 * renderer. It reads through the manifest-gated storage exactly like the
 * detection half it reuses, so an undeclared key is denied rather than read.
 *
 * ## The states, and what proves each one
 *
 *  - `migrated`   — there is no residue to move, OR the re-home completion
 *                   marker (`LEGACY_PII_REHOME_MARKER_KEY`) exists. That marker
 *                   is only ever written after a run was written AND verified,
 *                   so its presence is positive proof of a completed re-home.
 *  - `incomplete` — residue exists, no verified completion marker, AND the
 *                   history-migration recovery marker holds a resumable backup
 *                   (a durable preimage an interrupted migration left behind).
 *                   The backup is the honest signal of "a migration started and
 *                   did not finish".
 *  - `pending`    — residue exists and nothing proves otherwise: it awaits the
 *                   user's explicit choice. Never reported as done.
 *
 * `already_migrated` and `no_residue` from the re-home status collapse into
 * `migrated` here: both mean "nothing is waiting to be moved". The plaintext
 * source is NEVER deleted (copy-without-delete), so residue may coexist with
 * `migrated` — the panel shows both facts rather than picking one.
 *
 * `historyMarker` is disclosed separately because it is a different migration's
 * marker; its value is PII-bearing, so only its KEY NAME and derived state are
 * ever exposed.
 */

import {
  detectLegacyPlaintextPii,
  type LegacyPiiPlaintextKeyReport,
} from "@/shared/lib/legacyPiiPlaintext";
import {
  getPiiStoreAccessState,
  type PiiVaultAccessState,
} from "@/shared/lib/crypto/piiStoreHydration";
import { guardedStorage } from "@/shared/lib/manifestStorage";
import { LEGACY_PII_REHOME_MARKER_KEY } from "@/shared/lib/migration/legacyPiiRehome";
import {
  MIGRATION_MARKER_KEY,
  isHistoryMigrationBackup,
} from "@/shared/lib/migration/marker";

/** The re-home disclosure state shown to the user. */
export type RehomeDisclosureState = "migrated" | "pending" | "incomplete";

/** The history-migration marker state shown to the user. */
export type HistoryMarkerState = "absent" | "complete" | "resumable";

/** What the panel needs to know about the re-home. Value-free. */
export interface RehomeDisclosure {
  state: RehomeDisclosureState;
  /** True when the verified completion marker exists. */
  completed: boolean;
  /** The marker KEY NAME only — never its value. */
  markerKey: string;
}

/** What the panel needs to know about the history-migration marker. */
export interface HistoryMarkerDisclosure {
  state: HistoryMarkerState;
  /** The marker KEY NAME only — never its value. */
  markerKey: string;
}

export interface LegacyPiiDisclosure {
  residue: {
    present: boolean;
    total: number;
    /** Per-key NAME + count. Same value-free shape as the detection half. */
    keys: LegacyPiiPlaintextKeyReport[];
  };
  vault: PiiVaultAccessState;
  rehome: RehomeDisclosure;
  historyMarker: HistoryMarkerDisclosure;
}

export interface LegacyPiiDisclosureOptions {
  /**
   * How to read a raw storage value. Injectable so a test can exercise the
   * derivation without a DOM; defaults to the manifest-gated `localStorage`
   * facade, mirroring `detectLegacyPlaintextPii`.
   */
  read?: (key: string) => string | null;
  /** Inject the vault state (tests); defaults to the gate's own answer. */
  vault?: PiiVaultAccessState;
}

function historyMarkerState(raw: string | null): HistoryMarkerState {
  if (raw === null) return "absent";
  // A parseable backup is a durable recovery preimage: an interrupted
  // migration. The legacy non-JSON "done" value and any non-backup document
  // mean there is nothing to resume.
  return isHistoryMigrationBackup(raw) !== null ? "resumable" : "complete";
}

function rehomeState(
  residuePresent: boolean,
  completed: boolean,
  historyState: HistoryMarkerState,
): RehomeDisclosureState {
  if (!residuePresent || completed) return "migrated";
  if (historyState === "resumable") return "incomplete";
  return "pending";
}

/**
 * Derive the value-free disclosure from the three read-only sources.
 *
 * Never throws: an unreadable value is reported as `absent`/no-residue by the
 * detection half, because a storage failure must not turn the Privacy screen
 * into an error page. Writes nothing.
 */
export function getLegacyPiiDisclosure(
  options: LegacyPiiDisclosureOptions = {},
): LegacyPiiDisclosure {
  const read = options.read ?? ((key: string) => guardedStorage.getItem(key));

  const report = detectLegacyPlaintextPii(read);
  const completed = read(LEGACY_PII_REHOME_MARKER_KEY) !== null;
  const historyState = historyMarkerState(read(MIGRATION_MARKER_KEY));

  return {
    residue: {
      present: report.present,
      total: report.total,
      keys: report.keys,
    },
    vault: options.vault ?? getPiiStoreAccessState(),
    rehome: {
      state: rehomeState(report.present, completed, historyState),
      completed,
      markerKey: LEGACY_PII_REHOME_MARKER_KEY,
    },
    historyMarker: {
      state: historyState,
      markerKey: MIGRATION_MARKER_KEY,
    },
  };
}
