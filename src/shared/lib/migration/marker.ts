/**
 * Value-free parsers for the v2 history-migration recovery markers (T4.1, W4.4).
 *
 * ## Two markers, two generations
 *
 *  - `open3dcalc_migration_done_v2` — the LEGACY marker. An older build wrote
 *    the full raw pre-migration history array (`source` / `baseEntries` /
 *    `productsSource`) into it, which made it PII in plaintext
 *    (SPEC-01: class user_content, pii true). The current code reads it only to
 *    CONSUME a marker an old install already stored and to CLEAN it once the
 *    migration verifies (§3.3). It is never written again.
 *  - `open3dcalc_migration_progress_v2` — the CURRENT marker. It is VALUE-FREE:
 *    a version and a type, never a record. Its presence means "a legacy-history
 *    migration started and did not finish; resume from the intact legacy
 *    source". Copy-without-delete guarantees the source is still there, so no
 *    preimage needs to be retained. See W4.4 / the PII-free marker rule.
 *
 * Both parsers are pure and read-only: they never touch storage and never
 * mutate their input. The `setItem` / `removeItem` sites stay in the migration
 * itself, next to the write barriers that make them safe.
 *
 * Byte-compatibility is load-bearing: the legacy shape and its "done" semantics
 * are unchanged from the inline parser this was extracted from.
 */

import type { HistoryEntry } from "@/shared/types";

/** The legacy, PII-bearing recovery marker key. Read/cleanup only. */
export const MIGRATION_MARKER_KEY = "open3dcalc_migration_done_v2";

/** The current, value-free progress marker key (Beta5 W4.4). */
export const MIGRATION_PROGRESS_KEY = "open3dcalc_migration_progress_v2";

export type HistoryMigrationBackup = {
  type: "open3dcalc-history-v2-backup";
  source: string;
  baseEntries: HistoryEntry[];
  productsSource?: string;
};

/** The value-free progress marker payload. No record content, ever. */
export type HistoryMigrationProgress = {
  type: "open3dcalc-history-v2-progress";
  v: 1;
};

const PROGRESS_TYPE = "open3dcalc-history-v2-progress";
const PROGRESS_VERSION = 1;

/**
 * Parse a raw legacy marker value into its backup record, or `null` when the
 * value is not the legacy backup shape.
 *
 * A `null` result covers BOTH a non-backup JSON document and a non-JSON value:
 * the latter is the legacy "migration complete" marker, which callers treat as
 * "nothing to resume". Pure and read-only.
 */
export function isHistoryMigrationBackup(
  value: string,
): HistoryMigrationBackup | null {
  try {
    const parsed = JSON.parse(value) as Partial<HistoryMigrationBackup>;
    if (
      parsed.type === "open3dcalc-history-v2-backup" &&
      typeof parsed.source === "string" &&
      Array.isArray(parsed.baseEntries) &&
      (parsed.productsSource === undefined ||
        typeof parsed.productsSource === "string")
    ) {
      return parsed as HistoryMigrationBackup;
    }
  } catch {
    // A non-JSON marker is the legacy "migration complete" value.
  }
  return null;
}

/**
 * Parse a raw progress marker value, or `null` when the value is not the
 * value-free progress marker. Pure and read-only.
 */
export function isHistoryMigrationProgress(
  value: string,
): HistoryMigrationProgress | null {
  try {
    const parsed = JSON.parse(value) as Partial<HistoryMigrationProgress>;
    if (parsed.type === PROGRESS_TYPE && parsed.v === PROGRESS_VERSION) {
      return { type: PROGRESS_TYPE, v: PROGRESS_VERSION };
    }
  } catch {
    // Not the progress marker.
  }
  return null;
}

/**
 * The exact value-free payload the migration writes. Exported so the writer and
 * the parser can never disagree, and so a test can assert it holds no record
 * content.
 */
export function historyMigrationProgressValue(): string {
  return JSON.stringify({ type: PROGRESS_TYPE, v: PROGRESS_VERSION });
}
