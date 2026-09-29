/**
 * Read-only parser for the v2 history-migration recovery marker (T4.1).
 *
 * The marker (`open3dcalc_migration_done_v2`) is a durable, PII-bearing backup
 * written before the legacy-history import starts, so an interrupted startup
 * can resume (SPEC-01: class user_content, pii true, encrypted_at_rest). This
 * module owns the ONLY read path over that value: it parses and validates the
 * backup shape and never writes. The `setItem` / `removeItem` sites stay in the
 * migration itself, next to the write barriers that make them safe.
 *
 * Byte-compatibility is load-bearing: the shape and the legacy-done semantics
 * are unchanged from the inline parser this was extracted from.
 */

import type { HistoryEntry } from "@/shared/types";

/** The durable recovery marker key (SPEC-01). */
export const MIGRATION_MARKER_KEY = "open3dcalc_migration_done_v2";

export type HistoryMigrationBackup = {
  type: "open3dcalc-history-v2-backup";
  source: string;
  baseEntries: HistoryEntry[];
  productsSource?: string;
};

/**
 * Parse a raw marker value into its backup record, or `null` when absent.
 *
 * A `null` result covers BOTH a non-backup JSON document and a non-JSON value:
 * the latter is the legacy "migration complete" marker, which callers treat as
 * "nothing to resume". Pure and read-only — no storage access, no mutation of
 * the input.
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
