/**
 * Renderer-side source of the DESKTOP legacy PII residue (Beta5 desktop
 * re-home).
 *
 * The web re-home reads the residue from `localStorage`. On desktop the
 * `persistence-bridge` deliberately never hydrates the three migrated PII keys,
 * so `localStorage` holds none of it: the residue lives in SQLite `storage`
 * rows and reaches the renderer through the READ-ONLY `privacy:legacy-rows` IPC
 * (see `electron/legacyRows.ts`).
 *
 * This module is the thin adapter between that IPC contract and the re-home's
 * `read` function. It is deliberately NOT where PII is written: it returns the
 * values in memory so the caller can copy them into the encrypted vault. The
 * values are never persisted here — the persistence bridge refuses these keys,
 * and the vault is the only destination.
 *
 * A refused or failed IPC read resolves to `null` ("no desktop source"), never a
 * throw: a storage problem must not turn an unlock into an error, and the caller
 * then falls back to the (empty) `localStorage` source and reports honestly.
 */

import type { LegacyPiiPlaintextKey } from "@/shared/lib/legacyPiiPlaintext";
import type { LegacyPiiRowsReport } from "../../../../electron/legacyRows.js";

/** Key NAME → raw legacy value, for the declared keys that have one. */
export type LegacyPiiRowMap = Partial<Record<LegacyPiiPlaintextKey, string>>;

/**
 * Map a `privacy:legacy-rows` report to the value map the re-home reads.
 *
 * Only rows that carry a value (`legacy_plaintext`) are kept; an
 * `already_encrypted` or `absent` row contributes nothing, so the merge can
 * never treat a ciphertext as residue.
 */
export function toLegacyPiiRowMap(
  report: LegacyPiiRowsReport,
): LegacyPiiRowMap {
  const map: LegacyPiiRowMap = {};
  for (const row of report.rows) {
    if (row.value !== null) map[row.key] = row.value;
  }
  return map;
}

/**
 * Fetch the desktop legacy rows over IPC, or `null` when there is no desktop
 * source (not Electron, the bridge lacks the method, or the read refused).
 */
export async function fetchDesktopLegacyPiiRows(): Promise<LegacyPiiRowMap | null> {
  if (typeof window === "undefined") return null;
  const privacy = window.electronAPI?.privacy;
  if (typeof privacy?.legacyRows !== "function") return null;
  try {
    return toLegacyPiiRowMap(await privacy.legacyRows());
  } catch {
    return null;
  }
}
