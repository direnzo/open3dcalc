/**
 * Residue source for the legacy-PII surfaces, desktop-aware.
 *
 * The web residue lives in `localStorage` and is read SYNCHRONOUSLY. On desktop
 * the persistence bridge never hydrates the three migrated PII keys, so the
 * residue is in SQLite and only reachable asynchronously through the read-only
 * `privacy:legacy-rows` IPC. A surface that only read `localStorage` would show
 * nothing on desktop: no prompt, and no residue in the disclosure panel — which
 * is exactly the "retained but invisible" defect the re-home closes.
 *
 * These hooks bridge the two: they start from the sync `localStorage` reader
 * (so the web behaviour and every existing test are unchanged) and, when a
 * desktop source answers, merge the fetched values in. The merge NEVER writes
 * anything and never persists PII — it only feeds detection and the re-home's
 * read path.
 */

import { useEffect, useMemo, useState } from "react";
import {
  detectLegacyPlaintextPii,
  type LegacyPiiPlaintextReport,
} from "@/shared/lib/legacyPiiPlaintext";
import type { LegacyPiiPlaintextKey } from "@/shared/lib/legacyPiiPlaintext";
import { guardedStorage } from "@/shared/lib/manifestStorage";
import {
  fetchDesktopLegacyPiiRows,
  type LegacyPiiRowMap,
} from "@/shared/lib/migration/desktopLegacyRows";

/** A sync reader of a raw storage value, the shape the detection half takes. */
export type LegacyPiiRead = (key: string) => string | null;

/**
 * Merge the desktop rows over a local reader.
 *
 * A desktop value wins for a key it carries; every other key falls through to
 * the local reader. `null` rows means "no desktop source", so the local reader
 * is returned unchanged.
 */
export function mergeLegacyPiiRead(
  localRead: LegacyPiiRead,
  rows: LegacyPiiRowMap | null,
): LegacyPiiRead {
  if (!rows) return localRead;
  return (key) => rows[key as LegacyPiiPlaintextKey] ?? localRead(key);
}

/**
 * Fetch the desktop residue once per mount. Returns `null` until it answers (and
 * forever on the web), so the first render is the sync-only view.
 */
function useDesktopLegacyRows(enabled: boolean): LegacyPiiRowMap | null {
  const [rows, setRows] = useState<LegacyPiiRowMap | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    void fetchDesktopLegacyPiiRows().then((fetched) => {
      if (!cancelled && fetched) setRows(fetched);
    });
    return () => {
      cancelled = true;
    };
  }, [enabled]);
  return rows;
}

/**
 * The reader a residue surface should use right now: the desktop rows merged
 * over `localStorage`. Stable across renders until the desktop rows arrive.
 */
export function useLegacyPiiRead(enabled = true): LegacyPiiRead {
  const rows = useDesktopLegacyRows(enabled);
  return useMemo(
    () => mergeLegacyPiiRead((key) => guardedStorage.getItem(key), rows),
    [rows],
  );
}

/** The value-free residue report, desktop-aware. */
export function useLegacyPiiResidue(enabled = true): LegacyPiiPlaintextReport {
  const read = useLegacyPiiRead(enabled);
  return useMemo(
    () => detectLegacyPlaintextPii(enabled ? read : undefined),
    [enabled, read],
  );
}
