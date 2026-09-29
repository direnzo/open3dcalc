/**
 * Legacy plaintext PII detection (ADR-002 §2.2 quarantine).
 *
 * After the three browser PII stores migrate onto the encrypted vault, any
 * plaintext still sitting under their old `localStorage` keys is legacy residue:
 * data written before the vault existed. ADR-002 §2.2 requires that residue to
 * be detected and surfaced to the user, never silently migrated, never silently
 * deleted, and never implicitly accepted.
 *
 * This module is ONLY the detection half. It answers "is there legacy plaintext
 * PII, and how much?", so the migration/keep-read-only/export/delete choice can
 * render without doing any discovery of its own. It deliberately does not
 * implement the choice flow or a migration state machine — those are a later
 * wave with their own encrypted preimage and consent surface.
 *
 * ## Why reading plaintext is allowed here
 *
 * The fail-closed rule ("PII is neither read nor written when the vault is
 * unavailable") governs the VAULT path. Legacy detection is the explicit
 * exception: its whole purpose is to let a user see what residue exists before
 * choosing what to do with it, so it must be able to read the plaintext residue
 * even while the vault is locked. It reads COUNTS only — never record contents —
 * and returns nothing that can be rendered as PII.
 */

import { guardedStorage } from "./manifestStorage.js";

/** The three plaintext `localStorage` keys the vault replaces. */
export const LEGACY_PII_PLAINTEXT_KEYS = [
  "open3dcalc_customers_v1",
  "open3dcalc_quotes_v1",
  "open3dcalc_history_v2",
] as const;

export type LegacyPiiPlaintextKey = (typeof LEGACY_PII_PLAINTEXT_KEYS)[number];

export interface LegacyPiiPlaintextKeyReport {
  key: LegacyPiiPlaintextKey;
  /** True when the key holds anything at all. */
  present: boolean;
  /** Number of records found, or 0 when present but unrecognizable. */
  count: number;
}

export interface LegacyPiiPlaintextReport {
  /** True when at least one of the three keys holds data. */
  present: boolean;
  /** Sum of the per-key counts. */
  total: number;
  keys: LegacyPiiPlaintextKeyReport[];
}

/** The array field a zustand persist wrapper holds for each key. */
const RECORD_FIELD: Record<LegacyPiiPlaintextKey, string> = {
  open3dcalc_customers_v1: "customers",
  open3dcalc_quotes_v1: "quotes",
  open3dcalc_history_v2: "entries",
};

function countRecords(raw: string, field: string): number {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return 0;
  }
  // A zustand persist wrapper is `{ state: {...}, version: N }`. A raw array is
  // the pre-zustand shape the same key held. Anything else is unrecognizable.
  if (Array.isArray(parsed)) return parsed.length;
  if (parsed && typeof parsed === "object") {
    const state = (parsed as { state?: unknown }).state;
    if (state && typeof state === "object") {
      const records = (state as Record<string, unknown>)[field];
      if (Array.isArray(records)) return records.length;
    }
  }
  return 0;
}

/**
 * Detect legacy plaintext PII under the three replaced keys.
 *
 * `read` is injectable so a test can exercise the counting without a DOM; the
 * default reads through the manifest-gated `localStorage` facade, so an
 * undeclared key is denied rather than read.
 */
export function detectLegacyPlaintextPii(
  read: (key: string) => string | null = (key) => guardedStorage.getItem(key),
): LegacyPiiPlaintextReport {
  const keys = LEGACY_PII_PLAINTEXT_KEYS.map((key) => {
    const raw = read(key);
    const present = raw !== null;
    return {
      key,
      present,
      count: present ? countRecords(raw, RECORD_FIELD[key]) : 0,
    };
  });

  return {
    present: keys.some((entry) => entry.present),
    total: keys.reduce((sum, entry) => sum + entry.count, 0),
    keys,
  };
}
