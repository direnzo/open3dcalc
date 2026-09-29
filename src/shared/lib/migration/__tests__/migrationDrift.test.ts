import { describe, expect, it } from "vitest";

import {
  LEGACY_HISTORY_SOURCE_KEY,
  LEGACY_PRODUCTS_SOURCE_KEY,
  MIGRATION_FINGERPRINT_KEY,
  detectMigrationDrift,
  migrationFingerprintValue,
  readMigrationFingerprint,
} from "../migrationDrift";

/**
 * T4.6 — value-free post-commit drift detection.
 *
 * The detector answers only "did the legacy source change since the migration
 * committed?" from two COUNTS. It must never read or return a record value, and
 * it must never reconcile: a drift is disclosed, not fixed.
 */

const CANARY = "SENTINEL-DRIFT-CANARY";

function readMap(
  entries: Record<string, string | null>,
): (key: string) => string | null {
  return (key: string) => entries[key] ?? null;
}

/** A legacy source array with `count` records, each carrying a leak canary. */
function source(count: number): string {
  return JSON.stringify(
    Array.from({ length: count }, (_, i) => ({ id: `row-${i}`, name: CANARY })),
  );
}

describe("readMigrationFingerprint", () => {
  it("returns null when no fingerprint is stored", () => {
    expect(readMigrationFingerprint(readMap({}))).toBeNull();
  });

  it("parses the value-free payload", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(2, null),
    });
    expect(readMigrationFingerprint(read)).toEqual({
      history: 2,
      products: null,
    });
  });

  it("reads a malformed value as no fingerprint", () => {
    const read = readMap({ [MIGRATION_FINGERPRINT_KEY]: "not-json" });
    expect(readMigrationFingerprint(read)).toBeNull();
  });
});

describe("detectMigrationDrift", () => {
  it("reports no drift when there is no fingerprint", () => {
    expect(detectMigrationDrift(readMap({}))).toEqual({
      detected: false,
      sources: [],
    });
  });

  it("reports no drift when the source is unchanged", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(1, null),
      [LEGACY_HISTORY_SOURCE_KEY]: source(1),
    });
    expect(detectMigrationDrift(read)).toEqual({
      detected: false,
      sources: [],
    });
  });

  it("detects a changed history source", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(1, null),
      [LEGACY_HISTORY_SOURCE_KEY]: source(2),
    });
    expect(detectMigrationDrift(read)).toEqual({
      detected: true,
      sources: [LEGACY_HISTORY_SOURCE_KEY],
    });
  });

  it("detects a product source that reappeared after being dropped", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(1, null),
      [LEGACY_HISTORY_SOURCE_KEY]: source(1),
      [LEGACY_PRODUCTS_SOURCE_KEY]: source(1),
    });
    expect(detectMigrationDrift(read)).toEqual({
      detected: true,
      sources: [LEGACY_PRODUCTS_SOURCE_KEY],
    });
  });

  it("treats a retained product count as matching when unchanged", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(0, 3),
      [LEGACY_PRODUCTS_SOURCE_KEY]: source(3),
    });
    expect(detectMigrationDrift(read).detected).toBe(false);
  });

  it("never returns a record value", () => {
    const read = readMap({
      [MIGRATION_FINGERPRINT_KEY]: migrationFingerprintValue(1, null),
      [LEGACY_HISTORY_SOURCE_KEY]: source(2),
      [LEGACY_PRODUCTS_SOURCE_KEY]: source(1),
    });
    expect(JSON.stringify(detectMigrationDrift(read))).not.toContain(CANARY);
  });
});
