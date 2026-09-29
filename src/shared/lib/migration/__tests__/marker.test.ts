import { afterEach, describe, expect, it, vi } from "vitest";
import {
  MIGRATION_MARKER_KEY,
  isHistoryMigrationBackup,
} from "@/shared/lib/migration/marker";

/**
 * T4.1 — the recovery-marker parser is a pure, read-only unit.
 *
 * The marker is a PII-bearing durable backup; these specs pin the exact shape
 * the migration writes today, the legacy "done" semantics, and the guarantee
 * that reading it never writes.
 */

const VALID_BACKUP = {
  type: "open3dcalc-history-v2-backup",
  source: JSON.stringify([{ id: "legacy-1", summary: "Peça antiga" }]),
  baseEntries: [],
};

describe("migration marker parser (read-only)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exports the marker key literal the migration uses", () => {
    expect(MIGRATION_MARKER_KEY).toBe("open3dcalc_migration_done_v2");
  });

  it("parses a valid JSON backup marker byte-compatibly", () => {
    const raw = JSON.stringify(VALID_BACKUP);
    expect(isHistoryMigrationBackup(raw)).toEqual(VALID_BACKUP);
  });

  it("parses a valid backup carrying an optional productsSource", () => {
    const withProducts = {
      ...VALID_BACKUP,
      productsSource: JSON.stringify([{ id: "produto-1" }]),
    };
    expect(isHistoryMigrationBackup(JSON.stringify(withProducts))).toEqual(
      withProducts,
    );
  });

  it("preserves baseEntries already persisted in the marker", () => {
    const withEntries = {
      ...VALID_BACKUP,
      baseEntries: [{ id: "base-1", timestamp: 1_700_000_000_001 }],
    };
    expect(isHistoryMigrationBackup(JSON.stringify(withEntries))).toEqual(
      withEntries,
    );
  });

  it.each([
    [
      "missing source",
      { type: "open3dcalc-history-v2-backup", baseEntries: [] },
    ],
    [
      "missing baseEntries",
      { type: "open3dcalc-history-v2-backup", source: "[]" },
    ],
    [
      "baseEntries is not an array",
      { type: "open3dcalc-history-v2-backup", source: "[]", baseEntries: {} },
    ],
    [
      "source is not a string",
      { type: "open3dcalc-history-v2-backup", source: 7, baseEntries: [] },
    ],
    [
      "unrecognized type",
      { type: "some-other-backup", source: "[]", baseEntries: [] },
    ],
    ["productsSource is not a string", { ...VALID_BACKUP, productsSource: 7 }],
  ])("rejects an incomplete/corrupt backup (%s)", (_label, value) => {
    expect(isHistoryMigrationBackup(JSON.stringify(value))).toBeNull();
  });

  it.each([
    ["object without the backup type", { hello: "world" }],
    ["array", []],
    ["null document", null],
    ["empty string", ""],
  ])("rejects a non-backup JSON document (%s)", (_label, value) => {
    expect(isHistoryMigrationBackup(JSON.stringify(value))).toBeNull();
  });

  it.each([
    ["legacy 'done' flag", "done"],
    ["legacy numeric marker", "1"],
    ["plain non-JSON text", "migration-complete"],
  ])(
    "treats a non-JSON marker as the legacy done value, returning null (%s)",
    (_label, raw) => {
      expect(isHistoryMigrationBackup(raw)).toBeNull();
    },
  );

  it("never writes: the parser is read-only", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const removeItem = vi.spyOn(Storage.prototype, "removeItem");
    const clear = vi.spyOn(Storage.prototype, "clear");

    isHistoryMigrationBackup(JSON.stringify(VALID_BACKUP));
    isHistoryMigrationBackup("done");

    expect(setItem).not.toHaveBeenCalled();
    expect(removeItem).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();
  });
});
