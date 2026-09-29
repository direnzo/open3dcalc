/**
 * Wave 3 — no plaintext PII write is reachable from `useAppInit`.
 *
 * The three migrated keys (`open3dcalc_customers_v1`, `open3dcalc_quotes_v1`,
 * `open3dcalc_history_v2`) now live in the encrypted vault. This spec proves,
 * on a REAL startup run rather than a unit call, that the startup path adds no
 * `localStorage` entry for any of them, and that the only keys the file writes
 * are the declared recovery marker and the non-PII product key.
 *
 * It uses the real `guardardedStorage` (not the mocked one the sibling suite
 * installs) so a write that reached `localStorage` would land in the real
 * store and be observed. `localStorage` is reset between specs.
 */

import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useAppInit } from "../useAppInit";
import { useHistoryStore } from "@/shared/stores/historyStore";
import { guardedStorage } from "@/shared/lib/manifestStorage";

const MIGRATED_KEYS = [
  "open3dcalc_customers_v1",
  "open3dcalc_quotes_v1",
  "open3dcalc_history_v2",
] as const;
const RECOVERY_MARKER = "open3dcalc_migration_done_v2";
const PRODUCTS_KEY = "open3dcalc_products";

/** A legacy history array, the input the migration reads to detect work. */
const LEGACY_HISTORY = JSON.stringify([
  {
    id: "hist-1",
    timestamp: 1_700_000_000_001,
    type: "fdm",
    summary: "Peça sintética",
    totalCost: 10,
    sellPrice: 20,
    profit: 10,
    result: {
      materialCost: 1,
      energyCost: 1,
      machineCost: 1,
      hardwareCost: 1,
      consumablesCost: 1,
      laborCost: 1,
      softwareCost: 1,
      failureCost: 1,
      extrasCost: 1,
      postProcessingCost: 1,
      subtotal: 10,
      totalCost: 10,
      sellPrice: 20,
      profit: 10,
      marketplaceFee: 0,
      taxAmount: 0,
      costPerGram: 0.2,
      costPerUnit: 10,
      unitWeight: 50,
      estimatedPrintTime: 1,
      targetMarginPercent: 50,
      breakEvenPrice: 10,
      actualMargin: 50,
      carbonFootprintGrams: 1,
    },
    snapshot: null,
  },
]);

describe("useAppInit — no plaintext PII write on startup", () => {
  let setSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    window.localStorage.clear();
    useHistoryStore.setState({ entries: [] });
    // Audit every write through the real storage facade.
    setSpy = vi.spyOn(guardedStorage, "setItem");
  });

  afterEach(() => {
    setSpy.mockRestore();
    window.localStorage.clear();
    useHistoryStore.setState({ entries: [] });
  });

  it("adds no localStorage entry for any migrated PII key during startup", async () => {
    // Arm the migration with legacy input under the history key (read-only).
    window.localStorage.setItem("open3dcalc_history_v2", LEGACY_HISTORY);

    renderHook(() => useAppInit(vi.fn()));
    // Let the fire-and-forget migration settle on the legacy path.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    for (const key of MIGRATED_KEYS) {
      // The customer/quote keys must never be written at all. The history key
      // may only hold the value this spec seeded as read-only input.
      if (key === "open3dcalc_history_v2") {
        expect(window.localStorage.getItem(key)).toBe(LEGACY_HISTORY);
      } else {
        expect(window.localStorage.getItem(key)).toBeNull();
      }
    }

    // Structural half: the ONLY keys the startup path writes are the declared
    // recovery marker and the non-PII product key.
    const writtenKeys = setSpy.mock.calls.map(
      (call: [key: string, value: string]) => call[0],
    );
    const unexpected = writtenKeys.filter(
      (key: string) => key !== RECOVERY_MARKER && key !== PRODUCTS_KEY,
    );
    expect(unexpected).toEqual([]);
    expect(writtenKeys).not.toContain("open3dcalc_customers_v1");
    expect(writtenKeys).not.toContain("open3dcalc_quotes_v1");
    expect(writtenKeys).not.toContain("open3dcalc_history_v2");
  });

  it("writes no migrated PII key even when there is no legacy work to do", async () => {
    renderHook(() => useAppInit(vi.fn()));
    await Promise.resolve();
    await Promise.resolve();

    const writtenKeys = setSpy.mock.calls.map(
      (call: [key: string, value: string]) => call[0],
    );
    for (const key of MIGRATED_KEYS) {
      expect(writtenKeys).not.toContain(key);
      expect(window.localStorage.getItem(key)).toBeNull();
    }
  });
});
