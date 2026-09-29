/**
 * The desktop-aware residue source used by the migration prompt and the residue
 * disclosure panel.
 *
 * On desktop the persistence bridge never hydrates the three migrated PII keys,
 * so a prompt that only read `localStorage` would never open and the disclosure
 * panel would always say "no residue" — the retained-but-invisible defect. These
 * tests pin that the hook merges the read-only IPC rows over `localStorage`, that
 * the web path is unchanged, and that a refused IPC read degrades to the local
 * view rather than throwing.
 */

import { afterEach, describe, expect, it } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

import {
  mergeLegacyPiiRead,
  useLegacyPiiResidue,
} from "@/shared/hooks/useLegacyPiiResidue";
import {
  fetchDesktopLegacyPiiRows,
  toLegacyPiiRowMap,
  type LegacyPiiRowMap,
} from "@/shared/lib/migration/desktopLegacyRows";

const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const HISTORY = "open3dcalc_history_v2";

function installLegacyRows(
  rows: Array<{ key: string; value: string | null; status: string }>,
): void {
  (window as unknown as { electronAPI: unknown }).electronAPI = {
    privacy: {
      legacyRows: async () => ({
        scannedAt: new Date().toISOString(),
        rows,
      }),
    },
  };
}

afterEach(() => {
  delete (window as { electronAPI?: unknown }).electronAPI;
  window.localStorage.clear();
});

describe("mergeLegacyPiiRead", () => {
  it("returns the local reader unchanged when there is no desktop source", () => {
    const local = (): string | null => "local";
    expect(mergeLegacyPiiRead(local, null)).toBe(local);
  });

  it("prefers a desktop value and falls through otherwise", () => {
    const rows: LegacyPiiRowMap = { [CUSTOMERS]: "desktop" };
    const read = mergeLegacyPiiRead(() => "local", rows);
    expect(read(CUSTOMERS)).toBe("desktop");
    expect(read(QUOTES)).toBe("local");
  });
});

describe("toLegacyPiiRowMap", () => {
  it("keeps only the rows that carry a legacy value", () => {
    const map = toLegacyPiiRowMap({
      scannedAt: new Date().toISOString(),
      rows: [
        { key: CUSTOMERS, value: "legacy", status: "legacy_plaintext" },
        { key: QUOTES, value: null, status: "already_encrypted" },
        { key: HISTORY, value: null, status: "absent" },
      ],
    });
    expect(map).toEqual({ [CUSTOMERS]: "legacy" });
  });
});

describe("fetchDesktopLegacyPiiRows", () => {
  it("resolves to null without a desktop bridge", async () => {
    await expect(fetchDesktopLegacyPiiRows()).resolves.toBeNull();
  });

  it("resolves to null when the bridge lacks the read-only reader", async () => {
    (window as unknown as { electronAPI: unknown }).electronAPI = {
      privacy: {},
    };
    await expect(fetchDesktopLegacyPiiRows()).resolves.toBeNull();
  });
});

describe("useLegacyPiiResidue", () => {
  it("reads only localStorage when there is no desktop bridge", () => {
    window.localStorage.setItem(
      CUSTOMERS,
      JSON.stringify({ state: { customers: [{ id: "a" }, { id: "b" }] } }),
    );
    const { result } = renderHook(() => useLegacyPiiResidue());
    expect(result.current.present).toBe(true);
    expect(result.current.total).toBe(2);
  });

  it("merges the desktop rows over localStorage", async () => {
    installLegacyRows([
      {
        key: CUSTOMERS,
        value: JSON.stringify({ state: { customers: [{ id: "a" }] } }),
        status: "legacy_plaintext",
      },
      {
        key: QUOTES,
        value: JSON.stringify({ state: { quotes: [{ id: "q" }] } }),
        status: "legacy_plaintext",
      },
    ]);

    const { result } = renderHook(() => useLegacyPiiResidue());

    await waitFor(() => expect(result.current.present).toBe(true));
    expect([...result.current.keys].map((k) => k.key)).toEqual([
      CUSTOMERS,
      QUOTES,
      "open3dcalc_history_v2",
    ]);
    expect(result.current.total).toBe(2);
  });

  it("degrades to the local view when the IPC read refuses (no throw)", async () => {
    (window as unknown as { electronAPI: unknown }).electronAPI = {
      privacy: {
        legacyRows: async () => Promise.reject(new Error("refused")),
      },
    };
    const { result } = renderHook(() => useLegacyPiiResidue());
    await waitFor(() => expect(result.current.present).toBe(false));
  });
});
