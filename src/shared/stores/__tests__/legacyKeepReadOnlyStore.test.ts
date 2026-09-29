import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { guardedStorage } from "@/shared/lib/manifestStorage";
import type { LegacyPiiPlaintextReport } from "@/shared/lib/legacyPiiPlaintext";
import {
  LEGACY_KEEP_READONLY_KEY,
  residueSignature,
  useLegacyKeepReadOnlyStore,
} from "../legacyKeepReadOnlyStore";

/**
 * L-2 — the persisted, value-free "keep read-only" decision.
 *
 * The store must remember the answer without ever holding a record: the
 * persisted payload is a residue SIGNATURE (key names + counts) and nothing
 * else. It must also forget on `reopen()`, which is the Privacy-screen path
 * back to the choice.
 */

const CANARY = "SENTINEL-KEEP-READONLY-CANARY";

function report(entries: Array<[string, number]>): LegacyPiiPlaintextReport {
  const keys = entries.map(([key, count]) => ({
    key: key as LegacyPiiPlaintextReport["keys"][number]["key"],
    present: count > 0,
    count,
  }));
  return {
    present: keys.some((entry) => entry.present),
    total: keys.reduce((sum, entry) => sum + entry.count, 0),
    keys,
  };
}

const WITH_RESIDUE = report([
  ["open3dcalc_customers_v1", 2],
  ["open3dcalc_quotes_v1", 0],
  ["open3dcalc_history_v2", 1],
]);

beforeEach(() => {
  window.localStorage.clear();
  useLegacyKeepReadOnlyStore.setState({ signature: null });
});

afterEach(() => {
  window.localStorage.clear();
  useLegacyKeepReadOnlyStore.setState({ signature: null });
});

describe("residueSignature", () => {
  it("encodes key names and counts, never a value", () => {
    const signature = residueSignature(WITH_RESIDUE);
    expect(signature).toContain("open3dcalc_customers_v1=2");
    expect(signature).toContain("open3dcalc_quotes_v1=absent");
    expect(signature).toContain("open3dcalc_history_v2=1");
    expect(signature).not.toContain(CANARY);
  });

  it("changes when the residue changes", () => {
    expect(residueSignature(WITH_RESIDUE)).not.toBe(
      residueSignature(
        report([
          ["open3dcalc_customers_v1", 3],
          ["open3dcalc_quotes_v1", 0],
          ["open3dcalc_history_v2", 1],
        ]),
      ),
    );
  });
});

describe("useLegacyKeepReadOnlyStore", () => {
  it("persists the decision as a value-free payload", () => {
    const signature = residueSignature(WITH_RESIDUE);
    useLegacyKeepReadOnlyStore.getState().keep(signature);

    expect(useLegacyKeepReadOnlyStore.getState().signature).toBe(signature);
    const raw = window.localStorage.getItem(LEGACY_KEEP_READONLY_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string) as Record<string, unknown>;
    // ONLY the type, version and the value-free signature — nothing else.
    expect(Object.keys(parsed).sort()).toEqual(["signature", "type", "v"]);
    expect(parsed.signature).toBe(signature);
    expect(raw).not.toContain(CANARY);
  });

  it("forgets the decision on reopen", () => {
    useLegacyKeepReadOnlyStore.getState().keep(residueSignature(WITH_RESIDUE));
    useLegacyKeepReadOnlyStore.getState().reopen();

    expect(useLegacyKeepReadOnlyStore.getState().signature).toBeNull();
    expect(guardedStorage.getItem(LEGACY_KEEP_READONLY_KEY)).toBeNull();
  });
});
