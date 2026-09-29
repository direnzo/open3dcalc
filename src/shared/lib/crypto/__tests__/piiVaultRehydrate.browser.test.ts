/**
 * W6 — unlock + rehydrate restore the EXACT persisted state, in a real browser.
 *
 * `rehydratePiiStores()` is the path that decides whether a user's customers
 * come back after a reload, and it is the path the Wave-5 vault-ordering fix
 * (squash-merged into `main` as `1b7b885`) hardened: a read that raced an
 * in-flight write could return the stale record, so the gate reported
 * `hydrated` while the store body came back empty. The jsdom suite covers that
 * with a store double; here the whole lifecycle runs against Chromium's own
 * IndexedDB and Web Crypto, through the same primitives production uses:
 * `gatedPiiPersistStorage` → a real zustand `persist` store → `skipHydration` →
 * `unlockPiiStoresAndRehydrate` → `rehydrate()`.
 *
 * The reload is simulated the honest way: the module's held key is zeroized and
 * its runtime state reset, then a BRAND NEW store instance (initial state, no
 * hydration) is registered and rehydrated. A fresh instance cannot pass by
 * already holding the state in memory — only a real read from the vault can.
 *
 * Synthetic fixtures only, never real PII. Real Web Crypto, no crypto mocks
 * (TEST-MATRIX §0).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createStore } from "zustand/vanilla";
import { persist } from "zustand/middleware";
import {
  PII_STORE_KEY,
  configurePiiStoreRuntime,
  didPiiWritesCommit,
  gatedPiiPersistStorage,
  getLastPiiWriteRefusal,
  getPiiStoreHydrationStatus,
  installPiiStoreRuntimeEnvironment,
  readPiiPersistedRecord,
  registerPiiPersistStore,
  resetPiiStoreHydrationForTests,
  unlockPiiStoresAndRehydrate,
  whenPiiWritesSettled,
} from "@/shared/lib/crypto/piiStoreHydration";
import {
  lockAllPiiStores,
  resetPiiStoreRuntimeForTests,
} from "@/shared/lib/crypto/piiStore";
import { resetPiiStoreGateForTests } from "@/shared/lib/crypto/piiStoreCapability";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import {
  createPiiVaultBrowserHarness,
  type PiiVaultBrowserHarness,
} from "@/shared/lib/crypto/__tests__/piiVaultBrowserHarness";

const PASS = "senha-sintetica-do-harness-browser";
const KEY = PII_STORE_KEY.customers;
const SEEDED = [
  "Cliente-Sintetico-Um-1123",
  "Cliente-Sintetico-Dois-4456",
  "Cliente-Sintetico-Tres-7789",
];

interface CustomerState {
  customers: string[];
}

/**
 * A real zustand store over the vault, arranged exactly like the shipped ones:
 * the gated storage, and `skipHydration` because a store must never hydrate at
 * construction, before a passphrase exists.
 */
function createCustomerStore() {
  return createStore<CustomerState>()(
    // The return type is annotated so `[]` is a `string[]` and not `never[]`,
    // and a fresh array is built per call: two instances in one spec must not
    // share state through the initializer.
    persist((): CustomerState => ({ customers: [] }), {
      name: KEY,
      version: 1,
      skipHydration: true,
      storage: gatedPiiPersistStorage<CustomerState>(KEY),
    }),
  );
}

/** Lock everything and forget the process's memory, as a page teardown does. */
function simulateReload(): void {
  lockAllPiiStores();
  resetPiiStoreRuntimeForTests();
  resetPiiStoreHydrationForTests();
  zeroizeSessionPassphrase();
  resetPiiStoreGateForTests();
}

describe("W6 — unlock + rehydrate restore the exact persisted state", () => {
  let harness: PiiVaultBrowserHarness;

  beforeEach(async () => {
    harness = createPiiVaultBrowserHarness("rehydrate");
    simulateReload();
    await harness.clear();
  });

  afterEach(() => {
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  it("restores a fresh store instance from the sealed record, without rewriting it", async () => {
    // ---- Seed: a first instance, unlocked and hydrated, accumulates data. ----
    configurePiiStoreRuntime({ indexedDb: harness.indexedDb });
    installPiiStoreRuntimeEnvironment();
    const seeded = createCustomerStore();
    registerPiiPersistStore(KEY, seeded.persist);

    await unlockPiiStoresAndRehydrate(PASS, { indexedDb: harness.indexedDb });
    expect(getPiiStoreHydrationStatus(KEY)).toBe("hydrated");

    seeded.setState({ customers: SEEDED });
    await whenPiiWritesSettled();
    // "Settled" includes "rejected"; durability needs the stronger answer.
    await expect(didPiiWritesCommit()).resolves.toBe(true);

    const persisted = await readPiiPersistedRecord(KEY);
    expect(persisted).toBe(
      JSON.stringify({ state: { customers: SEEDED }, version: 1 }),
    );
    const rawBefore = await harness.rawRecord(KEY);
    expect(rawBefore).not.toBeNull();
    // At rest, in the browser's store: no plaintext.
    for (const name of SEEDED) expect(rawBefore).not.toContain(name);

    // ---- Reload: the key is gone and no module remembers the store. ----
    simulateReload();
    configurePiiStoreRuntime({ indexedDb: harness.indexedDb });
    installPiiStoreRuntimeEnvironment();

    const reloaded = createCustomerStore();
    registerPiiPersistStore(KEY, reloaded.persist);

    // Nothing hydrated it: it holds its initial state, and the gate must refuse
    // to write that empty state over the real record.
    expect(reloaded.getState().customers).toEqual([]);
    expect(getPiiStoreHydrationStatus(KEY)).toBe("idle");

    reloaded.setState({ customers: ["Nao-Deve-Sobrescrever-0000"] });
    await whenPiiWritesSettled();
    // `profile_locked` and not `capability_unknown`: the real browser environment
    // IS capable, and the only thing missing is the derived key.
    expect(getLastPiiWriteRefusal()).toEqual({
      key: KEY,
      reason: "profile_locked",
    });
    // The refused write is a refused write, not an erased record.
    expect(await harness.rawRecord(KEY)).toBe(rawBefore);

    // ---- Unlock again and rehydrate the fresh instance. ----
    await unlockPiiStoresAndRehydrate(PASS, { indexedDb: harness.indexedDb });

    expect(getPiiStoreHydrationStatus(KEY)).toBe("hydrated");
    expect(reloaded.getState().customers).toEqual(SEEDED);
    await expect(readPiiPersistedRecord(KEY)).resolves.toBe(persisted);
    // Byte-identical: rehydration READ the record, it did not re-seal it.
    expect(await harness.rawRecord(KEY)).toBe(rawBefore);
    // A successful unlock clears the refusal the UI was showing.
    expect(getLastPiiWriteRefusal()).toBeNull();
  });

  it("reports the refusal instead of handing back an empty store while locked", async () => {
    configurePiiStoreRuntime({ indexedDb: harness.indexedDb });
    installPiiStoreRuntimeEnvironment();
    const store = createCustomerStore();
    registerPiiPersistStore(KEY, store.persist);

    // Locked: `readPiiPersistedRecord` is fail-closed, so a caller that treats
    // "no value" as "no data" cannot erase the user's records by accident.
    await expect(readPiiPersistedRecord(KEY)).resolves.toBeNull();
    expect(await harness.rawRecords()).toEqual([]);

    await unlockPiiStoresAndRehydrate(PASS, { indexedDb: harness.indexedDb });
    store.setState({ customers: SEEDED });
    await whenPiiWritesSettled();

    simulateReload();
    configurePiiStoreRuntime({ indexedDb: harness.indexedDb });
    installPiiStoreRuntimeEnvironment();

    // Locked again. The record EXISTS, and the locked read still reports null
    // rather than the plaintext it cannot open.
    await expect(readPiiPersistedRecord(KEY)).resolves.toBeNull();
    expect(await harness.rawRecord(KEY)).not.toBeNull();
  });
});
