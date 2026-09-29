/**
 * Wave 3 (HIGH-3) — re-home of legacy plaintext browser PII into the vault.
 *
 * A profile whose customers/quotes/history still sit in plaintext
 * `localStorage` has, after Wave 3, a locked (and empty) vault: the stores set
 * `skipHydration: true`, so after unlock they hydrate from an empty vault and
 * render EMPTY surfaces while the real data stays stranded in plaintext.
 *
 * `migrateLegacyPlaintextPiiToVault()` is the WEB remediation: with an explicit
 * migration consent and a hydrated vault, it reads the plaintext residue, writes
 * it into the ENCRYPTED destination through the hydrated stores, VERIFIES the
 * value by reading the sealed record back, and only then records a value-free
 * completion marker. It is copy-without-delete: the plaintext source stays and
 * is disclosed.
 *
 * Real Web Crypto, the real vault gate, a fake IndexedDB — no crypto mocks
 * (TEST-MATRIX §0). Synthetic fixtures only.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  LEGACY_PII_REHOME_MARKER_KEY,
  migrateLegacyPlaintextPiiToVault,
} from "@/shared/lib/migration/legacyPiiRehome";
import { LEGACY_PII_PLAINTEXT_KEYS } from "@/shared/lib/legacyPiiPlaintext";
import { useConsentStore } from "@/shared/stores/consentStore";
import { useCustomerStore } from "@/shared/stores/customerStore";
import { useQuoteStore } from "@/shared/stores/quoteStore";
import { useHistoryStore } from "@/shared/stores/historyStore";
import {
  configurePiiStoreRuntime,
  readPiiPersistedRecord,
  resetPiiStoreHydrationForTests,
  unlockPiiStoresAndRehydrate,
  whenPiiWritesSettled,
} from "@/shared/lib/crypto/piiStoreHydration";
import {
  lockAllPiiStores,
  resetPiiStoreRuntimeForTests,
} from "@/shared/lib/crypto/piiStore";
import {
  resetPiiStoreGateForTests,
  setPiiPersistenceDeclined,
  setPiiStoreEnvironment,
} from "@/shared/lib/crypto/piiStoreCapability";
import { setDemoPersistenceSuppressed } from "@/shared/lib/manifestStorage";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import { PII_STORE_ENVIRONMENT } from "@/shared/lib/crypto/__tests__/piiStoreFixtures";
import {
  createFakeIndexedDb,
  type FakeIndexedDb,
} from "@/shared/test/fakeIndexedDb";
import type { Customer, HistoryEntry, Quote } from "@/shared/types";

const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const HISTORY = "open3dcalc_history_v2";
const PASS = "senha-sintetica-rehome-4242";

const CUSTOMER_FIXTURES = [
  {
    id: "legacy_cust_1",
    name: "Ana Síntética",
    company: "Ana Ltda",
    email: "ana@example.com",
    phone: "11999990000",
    address: "Rua A, 1",
    notes: "primeira",
    createdAt: 1_700_000_000_001,
    updatedAt: 1_700_000_000_001,
    quoteCount: 2,
  },
  {
    id: "legacy_cust_2",
    name: "Bruno Sintético",
    company: "Bruno ME",
    email: "bruno@example.com",
    phone: "11999990001",
    address: "Rua B, 2",
    notes: "segunda",
    createdAt: 1_700_000_000_002,
    updatedAt: 1_700_000_000_002,
    quoteCount: 0,
  },
];

const QUOTE_FIXTURE = {
  id: "legacy_quote_1",
  number: 7,
  title: "Orçamento Sintético",
  customerId: "legacy_cust_1",
  customerSnapshot: undefined,
  items: [],
  globalDiscountPercent: 5,
  subtotal: 0,
  discountAmount: 0,
  total: 0,
  status: "draft" as const,
  validUntil: "2026-12-31",
  paymentTerms: "30 dias",
  deliveryEstimate: "5 dias",
  footerNote: undefined,
  createdAt: 1_700_000_000_010,
  updatedAt: 1_700_000_000_010,
};

function historyFixture(id: string, timestamp: number): HistoryEntry {
  return {
    id,
    timestamp,
    type: "fdm",
    name: id,
    summary: "synthetic",
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
  } as HistoryEntry;
}

const HISTORY_FIXTURES = [
  historyFixture("legacy_hist_2", 1_700_000_000_202),
  historyFixture("legacy_hist_1", 1_700_000_000_101),
];

/** Write a zustand-wrapper legacy residue under one of the three keys. */
function seedLegacyWrapper(
  key: string,
  field: string,
  records: unknown[],
): void {
  window.localStorage.setItem(
    key,
    JSON.stringify({ state: { [field]: records }, version: 1 }),
  );
}

function seedAllResidue(): void {
  seedLegacyWrapper(CUSTOMERS, "customers", CUSTOMER_FIXTURES);
  seedLegacyWrapper(QUOTES, "quotes", [QUOTE_FIXTURE]);
  seedLegacyWrapper(HISTORY, "entries", HISTORY_FIXTURES);
}

async function drainWrites(): Promise<void> {
  await whenPiiWritesSettled();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await whenPiiWritesSettled();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("Wave 3 (HIGH-3) — migrateLegacyPlaintextPiiToVault", () => {
  let idb: FakeIndexedDb;
  const options = () => ({
    indexedDb: idb.factory,
    environment: PII_STORE_ENVIRONMENT,
  });

  function resetAll(): void {
    resetPiiStoreGateForTests();
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    zeroizeSessionPassphrase();
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    window.localStorage.clear();

    useCustomerStore.setState({ customers: [], searchQuery: "" });
    useQuoteStore.setState({
      quotes: [],
      nextNumber: 1,
      searchQuery: "",
      statusFilter: "all",
    });
    useHistoryStore.setState({
      entries: [],
      search: "",
      sortBy: "date",
      sortOrder: "desc",
      filterType: "all",
      dateFrom: null,
      dateTo: null,
    });
    useConsentStore.setState({
      privacyBannerDismissed: false,
      consentGiven: false,
      consentDate: null,
      receipt: null,
      receiptDigest: null,
      withdrawnReceipts: [],
      migrationConsentGiven: false,
      migrationConsentDate: null,
      migrationReceipt: null,
      migrationReceiptDigest: null,
      withdrawnMigrationReceipts: [],
    });
  }

  async function unlockVault(): Promise<void> {
    await unlockPiiStoresAndRehydrate(PASS, options());
    await drainWrites();
  }

  beforeEach(() => {
    idb = createFakeIndexedDb();
    resetAll();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    configurePiiStoreRuntime(options());
  });

  afterEach(() => {
    resetAll();
  });

  // ── 1. Consent gate ─────────────────────────────────────────────────

  it("refuses without migration consent and writes nothing", async () => {
    seedAllResidue();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("consent_required");
    expect(result.migratedKeys).toEqual([]);
    // The plaintext source stays; nothing was written anywhere.
    expect(window.localStorage.getItem(CUSTOMERS)).not.toBeNull();
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
    expect(useCustomerStore.getState().customers).toHaveLength(0);
    expect(await readPiiPersistedRecord(CUSTOMERS)).toBeNull();
  });

  // ── 2. Vault gate ───────────────────────────────────────────────────

  it("refuses an un-hydrated vault honestly, without touching plaintext", async () => {
    seedAllResidue();
    await useConsentStore.getState().grantMigrationConsent();

    // No unlock: the vault is locked.
    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("vault_unavailable");
    expect(result.migratedKeys).toEqual([]);
    // No vault was ever opened, no marker written, source untouched.
    expect(idb.databaseNames()).toEqual([]);
    expect(window.localStorage.getItem(CUSTOMERS)).not.toBeNull();
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
  });

  // ── 3. Happy path ───────────────────────────────────────────────────

  it("migrates all three keys into the vault, verifies, and preserves the source", async () => {
    seedAllResidue();
    const origins = {
      [CUSTOMERS]: window.localStorage.getItem(CUSTOMERS),
      [QUOTES]: window.localStorage.getItem(QUOTES),
      [HISTORY]: window.localStorage.getItem(HISTORY),
    };
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("migrated");
    expect([...result.migratedKeys].sort()).toEqual(
      [...LEGACY_PII_PLAINTEXT_KEYS].sort(),
    );

    // In-memory stores now hold the re-homed records.
    expect(useCustomerStore.getState().customers).toHaveLength(2);
    expect(useQuoteStore.getState().quotes).toHaveLength(1);
    expect(useHistoryStore.getState().entries).toHaveLength(2);

    // The encrypted destination VERIFIABLY holds them.
    const vaultCustomers = JSON.parse(
      (await readPiiPersistedRecord(CUSTOMERS)) as string,
    ) as { state: { customers: Customer[] } };
    expect(vaultCustomers.state.customers.map((c) => c.id).sort()).toEqual([
      "legacy_cust_1",
      "legacy_cust_2",
    ]);
    const vaultQuotes = JSON.parse(
      (await readPiiPersistedRecord(QUOTES)) as string,
    ) as { state: { quotes: Quote[] } };
    expect(vaultQuotes.state.quotes.map((q) => q.id)).toEqual([
      "legacy_quote_1",
    ]);
    const vaultHistory = JSON.parse(
      (await readPiiPersistedRecord(HISTORY)) as string,
    ) as { state: { entries: HistoryEntry[] } };
    expect(vaultHistory.state.entries.map((e) => e.id).sort()).toEqual([
      "legacy_hist_1",
      "legacy_hist_2",
    ]);

    // Copy-without-delete: the plaintext source is byte-identical.
    for (const key of LEGACY_PII_PLAINTEXT_KEYS) {
      expect(window.localStorage.getItem(key)).toBe(origins[key]);
    }

    // The completion marker is value-free: no record field leaks into it.
    const marker = window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY);
    expect(marker).not.toBeNull();
    expect(marker).not.toMatch(
      /Ana|Bruno|legacy_cust|legacy_hist|example\.com/,
    );
  });

  it("imports a raw pre-zustand array shape too", async () => {
    window.localStorage.setItem(CUSTOMERS, JSON.stringify(CUSTOMER_FIXTURES));
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("migrated");
    expect(useCustomerStore.getState().customers).toHaveLength(2);
    expect(window.localStorage.getItem(CUSTOMERS)).not.toBeNull();
  });

  // ── 4. Idempotency ──────────────────────────────────────────────────

  it("is idempotent: a second run re-imports nothing and overwrites nothing", async () => {
    seedAllResidue();
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const first = await migrateLegacyPlaintextPiiToVault();
    expect(first.status).toBe("migrated");
    const vaultBefore = await readPiiPersistedRecord(CUSTOMERS);

    const second = await migrateLegacyPlaintextPiiToVault();
    expect(second.status).toBe("already_migrated");
    expect(useCustomerStore.getState().customers).toHaveLength(2);
    expect(await readPiiPersistedRecord(CUSTOMERS)).toBe(vaultBefore);

    // Even with the marker cleared, the store import dedupes by id: no
    // duplicate, and the destination is never replaced with an empty value.
    window.localStorage.removeItem(LEGACY_PII_REHOME_MARKER_KEY);
    const third = await migrateLegacyPlaintextPiiToVault();
    expect(third.status).toBe("migrated");
    expect(useCustomerStore.getState().customers).toHaveLength(2);
    expect(useHistoryStore.getState().entries).toHaveLength(2);
  });

  // ── 5. Corrupt / incomplete residue ─────────────────────────────────

  it("does not destroy the destination when the legacy value is corrupt", async () => {
    // Session 1: put a real, unrelated record in the vault.
    await unlockVault();
    useHistoryStore.setState({ entries: [] });
    useHistoryStore.getState().addEntry(historyFixture("keep_me", 1));
    await drainWrites();
    const destinationBefore = await readPiiPersistedRecord(HISTORY);
    expect(destinationBefore).toContain("keep_me");

    // Fresh session, corrupt legacy residue for the same key.
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    configurePiiStoreRuntime(options());
    useHistoryStore.setState({ entries: [] });
    window.localStorage.setItem(HISTORY, "{ not json");
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("incomplete");
    expect(result.skippedKeys).toContain(HISTORY);
    // Destination byte-identical: corruption never overwrites the vault.
    expect(await readPiiPersistedRecord(HISTORY)).toBe(destinationBefore);
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
    expect(window.localStorage.getItem(HISTORY)).toBe("{ not json");
  });

  it("does not mark complete while an incomplete record cannot be re-homed", async () => {
    // A history record without `result` is refused by the store's importer, so
    // the vault can never hold it — the migration must not claim completion.
    window.localStorage.setItem(
      HISTORY,
      JSON.stringify({
        state: { entries: [{ id: "broken", timestamp: 1 }] },
        version: 2,
      }),
    );
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("incomplete");
    expect(result.migratedKeys).toEqual([]);
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
    // The source is preserved for a future, corrected attempt.
    expect(window.localStorage.getItem(HISTORY)).not.toBeNull();
  });

  // ── 6. Verify-before-complete ───────────────────────────────────────

  it("does not mark complete when the vault write does not commit", async () => {
    seedLegacyWrapper(CUSTOMERS, "customers", CUSTOMER_FIXTURES);
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    // Make the first vault put fail: the write settles rejected.
    idb.failPutsOnCall(1);
    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("incomplete");
    expect(idb.putCalls()).toBeGreaterThan(0);
    expect(await readPiiPersistedRecord(CUSTOMERS)).toBeNull();
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
    expect(window.localStorage.getItem(CUSTOMERS)).not.toBeNull();
  });

  // ── 7. No-op cases ──────────────────────────────────────────────────

  it("returns no_residue when there is no legacy plaintext at all", async () => {
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("no_residue");
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
  });

  it("treats an empty legacy array as nothing to migrate", async () => {
    seedLegacyWrapper(CUSTOMERS, "customers", []);
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault();

    expect(result.status).toBe("no_residue");
    expect(await readPiiPersistedRecord(CUSTOMERS)).toBeNull();
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
  });

  it("treats a residue that vanished before the read as nothing to migrate", async () => {
    // The injected read reports the key present on detection, then gone.
    let calls = 0;
    const read = (key: string): string | null => {
      if (key !== CUSTOMERS) return null;
      calls += 1;
      return calls === 1
        ? JSON.stringify({
            state: { customers: CUSTOMER_FIXTURES },
            version: 1,
          })
        : null;
    };
    await useConsentStore.getState().grantMigrationConsent();
    await unlockVault();

    const result = await migrateLegacyPlaintextPiiToVault({ read });

    expect(result.status).toBe("no_residue");
    expect(
      window.localStorage.getItem(LEGACY_PII_REHOME_MARKER_KEY),
    ).toBeNull();
  });
});
