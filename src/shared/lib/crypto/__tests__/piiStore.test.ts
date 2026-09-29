/**
 * The browser PII vault: sealed values in IndexedDB, no plaintext path.
 *
 * The AAD is asserted as a HAND-WRITTEN BYTE LITERAL, never rebuilt with the
 * same code that produced it — a test that re-derives the expectation proves
 * only that the builder is idempotent, and stays green forever if the
 * contract itself is wrong. The literal below IS the specification; the
 * Wave 1 builder (`buildAadBytes`, itself pinned in `envelope.test.ts`) must
 * match it byte for byte, and the interop test proves the vault really sealed
 * under those bytes rather than under something that happens to compare equal.
 *
 * Synthetic fixtures only, never real PII. Real Web Crypto, no crypto mocks
 * (TEST-MATRIX §0).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { StorageValue } from "zustand/middleware";
import {
  buildAadBytes,
  decryptWithPassphrase,
  AT_REST_PURPOSE,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  PBKDF2_ITERATIONS,
  type AtRestEnvelope,
} from "@/shared/lib/crypto/envelope";
import {
  createPiiStore,
  hasPiiVaultRecord,
  heldKeyForTests,
  lockAllPiiStores,
  lockPiiStore,
  PII_VAULT_KEY,
  PII_VAULT_STORE,
  PiiStoreDeniedError,
  PiiStoreRecordRejectedError,
  PiiStoreWriteError,
  piiPersistStorage,
  resetPiiStoreRuntimeForTests,
  unlockPiiStore,
  vaultExpectationFor,
} from "@/shared/lib/crypto/piiStore";
import { PII_SCHEMA_VERSION } from "@/shared/lib/crypto/piiSchemaVersion";
import { PII_STORE_ENVIRONMENT } from "@/shared/lib/crypto/__tests__/piiStoreFixtures";
import { setDemoPersistenceSuppressed } from "@/shared/lib/manifestStorage";
import {
  setPiiPersistenceDeclined,
  setPiiStoreEnvironment,
} from "@/shared/lib/crypto/piiStoreCapability";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import {
  createFakeIndexedDb,
  type FakeIndexedDb,
} from "@/shared/test/fakeIndexedDb";

const PASS = "senha-sintética-de-teste-4242";
const OTHER_PASS = "outra-senha-errada-9999";
const KEY = "open3dcalc_customers_v1";
const PAYLOAD =
  '{"state":{"customers":[{"name":"Fernanda Sintética"}]},"version":1}';

/**
 * The normative AAD byte string for K = `open3dcalc_customers_v1`,
 * P = `at-rest`, S = 1, F = 1, laid out by hand:
 *
 *   "open3dcalc-pii-at-rest"  bytes  0..21   (22 bytes)
 *   NUL                       byte  22
 *   "open3dcalc_customers_v1" bytes 23..45   (23 bytes)
 *   NUL                       byte  46
 *   "at-rest"                 bytes 47..53   ( 7 bytes)
 *   NUL                       byte  54
 *   "schema:1"                bytes 55..62   ( 8 bytes)
 *   NUL                       byte  63
 *   "envelope:1"              bytes 64..73   (10 bytes)
 *
 * 74 bytes total; the four NUL separators sit at 22, 46, 54 and 63.
 */
const EXPECTED_AAD_BYTES = [
  // "open3dcalc-pii-at-rest"
  111, 112, 101, 110, 51, 100, 99, 97, 108, 99, 45, 112, 105, 105, 45, 97, 116,
  45, 114, 101, 115, 116, 0,
  // "open3dcalc_customers_v1"
  111, 112, 101, 110, 51, 100, 99, 97, 108, 99, 95, 99, 117, 115, 116, 111, 109,
  101, 114, 115, 95, 118, 49, 0,
  // "at-rest"
  97, 116, 45, 114, 101, 115, 116, 0,
  // "schema:1"
  115, 99, 104, 101, 109, 97, 58, 49, 0,
  // "envelope:1"
  101, 110, 118, 101, 108, 111, 112, 101, 58, 49,
];

function recordOf(idb: FakeIndexedDb, key = KEY): AtRestEnvelope {
  const raw = idb.raw(PII_VAULT_STORE, key);
  expect(typeof raw, "record must be a JSON string, never a live object").toBe(
    "string",
  );
  return JSON.parse(raw as string) as AtRestEnvelope;
}

describe("PII vault: the AAD byte contract (ADR-001 §2.4)", () => {
  it("composes exactly the hand-written literal for a real PII key", () => {
    const bytes = buildAadBytes(vaultExpectationFor(KEY));
    expect(Array.from(bytes)).toEqual(EXPECTED_AAD_BYTES);
    expect(bytes.length).toBe(74);
  });

  it("separates the four components with a single NUL at a known offset", () => {
    const bytes = buildAadBytes(vaultExpectationFor(KEY));
    const nul: number[] = [];
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 0) nul.push(i);
    expect(nul).toEqual([22, 46, 54, 63]);
    const decoder = new TextDecoder();
    expect(decoder.decode(bytes.slice(0, 22))).toBe("open3dcalc-pii-at-rest");
    expect(decoder.decode(bytes.slice(23, 46))).toBe(KEY);
    expect(decoder.decode(bytes.slice(47, 54))).toBe(AT_REST_PURPOSE);
    expect(decoder.decode(bytes.slice(55, 63))).toBe("schema:1");
    expect(decoder.decode(bytes.slice(64, 74))).toBe("envelope:1");
  });

  it("takes S and F from the pinned shared constants, not from literals", () => {
    // A vault that hardcoded S = 1 would look identical today and would be
    // wrong the moment a PII key's schema version moves — with no test failing
    // and no error at runtime.
    const expectation = vaultExpectationFor(KEY);
    expect(expectation.schemaVersion).toBe(PII_SCHEMA_VERSION);
    expect(expectation.envelopeFormatVersion).toBe(
      CURRENT_ENVELOPE_FORMAT_VERSION,
    );
    expect(expectation.purpose).toBe(AT_REST_PURPOSE);
    expect(expectation.key).toBe(KEY);
  });

  it("binds a different storage key to different bytes, at the same length", () => {
    const base = Array.from(buildAadBytes(vaultExpectationFor(KEY)));
    // Same-length substitution: a differing length would also make the bytes
    // differ, which proves nothing about the binding.
    const other = Array.from(
      buildAadBytes(vaultExpectationFor("open3dcalc_customers_v2")),
    );
    expect(other.length).toBe(base.length);
    expect(other).not.toEqual(base);
    expect(other.filter((b, i) => b !== base[i])).toHaveLength(1);
    // And a separator never moves, so no component can slide into a neighbour.
    expect(other[22]).toBe(0);
    expect(other[46]).toBe(0);
    expect(other[54]).toBe(0);
    expect(other[63]).toBe(0);
  });
});

describe("PII vault: round trip, and no plaintext anywhere", () => {
  let idb: FakeIndexedDb;

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setDemoPersistenceSuppressed(false);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  async function open(): Promise<ReturnType<typeof createPiiStore>> {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    return createPiiStore(KEY, options);
  }

  it("stores a sealed record under the key name and reads it back", async () => {
    const store = await open();
    await store.write(PAYLOAD);
    expect(idb.keys(PII_VAULT_STORE)).toEqual([KEY]);
    expect(await store.read()).toBe(PAYLOAD);
    expect(await store.exists()).toBe(true);
  });

  it("never leaves the plaintext in the database", async () => {
    const store = await open();
    await store.write(PAYLOAD);
    const raw = idb.raw(PII_VAULT_STORE, KEY) as string;
    // The record, the key name and the envelope metadata are the ONLY things
    // on disk. The name is metadata by ADR-001 §2.1; the payload is not.
    expect(raw).not.toContain("Fernanda");
    expect(raw).not.toContain(PAYLOAD);
    const record = recordOf(idb);
    expect(record.v).toBe("2.0");
    expect(record.kdf.alg).toBe("PBKDF2-SHA256");
    expect(record.kdf.it).toBe(PBKDF2_ITERATIONS);
    expect(record.cipher.alg).toBe("AES-256-GCM");
    expect(record.meta).toEqual(vaultExpectationFor(KEY));
    // The key NAME is present and the payload is not: names are metadata.
    expect(raw).toContain(KEY);
  });

  it("seals a fresh nonce per envelope, so equal plaintexts differ", async () => {
    const store = await open();
    await store.write(PAYLOAD);
    const first = recordOf(idb);
    await store.write(PAYLOAD);
    const second = recordOf(idb);
    expect(first.cipher.iv).not.toBe(second.cipher.iv);
    expect(first.ct).not.toBe(second.ct);
    // Same salt: the store's key is derived once, and the salt travels in each
    // record so a record is self-describing and the Wave 1 reader can open it.
    expect(first.kdf.salt).toBe(second.kdf.salt);
    expect(first.kdf.salt).toMatch(/^[0-9a-f]{32}$/);
  });

  it("gives two stores independent random salts", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore("open3dcalc_customers_v1", PASS, options);
    await unlockPiiStore("open3dcalc_quotes_v1", PASS, options);
    await createPiiStore("open3dcalc_customers_v1", options).write("a");
    await createPiiStore("open3dcalc_quotes_v1", options).write("b");
    const a = recordOf(idb, "open3dcalc_customers_v1");
    const b = recordOf(idb, "open3dcalc_quotes_v1");
    expect(a.kdf.salt).not.toBe(b.kdf.salt);
  });

  it("holds the derived key non-extractable", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const store = createPiiStore(KEY, options);
    // The only observable proof: a non-extractable key cannot be exported, so
    // even a full heap dump cannot turn the session into a decryption oracle.
    const held = await exportedHeldKey(store);
    expect(held).toBe(false);
    await store.write(PAYLOAD);
    expect(await store.read()).toBe(PAYLOAD);
  });

  it("writes records the Wave 1 reader can open — same contract, same bytes", async () => {
    // The vault is a storage layer, not a second envelope format. A record it
    // writes is a v2 envelope: `decryptWithPassphrase` re-derives from the
    // record's own salt and builds the AAD from its own expectation, so this
    // passing proves the vault sealed under the normative bytes.
    const store = await open();
    await store.write(PAYLOAD);
    const raw = idb.raw(PII_VAULT_STORE, KEY) as string;
    const opened = await decryptWithPassphrase(
      raw,
      PASS,
      vaultExpectationFor(KEY),
    );
    expect(opened).toBe(PAYLOAD);
  });

  it("removes a record without leaving a tombstone", async () => {
    const store = await open();
    await store.write(PAYLOAD);
    await store.remove();
    expect(idb.keys(PII_VAULT_STORE)).toEqual([]);
    expect(await store.read()).toBeNull();
    expect(await store.exists()).toBe(false);
  });

  it("reads a missing record as null, not as an error", async () => {
    const store = await open();
    expect(await store.read()).toBeNull();
  });
});

/**
 * MEDIUM-1 — a locked-safe presence read. "Is there a profile to unlock?" is
 * metadata, not PII: it must be answerable BEFORE any key is held so the locked
 * shell can offer "create" to a new profile and "unlock" to an existing one.
 */
describe("PII vault: presence without unlock", () => {
  let idb: FakeIndexedDb;
  const options = () => ({
    indexedDb: idb.factory,
    environment: PII_STORE_ENVIRONMENT,
  });

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setDemoPersistenceSuppressed(false);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  it("reports no record for a fresh profile", async () => {
    expect(await hasPiiVaultRecord(KEY, options())).toBe(false);
  });

  it("reports an existing record while the vault is locked", async () => {
    await unlockPiiStore(KEY, PASS, options());
    await createPiiStore(KEY, options()).write(PAYLOAD);
    lockAllPiiStores();

    expect(await hasPiiVaultRecord(KEY, options())).toBe(true);
  });

  it("treats a declined user as having no durable profile", async () => {
    await unlockPiiStore(KEY, PASS, options());
    await createPiiStore(KEY, options()).write(PAYLOAD);
    lockAllPiiStores();
    setPiiPersistenceDeclined(true);

    expect(await hasPiiVaultRecord(KEY, options())).toBe(false);
  });

  it("treats a demo session as having no durable profile", async () => {
    await unlockPiiStore(KEY, PASS, options());
    await createPiiStore(KEY, options()).write(PAYLOAD);
    lockAllPiiStores();
    setDemoPersistenceSuppressed(true);

    expect(await hasPiiVaultRecord(KEY, options())).toBe(false);
  });

  it("reports no record when the environment cannot hold one", async () => {
    setPiiStoreEnvironment(null);

    expect(await hasPiiVaultRecord(KEY, options())).toBe(false);
  });
});

/**
 * Ask the vault whether its held key can be exported. The vault deliberately
 * exposes no key handle, so the question is asked of the platform through the
 * same runtime the vault derived the key in.
 */
async function exportedHeldKey(
  store: ReturnType<typeof createPiiStore>,
): Promise<boolean> {
  const key = heldKeyForTests(store.key);
  expect(key, "the vault must hold a derived key once unlocked").not.toBeNull();
  try {
    await globalThis.crypto.subtle.exportKey("raw", key as CryptoKey);
    return true;
  } catch {
    return false;
  }
}

describe("PII vault: a wrong passphrase changes nothing on disk", () => {
  let idb: FakeIndexedDb;

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  it("refuses the wrong passphrase and preserves the sealed value byte for byte", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    await createPiiStore(KEY, options).write(PAYLOAD);
    const sealed = idb.raw(PII_VAULT_STORE, KEY) as string;

    // A wrong passphrase must be caught at unlock, not discovered later on the
    // first read — and it must never be "fixed" by writing over the record.
    const error = await unlockPiiStore(KEY, OTHER_PASS, options).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(PiiStoreRecordRejectedError);
    expect((error as PiiStoreRecordRejectedError).reason).toBe(
      "authentication_failed",
    );
    // Byte-identical: the only copy of the user's data is untouched.
    expect(idb.raw(PII_VAULT_STORE, KEY)).toBe(sealed);
    expect(idb.keys(PII_VAULT_STORE)).toEqual([KEY]);

    // The correct passphrase still opens the preserved value.
    await unlockPiiStore(KEY, PASS, options);
    expect(await createPiiStore(KEY, options).read()).toBe(PAYLOAD);
  });

  it("does not cache a key derived from a wrong passphrase", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    await createPiiStore(KEY, options).write(PAYLOAD);
    await unlockPiiStore(KEY, OTHER_PASS, options).catch(() => undefined);
    // A cached key from the failed attempt would make the vault look unlocked
    // while every read fails, and would let a later read succeed under a
    // passphrase the user never entered.
    expect(createPiiStore(KEY, options).isUnlocked()).toBe(false);
  });

  it("locking drops the held key and the record stays", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    await createPiiStore(KEY, options).write(PAYLOAD);
    lockPiiStore(KEY);
    const store = createPiiStore(KEY, options);
    expect(store.isUnlocked()).toBe(false);
    // Locking is not deletion: the bytes are still on disk, still sealed.
    expect(idb.raw(PII_VAULT_STORE, KEY)).toBeTypeOf("string");
  });
});

describe("PII vault: a value that cannot be sealed is not silently dropped", () => {
  let idb: FakeIndexedDb;

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setDemoPersistenceSuppressed(false);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  it("rejects an unserialisable value and keeps the previous record intact", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const storage = piiPersistStorage<{ entries: unknown[] }>(KEY, options);
    await storage.setItem(KEY, { state: { entries: ["good"] }, version: 1 });
    const good = idb.raw(PII_VAULT_STORE, KEY);

    // A circular state object is the realistic shape: zustand hands the
    // storage whatever the store holds, and `JSON.stringify` throws on it.
    const state: { entries: unknown[]; self?: unknown } = { entries: [] };
    state.self = state;
    const error = await storage.setItem(KEY, { state }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(PiiStoreWriteError);
    expect((error as PiiStoreWriteError).reason).toBe("unserializable_value");
    // Dropping the write silently would be data loss that looks like success.
    expect(idb.raw(PII_VAULT_STORE, KEY)).toBe(good);
    expect(await storage.getItem(KEY)).toEqual({
      state: { entries: ["good"] },
      version: 1,
    });
  });

  it("rejects a BigInt and an undefined state, both unserialisable", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const storage = piiPersistStorage<Record<string, unknown>>(KEY, options);
    // `JSON.stringify(1n)` throws; `JSON.stringify(undefined)` returns
    // undefined, so a naive `setItem` would seal the string "undefined" and a
    // later read would hand the store a value it never wrote.
    await expect(
      storage.setItem(KEY, { state: { big: 1n } }),
    ).rejects.toBeInstanceOf(PiiStoreWriteError);
    await expect(
      storage.setItem(
        KEY,
        undefined as unknown as StorageValue<Record<string, unknown>>,
      ),
    ).rejects.toBeInstanceOf(PiiStoreWriteError);
    expect(idb.keys(PII_VAULT_STORE)).toEqual([]);
  });
});

describe("PII vault: concurrent writers do not interleave", () => {
  let idb: FakeIndexedDb;

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  it("serialises writers into one coherent record, never a torn one", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const store = createPiiStore(KEY, options);
    const payloads = Array.from(
      { length: 8 },
      (_, i) => `{"writer":${i},"pad":"${"x".repeat(200)}"}`,
    );

    // All eight in flight at once, with no await between the calls.
    await Promise.all(payloads.map((p) => store.write(p)));

    // One record, from a single writer. A torn record would be a blend of two.
    expect(idb.keys(PII_VAULT_STORE)).toEqual([KEY]);
    const final = await store.read();
    expect(payloads).toContain(final);
    const parsed = JSON.parse(final ?? "null") as {
      writer: number;
      pad: string;
    };
    expect(parsed.pad).toHaveLength(200);
    expect(parsed.pad).toBe("x".repeat(200));
  });

  it("commits writers in CALL order, so the last write issued wins", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const store = createPiiStore(KEY, options);

    // The stale-write shape an action produces: a wide (slower to seal) value
    // first, then a small one. Sealing before enqueueing makes commit order
    // follow crypto-completion order, so the FIRST value seals last and lands
    // last — a stale record over the newer one. Serialising the whole write
    // makes call order the commit order.
    const stale = `{"turn":"stale","pad":"${"x".repeat(2_000_000)}"}`;
    const fresh = '{"turn":"fresh"}';

    const first = store.write(stale);
    const second = store.write(fresh);
    await Promise.all([first, second]);

    expect(await store.read()).toBe(fresh);
  });

  it("never has two readwrite transactions open on the store at once", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const store = createPiiStore(KEY, options);
    await Promise.all(
      Array.from({ length: 8 }, (_, i) => store.write(`{"writer":${i}}`)),
    );
    // The structural half of the guarantee: the vault holds at most one
    // readwrite transaction at a time, so a later writer can never observe a
    // half-committed record. This is what the double records.
    expect(idb.maxConcurrentReadWrite()).toBe(1);
  });

  it("a failed write does not poison the queue for the next one", async () => {
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const store = createPiiStore(KEY, options);
    await expect(store.write("")).rejects.toBeInstanceOf(PiiStoreWriteError);
    await store.write(PAYLOAD);
    expect(await store.read()).toBe(PAYLOAD);
  });

  it("REFUSES a locked READ instead of returning empty — the data-loss path", async () => {
    // The single most important assertion in this file. A locked read that
    // returned `null` or `""` would hydrate the store with its INITIAL state,
    // and the store's first `set()` would persist that initial state (an empty
    // customer list) straight over the user's real one. The vault looks
    // healthy, the data is gone, and nobody notices until their quotes are
    // missing. So a locked read REJECTS, and the reason is typed.
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    await createPiiStore(KEY, options).write(PAYLOAD);

    // Non-vacuity: the record EXISTS and opens fine while unlocked. Without
    // this the assertions below would also pass on a vault holding nothing.
    expect(await createPiiStore(KEY, options).read()).toBe(PAYLOAD);

    lockPiiStore(KEY);
    const locked = createPiiStore(KEY, options);
    expect(locked.isUnlocked()).toBe(false);
    const error = await locked.read().then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(PiiStoreDeniedError);
    expect((error as PiiStoreDeniedError).reason).toBe("profile_locked");
  });

  it("REFUSES a locked zustand getItem, which is the hydration path itself", async () => {
    // `piiPersistStorage` is what a migrated store would hydrate from, so this
    // is the assertion that pins the DESIGN DECISION rather than the
    // docstring: the refusal has to reach zustand's hydration call, or
    // `skipHydration` + post-unlock `rehydrate()` buys nothing.
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(KEY, PASS, options);
    const storage = piiPersistStorage<{ entries: unknown[] }>(KEY, options);
    await storage.setItem(KEY, { state: { entries: ["kept"] }, version: 1 });
    expect(await storage.getItem(KEY)).toEqual({
      state: { entries: ["kept"] },
      version: 1,
    });

    lockPiiStore(KEY);
    // It must NOT resolve to null. A null here is what lets the store keep its
    // initial state and then write that state back over the record.
    await expect(
      piiPersistStorage<{ entries: unknown[] }>(KEY, options).getItem(KEY),
    ).rejects.toBeInstanceOf(PiiStoreDeniedError);
    // Nor may a locked write slip through to replace the record.
    await expect(
      piiPersistStorage<{ entries: unknown[] }>(KEY, options).setItem(KEY, {
        state: { entries: [] },
        version: 1,
      }),
    ).rejects.toBeInstanceOf(PiiStoreDeniedError);

    // And the record survived both attempts untouched.
    await unlockPiiStore(KEY, PASS, options);
    expect(await storage.getItem(KEY)).toEqual({
      state: { entries: ["kept"] },
      version: 1,
    });
  });

  it("declares one vault surface, not three keys", () => {
    // The manifest entry names the DATABASE, and the three PII stores are
    // records inside it — one declared surface, three record ids.
    expect(PII_VAULT_KEY).toBe("open3dcalc_pii_vault");
  });
});
