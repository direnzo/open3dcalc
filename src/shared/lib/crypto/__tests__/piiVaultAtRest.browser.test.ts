/**
 * W6 — the browser PII vault against a REAL browser: sealed at rest, and the
 * write commit order following call order when two writes go out back to back.
 *
 * ## What this spec adds over the jsdom suite
 *
 * The cryptography was already real in `piiStore.test.ts`; the STORE was not.
 * jsdom has no IndexedDB, so those specs inject `createFakeIndexedDb()` and pin
 * `PII_STORE_ENVIRONMENT` by hand, because jsdom reports
 * `window.isSecureContext` as `undefined`. That means three things a public beta
 * depends on had never run:
 *
 *  - the capability sampler deciding on a REAL secure origin;
 *  - the port's transaction/auto-commit/upgrade handshake against a real
 *    IndexedDB implementation;
 *  - the bytes actually committed, read back with the DOM's own API instead of
 *    with the vault's decrypting `read()`.
 *
 * Nothing is injected here except the spec-scoped database name (see
 * `piiVaultBrowserHarness.ts`): `window.isSecureContext`, `crypto.subtle` and
 * `indexedDB` are Chromium's own.
 *
 * Synthetic fixtures only, never real PII. Real Web Crypto, no crypto mocks
 * (TEST-MATRIX §0).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ENVELOPE_VERSION,
  PBKDF2_ITERATIONS,
  decryptWithPassphrase,
  type AtRestEnvelope,
} from "@/shared/lib/crypto/envelope";
import {
  createPiiStore,
  lockAllPiiStores,
  PiiStoreDeniedError,
  resetPiiStoreRuntimeForTests,
  unlockPiiStore,
  vaultExpectationFor,
} from "@/shared/lib/crypto/piiStore";
import { resetPiiStoreGateForTests } from "@/shared/lib/crypto/piiStoreCapability";
import { resetPiiStoreHydrationForTests } from "@/shared/lib/crypto/piiStoreHydration";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import {
  ciphertextBytes,
  containsBytes,
  createPiiVaultBrowserHarness,
  type PiiVaultBrowserHarness,
} from "@/shared/lib/crypto/__tests__/piiVaultBrowserHarness";

const PASS = "senha-sintetica-do-harness-browser";
const KEY = "open3dcalc_customers_v1";
/** A marker that exists ONLY inside the plaintext, never in a field name. */
const MARKER = "Cliente-Sintetico-Do-Harness-At-4891";

function payloadFor(marker: string): string {
  return `{"state":{"customers":[{"name":"${marker}"}]},"version":1}`;
}

function envelopeOf(raw: string): AtRestEnvelope {
  return JSON.parse(raw) as AtRestEnvelope;
}

/** The plaintext behind a sealed record, read WITHOUT the vault. */
async function plaintextOf(
  harness: PiiVaultBrowserHarness,
  key: string,
): Promise<string | null> {
  const raw = await harness.rawRecord(key);
  if (raw === null) return null;
  return decryptWithPassphrase(raw, PASS, vaultExpectationFor(key));
}

describe("W6 — the PII vault seals at rest in a real browser", () => {
  let harness: PiiVaultBrowserHarness;

  beforeEach(async () => {
    harness = createPiiVaultBrowserHarness("atrest");
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    zeroizeSessionPassphrase();
    // The gate stays as installed by the vault's own sampler: this spec's point
    // is that a real secure origin passes it WITHOUT an override. Only the
    // "nothing installed yet" state has to be cleared between specs, so the
    // sampler demonstrably re-derives the capable environment each time.
    resetPiiStoreGateForTests();
    await harness.clear();
  });

  afterEach(() => {
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  it("samples a capable environment from the real browser, with no injected facts", async () => {
    // No `environment` option anywhere: the gate must reach `null` refusal on
    // its own. This is the assertion the jsdom specs cannot make, because jsdom
    // reports `isSecureContext: undefined` and therefore has to be handed
    // `PII_STORE_ENVIRONMENT`.
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });

    await expect(
      unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb }),
    ).resolves.toBeUndefined();
    expect(store.isUnlocked()).toBe(true);
  });

  it("fails closed when the passphrase is empty, without touching storage", async () => {
    await expect(
      unlockPiiStore(KEY, "", { indexedDb: harness.indexedDb }),
    ).rejects.toBeInstanceOf(PiiStoreDeniedError);
    expect(await harness.rawRecords()).toEqual([]);
  });

  it("writes the plaintext nowhere: neither the JSON record nor the ciphertext bytes carry it", async () => {
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });
    await unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb });

    const payload = payloadFor(MARKER);
    await store.write(payload);

    // Independent read: the DOM's own IndexedDB API, not the vault's `read()`.
    const records = await harness.rawRecords();
    expect(records).toHaveLength(1);
    const [record] = records;
    expect(record.key).toBe(KEY);

    // The record is an unopened Wave-1 v2 envelope, not a live object and not
    // the plaintext.
    expect(record.raw).not.toContain(MARKER);
    expect(record.raw).not.toContain(PASS);
    const envelope = envelopeOf(record.raw);
    expect(envelope.v).toBe(ENVELOPE_VERSION);
    expect(envelope.kdf.alg).toBe("PBKDF2-SHA256");
    expect(envelope.kdf.it).toBe(PBKDF2_ITERATIONS);
    expect(envelope.cipher.alg).toBe("AES-256-GCM");
    // `meta` is unauthenticated metadata; it is compared, never trusted. It is
    // allowed to name the key — it must not carry the value.
    expect(envelope.meta.key).toBe(KEY);
    expect(JSON.stringify(envelope.meta)).not.toContain(MARKER);

    // Byte-level proof: decode the committed ciphertext and scan it.
    const needle = new TextEncoder().encode(MARKER);
    expect(containsBytes(ciphertextBytes(record.raw), needle)).toBe(false);

    // And the byte string that IS stored decrypts to exactly the plaintext that
    // was written, under the CALLER's expectation — so the absence above is
    // sealing, not a lost write.
    await expect(
      decryptWithPassphrase(record.raw, PASS, vaultExpectationFor(KEY)),
    ).resolves.toBe(payload);
    await expect(store.read()).resolves.toBe(payload);
  });

  it("re-seals on every write, so a replaced value's old bytes are gone", async () => {
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });
    await unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb });

    const superseded = payloadFor("Cliente-Superseded-At-7231");
    await store.write(superseded);
    await store.write(payloadFor(MARKER));

    const records = await harness.rawRecords();
    expect(records).toHaveLength(1);
    // A fresh IV per seal means the old ciphertext cannot survive as a substring
    // of the new record, and the store holds one record per logical key.
    expect(records[0].raw).not.toContain(superseded);
    expect(
      containsBytes(
        ciphertextBytes(records[0].raw),
        new TextEncoder().encode(superseded),
      ),
    ).toBe(false);
    await expect(plaintextOf(harness, KEY)).resolves.toBe(payloadFor(MARKER));
  });
});

describe("W6 — write commit order follows call order in a real browser", () => {
  let harness: PiiVaultBrowserHarness;

  beforeEach(async () => {
    harness = createPiiVaultBrowserHarness("ordering");
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    zeroizeSessionPassphrase();
    resetPiiStoreGateForTests();
    await harness.clear();
  });

  afterEach(() => {
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  /**
   * An INTEGRATION-level contract guard: with two writes issued back to back,
   * the store must end up holding the LAST value ISSUED, and both readers (the
   * vault's `read()` and an independent decrypt of the raw record) must agree.
   *
   * This is a guard, NOT a falsifiable regression test for the Wave-5 ordering
   * fix (squash-merged into `main` as `1b7b885`). Verified empirically: with
   * that fix reverted, the whole browser suite still passes 9/9, because
   * Chromium completes the two AES-GCM seals in FIFO emission order — so
   * "seal before enqueue" does NOT invert the commit order in this runtime,
   * and the shapes below cannot reproduce the pre-fix inversion. What the spec
   * adds is coverage of the real IndexedDB contract on the runtime that
   * actually ships it.
   *
   * The deterministic, falsifiable guard is the unit test in `piiStore.test.ts`
   * ("commits writers in CALL order, so the last write issued wins"): it runs
   * against the injected store, where seal completion order is controllable,
   * and it is the test that fails when the fix is reverted. That is where the
   * regression is detected; this browser spec keeps the integration behaviour
   * honest against a real Chromium.
   *
   * The defect was a race, so no single round can be a deterministic RED; the
   * rounds below make the property observable and the expectation exact, and
   * both readers (the vault's `read()` and an independent decrypt of the raw
   * record) must agree.
   */
  it("keeps commit order = call order: the last value issued, in both orders and over repeated rounds", async () => {
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });
    await unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb });

    for (let round = 0; round < 6; round++) {
      const earlier = payloadFor(`Rodada-${round}-Anterior`);
      const later = payloadFor(`Rodada-${round}-Posterior`);
      // Alternating order, so a passing run cannot be an artifact of which
      // value happens to be the larger one.
      const [first, last] =
        round % 2 === 0 ? [earlier, later] : [later, earlier];

      await Promise.all([store.write(first), store.write(last)]);

      await expect(store.read()).resolves.toBe(last);
      await expect(plaintextOf(harness, KEY)).resolves.toBe(last);
    }
  });

  /**
   * The shape that WOULD be adversarial if seal completion order were free: the
   * FIRST write is the large one, so "seal before enqueue" would be expected to
   * let the small second payload's seal win the race. Chromium still seals in
   * FIFO, so this shape does NOT reproduce the pre-fix inversion (see the
   * describe docstring and the falsifiable unit guard in `piiStore.test.ts`); it
   * asserts the property holds under the biggest payload the store can see.
   */
  it("keeps the last value issued in the slow-seal-first shape (Chromium does not invert it)", async () => {
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });
    await unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb });

    // 64 KiB of filler, generated at run time: the two seals differ in size so
    // the shape is real, without committing a high-entropy literal.
    const bulky = `{"state":{"customers":[{"name":"Lento","notes":"${"z".repeat(
      64 * 1024,
    )}"}]},"version":1}`;
    const small = payloadFor("Ultimo-Pequeno-9012");

    await Promise.all([store.write(bulky), store.write(small)]);

    await expect(store.read()).resolves.toBe(small);
    await expect(plaintextOf(harness, KEY)).resolves.toBe(small);
  });

  it("serialises the two writers, so the store never holds a half-written record", async () => {
    const store = createPiiStore(KEY, { indexedDb: harness.indexedDb });
    await unlockPiiStore(KEY, PASS, { indexedDb: harness.indexedDb });

    const values = [
      payloadFor("Serie-A"),
      payloadFor("Serie-B"),
      payloadFor("Serie-C"),
      payloadFor("Serie-D"),
    ];
    await Promise.all(values.map((value) => store.write(value)));

    // Exactly one record, and it is the last value issued.
    const records = await harness.rawRecords();
    expect(records).toHaveLength(1);
    await expect(store.read()).resolves.toBe(values[values.length - 1]);
  });
});
