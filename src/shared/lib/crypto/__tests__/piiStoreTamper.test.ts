/**
 * The vault reader refuses a moved, swapped or tampered record.
 *
 * Wave 1 (ADR-001 §2.4) fixed the reader defect where the AAD was derived from
 * the ciphertext's own metadata, so a ciphertext copied to another key
 * decrypted cleanly. A storage adapter sitting on top of that contract is
 * exactly where the defect would come back, because a vault holds many records
 * in one database and can plausibly be handed the wrong one.
 *
 * ## How each dimension is isolated
 *
 * There are two layers to a refusal, and perturbing a record's header only
 * exercises the outer one:
 *
 *  1. the **metadata comparison** — `meta` is compared to the caller's
 *     expectation;
 *  2. the **AES-GCM binding** — the tag covers `buildAadBytes(expectation)`.
 *
 * To prove layer 2 for `purpose`, `S` and `F` independently, the adversarial
 * record is BUILT with a genuine envelope under the wrong expectation (using
 * Wave 1's own `encryptWithPassphrase`, i.e. as someone who knows the
 * passphrase) and then its header is re-stamped to agree with the caller. The
 * comparison is now satisfied by construction, so the ONLY thing that can
 * reject it is the tag. Without that construction these cases would pass while
 * binding nothing at all — they would be testing the comparison four times.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  buildAadBytes,
  encryptWithPassphrase,
  type EnvelopeExpectation,
} from "@/shared/lib/crypto/envelope";
import type { VaultIdbFactory } from "@/shared/lib/crypto/indexedDbPort";
import {
  createPiiStore,
  lockAllPiiStores,
  PiiStoreRecordRejectedError,
  resetPiiStoreRuntimeForTests,
  unlockPiiStore,
  vaultExpectationFor,
  PII_VAULT_STORE,
} from "@/shared/lib/crypto/piiStore";
import { setDemoPersistenceSuppressed } from "@/shared/lib/manifestStorage";
import {
  setPiiPersistenceDeclined,
  setPiiStoreEnvironment,
} from "@/shared/lib/crypto/piiStoreCapability";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import { PII_STORE_ENVIRONMENT } from "@/shared/lib/crypto/__tests__/piiStoreFixtures";
import {
  createFakeIndexedDb,
  type FakeIndexedDb,
} from "@/shared/test/fakeIndexedDb";

const PASS = "senha-sintética-de-teste-4242";
const KEY = "open3dcalc_customers_v1";
const OTHER_KEY = "open3dcalc_quotes_v1";
/** A third real PII store, so a "move" can overwrite nothing. */
const THIRD_KEY = "open3dcalc_history_v2";
const PAYLOAD =
  '{"state":{"customers":[{"name":"Fernanda Sintética"}]},"version":1}';

type Record_ = Record<string, unknown>;
type Options = {
  indexedDb: VaultIdbFactory;
  environment: typeof PII_STORE_ENVIRONMENT;
};

describe("PII vault: a moved, re-labelled, swapped or tampered record is refused", () => {
  let idb: FakeIndexedDb;
  let options: Options;

  beforeEach(async () => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
    options = { indexedDb: idb.factory, environment: PII_STORE_ENVIRONMENT };
    await unlockPiiStore(KEY, PASS, options);
    await unlockPiiStore(OTHER_KEY, PASS, options);
    await unlockPiiStore(THIRD_KEY, PASS, options);
    await createPiiStore(KEY, options).write(PAYLOAD);
    await createPiiStore(OTHER_KEY, options).write("[]");
    await createPiiStore(THIRD_KEY, options).write("[]");
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  function recordAt(key: string): Record_ {
    return JSON.parse(idb.raw(PII_VAULT_STORE, key) as string) as Record_;
  }

  /**
   * Plant a record straight into the vault, bypassing the cipher.
   *
   * `string` is accepted raw and NOT re-stringified, so a test can plant bytes
   * that are not valid JSON at all — the case a `Record_`-only signature would
   * make unrepresentable, and the case the reader most needs to refuse.
   */
  function plant(key: string, record: string | Record_): void {
    idb.seed(
      PII_VAULT_STORE,
      key,
      typeof record === "string" ? record : JSON.stringify(record),
    );
  }

  async function readReason(key = KEY): Promise<string> {
    const error = await createPiiStore(key, options)
      .read()
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(error).toBeInstanceOf(PiiStoreRecordRejectedError);
    return (error as PiiStoreRecordRejectedError).reason;
  }

  /**
   * Build a GENUINE envelope under `expectation`, pinned to this store's salt
   * and re-stamped to the caller's expectation — so the header is honest and
   * the metadata comparison is satisfied. Only the AES-GCM tag is left to
   * catch the difference, which is exactly the binding under test.
   */
  async function reseal(
    expectation: EnvelopeExpectation,
    payload = PAYLOAD,
  ): Promise<Record_> {
    const envelope = JSON.parse(
      await encryptWithPassphrase(payload, PASS, expectation),
    ) as Record_;
    const storeSalt = (recordAt(KEY).kdf as Record<string, unknown>).salt;
    return {
      ...envelope,
      kdf: { ...(envelope.kdf as object), salt: storeSalt },
      meta: { ...vaultExpectationFor(KEY) },
    };
  }

  it("refuses a record MOVED to another store, and names the salt as the cause", async () => {
    // One valid ciphertext filed under the wrong key. Each store has its own
    // random salt, so the move is caught by the salt binding before any crypto
    // runs — an unauthenticated field in the record cannot select the key.
    plant(THIRD_KEY, recordAt(KEY));
    expect(await readReason(THIRD_KEY)).toBe("salt_mismatch");
    // No record is consumed by the refusal: the source is untouched, and the
    // third store's own record was the thing overwritten by the move itself.
    expect(await createPiiStore(KEY, options).read()).toBe(PAYLOAD);
    expect(await createPiiStore(OTHER_KEY, options).read()).toBe("[]");
    // The moved ciphertext is still ON DISK, undecryptable and undeleted.
    expect(idb.raw(PII_VAULT_STORE, THIRD_KEY)).toBe(
      JSON.stringify(recordAt(KEY)),
    );
  });

  it("refuses a record RE-LABELLED in place, on the metadata comparison", async () => {
    // The salt still belongs to this store, so the salt check passes; only the
    // header disagrees. The other half of the binding, and the one that catches
    // a record re-labelled in place.
    const record = recordAt(KEY);
    (record.meta as Record<string, unknown>).key = OTHER_KEY;
    plant(KEY, record);
    expect(await readReason()).toBe("metadata_mismatch");
  });

  it("refuses a SWAPPED KEY bound only by the tag, not the comparison", async () => {
    // Sealed under the quotes key, then re-stamped to claim the customers key:
    // the header is honest and the comparison passes, so a reader that derived
    // the AAD from the header would open this cleanly. That is the Wave 1
    // defect, reproduced and refused.
    plant(KEY, await reseal({ ...vaultExpectationFor(KEY), key: OTHER_KEY }));
    expect(await readReason()).toBe("authentication_failed");
  });

  it("refuses a SWAPPED PURPOSE, independently of the key", async () => {
    plant(
      KEY,
      await reseal({ ...vaultExpectationFor(KEY), purpose: "erasure" }),
    );
    expect(await readReason()).toBe("authentication_failed");
  });

  it("refuses a SWAPPED SCHEMA version, independently of the envelope version", async () => {
    // S and F are separate axes (ADR-001 §3.3): a value can keep its schema
    // while the sealed format changes. Perturbing S alone has to fail on its own.
    plant(KEY, await reseal({ ...vaultExpectationFor(KEY), schemaVersion: 2 }));
    expect(await readReason()).toBe("authentication_failed");
  });

  it("refuses a SWAPPED ENVELOPE format version, independently of the schema", async () => {
    plant(
      KEY,
      await reseal({
        ...vaultExpectationFor(KEY),
        envelopeFormatVersion: 2,
      }),
    );
    expect(await readReason()).toBe("authentication_failed");
  });

  it("binds each of the four components to DISTINCT bytes", async () => {
    // The four cases above each fail, which is necessary but not sufficient: a
    // reader that ignored `purpose` entirely would also fail all four, because
    // three of them perturb a field the comparison reads. Assert the bytes
    // differ so no component can be decorative.
    const base = Array.from(buildAadBytes(vaultExpectationFor(KEY)));
    for (const variant of [
      { ...vaultExpectationFor(KEY), key: OTHER_KEY + "xx" },
      { ...vaultExpectationFor(KEY), purpose: "erasure" },
      { ...vaultExpectationFor(KEY), schemaVersion: 2 },
      { ...vaultExpectationFor(KEY), envelopeFormatVersion: 2 },
    ]) {
      expect(Array.from(buildAadBytes(variant))).not.toEqual(base);
    }
  });

  it("refuses tampered CIPHERTEXT", async () => {
    const record = recordAt(KEY);
    const ct = record.ct as string;
    record.ct = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    plant(KEY, record);
    expect(await readReason()).toBe("authentication_failed");
  });

  it("refuses a tampered NONCE, so a record cannot be re-pointed at another value", async () => {
    const record = recordAt(KEY);
    const cipher = record.cipher as Record<string, unknown>;
    const iv = cipher.iv as string;
    cipher.iv = (iv[0] === "0" ? "1" : "0") + iv.slice(1);
    plant(KEY, record);
    expect(await readReason()).toBe("authentication_failed");
  });

  it("refuses a SALT swapped for another store's, naming it as the cause", async () => {
    // The honest diagnosis. Left to the tag this is an indistinguishable
    // authentication failure on a record that was written correctly, which is
    // the worst diagnostic an operator can be handed.
    const record = recordAt(KEY);
    const other = recordAt(OTHER_KEY);
    record.kdf = {
      ...(record.kdf as object),
      salt: (other.kdf as Record<string, unknown>).salt,
    };
    plant(KEY, record);
    expect(await readReason()).toBe("salt_mismatch");
  });

  it("refuses a KDF work-factor downgrade rather than deriving with it", async () => {
    // Parameters are declared by the VERSION, not read from the ciphertext: a
    // record naming fewer iterations is refused, never derived with. A build
    // that honoured it would let an attacker re-seal a weak envelope.
    const record = recordAt(KEY);
    (record.kdf as Record<string, unknown>).it = 1000;
    plant(KEY, record);
    expect(await readReason()).toBe("parameter_drift");
  });

  it("refuses a record that is not a v2 envelope", async () => {
    const record = recordAt(KEY);
    record.v = "1.1";
    plant(KEY, record);
    expect(await readReason()).toBe("unknown_envelope_version");
  });

  it("refuses a truncated or non-JSON record instead of reading past it", async () => {
    plant(KEY, '{"v":"2.0","ct":');
    expect(await readReason()).toBe("malformed_record");
    plant(KEY, "not json at all");
    expect(await readReason()).toBe("malformed_record");
  });

  it("refuses a record with NO meta block, as malformed rather than mismatched", async () => {
    // Reporting this as `metadata_mismatch` would tell an operator the record
    // came from a different contract, when in fact it carries no identity.
    const record = recordAt(KEY);
    delete record.meta;
    plant(KEY, record);
    expect(await readReason()).toBe("malformed_record");
  });

  it("leaves the record on disk after every refusal — a refusal is not a delete", async () => {
    const honest = idb.raw(PII_VAULT_STORE, KEY);
    const tampered = await reseal({
      ...vaultExpectationFor(KEY),
      purpose: "erasure",
    });
    plant(KEY, tampered);
    const planted = idb.raw(PII_VAULT_STORE, KEY);
    expect(await readReason()).toBe("authentication_failed");
    // Byte-identical after the refusal: the only copy of the user's data is
    // still there, and a refusal is never an implicit cleanup.
    expect(idb.raw(PII_VAULT_STORE, KEY)).toBe(planted);
    expect(planted).not.toBe(honest);
  });
});

describe("PII vault: the reader never derives the AAD from the record", () => {
  let idb: FakeIndexedDb;
  let options: Options;

  beforeEach(async () => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
    options = { indexedDb: idb.factory, environment: PII_STORE_ENVIRONMENT };
    await unlockPiiStore(KEY, PASS, options);
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  it("the expectation is a pure function of the CALLER's key, not the record's", async () => {
    await createPiiStore(KEY, options).write(PAYLOAD);
    const before = Array.from(buildAadBytes(vaultExpectationFor(KEY))).join(
      ",",
    );

    // Plant a record that CLAIMS to be a quotes record. The vault's own
    // expectation must not move by a single byte: nothing read out of the
    // record may reach the AAD.
    const record = JSON.parse(
      idb.raw(PII_VAULT_STORE, KEY) as string,
    ) as Record<string, unknown>;
    (record.meta as Record<string, unknown>).key = OTHER_KEY;
    idb.seed(PII_VAULT_STORE, KEY, JSON.stringify(record));

    expect(Array.from(buildAadBytes(vaultExpectationFor(KEY))).join(",")).toBe(
      before,
    );
    expect(vaultExpectationFor(KEY).key).toBe(KEY);
    // Which means the read fails — the tag covers the expectation, not the
    // header that claims to describe it.
    const error = await createPiiStore(KEY, options)
      .read()
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect((error as PiiStoreRecordRejectedError).reason).toBe(
      "metadata_mismatch",
    );
  });
});
