/**
 * SPEC-01 declaration and egress exclusion for the browser PII vault.
 *
 * Three separate claims, pinned together because they move together:
 *
 *  1. **The declaration.** The vault is a distinct `indexeddb` surface, not a
 *     `localStorage` key. It was declared only when this task landed — until
 *     then the single largest PII store in the web build (three PII keys'
 *     worth of records, sealed) was an UNDECLARED surface, which is the
 *     `pii_stage` omission one layer out.
 *  2. **The re-consent consequence.** A new declared PII surface is a
 *     privacy-contract change, so `policy_version` moves 1.6 → 1.7 and a
 *     SPEC-04 receipt issued under 1.6 evaluates `policy_mismatch`.
 *  3. **The egress exclusion.** The vault must be unreachable from
 *     `dataSync.ts`. That guarantee is STRUCTURAL — `dataSync` reads a fixed
 *     list of `localStorage` key literals and never enumerates a store — and a
 *     structural guarantee is exactly the kind that gets broken by one careless
 *     `for (const key of ...)` later. Both halves are pinned: the behaviour
 *     (a sealed sentinel never appears in a collected bundle) and the shape
 *     (the source contains no storage enumeration and no vault reference).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import manifestFixture from "../../../../docs/privacy/SPEC-01-manifest-fixture.json";
import {
  getEntry,
  loadManifest,
  type ManifestDocument,
} from "@/shared/lib/dataManifest";
import { collectSyncData } from "@/shared/lib/dataSync";
import {
  createPiiStore,
  lockAllPiiStores,
  PII_VAULT_KEY,
  resetPiiStoreRuntimeForTests,
  unlockPiiStore,
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
import { PII_SCHEMA_VERSION } from "@/shared/lib/crypto/piiSchemaVersion";

const doc = manifestFixture as ManifestDocument;
const CUSTOMERS = "open3dcalc_customers_v1";
const PASS = "senha-sintética-de-teste-4242";

/** A marker that appears ONLY inside sealed PII, never in a real field. */
const SENTINEL = "zz-placa-sintetica-nao-exportavel-4242";

describe("SPEC-01: the vault is a declared PII indexeddb surface", () => {
  it("is registered as a distinct surface, not a localStorage key", () => {
    const entry = getEntry(loadManifest(doc), PII_VAULT_KEY);
    expect(entry).toMatchObject({
      key: PII_VAULT_KEY,
      surface: "indexeddb",
      // The vault is a browser store. Electron PII lives in `db/`, and this
      // declaration must not imply a desktop surface that does not exist.
      platforms: ["web", "pwa"],
      class: "user_content",
      pii: true,
      persistence: "encrypted_at_rest",
      sync: "never",
      export: "never",
      erasure: "erase_on_delete_all",
      legal_basis: "consent",
      owner: "hermes",
    });
  });

  it("is not one of the plaintext localStorage keys it replaces", () => {
    const vault = getEntry(loadManifest(doc), PII_VAULT_KEY);
    // The failure this prevents: declaring the vault as a `localStorage`
    // entry, which would make the inventory say the PII is still in
    // localStorage — a claim that is both wrong and reassuringly familiar.
    expect(vault?.surface).not.toBe("localStorage");
    // The three real PII keys keep their own declarations; this task does not
    // rewrite them, it adds the surface they will migrate onto.
    for (const key of [
      CUSTOMERS,
      "open3dcalc_quotes_v1",
      "open3dcalc_history_v2",
    ]) {
      expect(getEntry(loadManifest(doc), key)?.surface).toBe("localStorage");
    }
  });

  it("declares retention that is true, including the absence of a sweeper", () => {
    const vault = getEntry(loadManifest(doc), PII_VAULT_KEY);
    // The records are the user's own customers/quotes/history, so they live
    // exactly as long as the user keeps them: no TTL, and none claimed.
    expect(vault?.retention).toEqual({
      policy: "user_controlled",
      max_days: 0,
    });
    // There is NO TTL sweeper anywhere, so the purpose has to say so — an
    // undeclared gap is the `appdata_temp_staging` mistake.
    expect(vault?.purpose).toMatch(/no ttl sweeper|no ttl/i);
    // And the honest ceiling: unreadable without the passphrase, which is not
    // retention, so it is disclosed as a property rather than sold as one.
    expect(vault?.purpose).toMatch(/passphrase/i);
    expect(vault?.purpose).toMatch(/never synced|not synced|sync: never/i);
  });

  it("is erased wholesale by the SPEC-02 IndexedDB sweep", () => {
    // `indexeddbAdapter().purge()` deletes every database the origin holds, so
    // the vault is covered by construction. The declaration has to agree with
    // what that sweep does, or the post-condition reports "clean" while the
    // sealed records survive.
    expect(getEntry(loadManifest(doc), PII_VAULT_KEY)?.erasure).toBe(
      "erase_on_delete_all",
    );
    expect(PII_VAULT_KEY.startsWith("open3dcalc_")).toBe(true);
  });

  it("is at schema version 1, the value PII_SCHEMA_VERSION is pinned to", () => {
    // ADR-001 §3.3 `TODO(hermes)`: `S` is a CONSTANT, not a per-key lookup, so
    // a PII at-rest entry whose `version` moves off 1 will strand every
    // existing envelope for that key the day the lookup lands. This entry
    // starts new, so it starts where the constant points.
    expect(getEntry(loadManifest(doc), PII_VAULT_KEY)?.version).toBe("1.0");
  });
});

describe("SPEC-04: policy_version 1.8 re-consents a 1.6 receipt", () => {
  it("is 1.8", () => {
    expect(doc.policy_version).toBe("1.8");
  });

  it("states why re-consenting is still free — nothing has shipped", async () => {
    // The exemption is a property of the RELEASE STATE, not of the process.
    // Recorded as an assertion so a later reader cannot mistake 1.8 for a
    // routine bump and repeat the reasoning at 1.9 when it is no longer free.
    // 1.7 declared the vault; 1.8 declared `legacy_residue`. Neither had
    // shipped. See SPEC-04 §6.
    const { issueReceipt, evaluateReceipt, receiptDigest } =
      await import("@/shared/lib/consentReceipt");
    const { receipt } = await issueReceipt([PII_VAULT_KEY], ["rehome_pii"]);
    const under1_6 = {
      ...receipt,
      policy_version: "1.6",
      policy_hash: `sha256:${"0".repeat(64)}`,
    };
    const evaluation = await evaluateReceipt({
      receipt: under1_6,
      digest: await receiptDigest(under1_6),
    });
    // `policy_mismatch`, not `tampered`: the receipt is intact, the POLICY the
    // user consented to changed.
    expect(evaluation.status).toBe("policy_mismatch");
    expect(evaluation.consentGiven).toBe(false);
    // The old receipt is retained as history for the delta UI, not discarded.
    expect(evaluation.receipt?.policy_version).toBe("1.6");
    expect(evaluation.currentPolicyVersion).toBe("1.8");
  });

  it("a receipt issued under 1.8 validates, so the re-consent path is reachable", async () => {
    const { issueReceipt } = await import("@/shared/lib/consentReceipt");
    const { receipt } = await issueReceipt([PII_VAULT_KEY], ["rehome_pii"]);
    expect(receipt.policy_version).toBe("1.8");
  });
});

describe("ADR-001 §3.3: the browser and Electron schema versions agree", () => {
  it("matches the pin in electron/cryptoCapability.ts", () => {
    // The two layers cannot import each other today: the main process cannot
    // reach the JSON fixture (node16 ESM output will not execute a static JSON
    // import), and this module is not on the electron build's import allowlist.
    // So the value is duplicated and the DUPLICATION IS PINNED — a drift here
    // would seal browser records under an `S` the desktop build never uses,
    // with no error anywhere.
    const source = readFileSync(
      resolve(
        __dirname,
        "..",
        "..",
        "..",
        "..",
        "electron",
        "cryptoCapability.ts",
      ),
      "utf8",
    );
    const pinned = source.match(/const PII_SCHEMA_VERSION = (\d+);/);
    expect(
      pinned,
      "the electron pin must remain a literal this test can read",
    ).not.toBeNull();
    expect(Number(pinned![1])).toBe(PII_SCHEMA_VERSION);
  });

  it("and the manifest is what will replace both", () => {
    // Neither constant survives the TODO(hermes) per-key lookup: the trusted
    // source is the per-key `version`, so the manifest is the destination for
    // BOTH of these pins, not just the electron one.
    const atRest = doc.keys.filter(
      (k) => k.pii && k.persistence === "encrypted_at_rest",
    );
    expect(atRest.length).toBeGreaterThan(0);
    const drifted = atRest
      .filter((k) => Number(k.version.split(".")[0]) !== PII_SCHEMA_VERSION)
      .map((k) => `${k.key}@${k.version}`);
    expect(
      drifted,
      "PII_SCHEMA_VERSION is a constant on BOTH platforms, not a per-key manifest lookup: bumping a PII key's manifest version strands every existing envelope for that key. Land ADR-001 §3.3 TODO(hermes) first.",
    ).toEqual([]);
  });
});

describe("Egress: dataSync cannot reach the vault", () => {
  let idb: FakeIndexedDb;

  beforeEach(async () => {
    idb = createFakeIndexedDb();
    setPiiStoreEnvironment(PII_STORE_ENVIRONMENT);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
    const options = {
      indexedDb: idb.factory,
      environment: PII_STORE_ENVIRONMENT,
    };
    await unlockPiiStore(CUSTOMERS, PASS, options);
    await createPiiStore(CUSTOMERS, options).write(
      `{"state":{"customers":[{"name":"Fernanda Sintética","tag":"${SENTINEL}"}]},"version":1}`,
    );
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
    window.localStorage.clear();
  });

  it("a sealed vault record never appears in a collected sync bundle", () => {
    // Behavioural half. The sentinel exists only inside the sealed record, so
    // if `collectSyncData()` can reach the vault it WILL show up here.
    expect(idb.raw("envelopes", CUSTOMERS)).toBeTypeOf("string");
    const bundle = JSON.stringify(collectSyncData());
    expect(bundle).not.toContain(SENTINEL);
    expect(bundle).not.toContain("Fernanda");
    // And the three legacy localStorage keys ARE collected, so this is not a
    // vacuous pass caused by the collector returning nothing at all.
    const data = collectSyncData();
    expect(data.customers).toBeDefined();
  });

  it("the vault is absent from the collector's key list, by name", () => {
    const bundle = JSON.stringify(collectSyncData());
    expect(bundle).not.toContain(PII_VAULT_KEY);
  });

  it("dataSync reaches storage only through fixed key literals — never an enumeration", () => {
    // Structural half, pinned so a future `for (const k of something)` cannot
    // quietly widen the egress set to include a surface nobody audited.
    const source = readFileSync(
      resolve(__dirname, "..", "dataSync.ts"),
      "utf8",
    );
    // No IndexedDB access at all: the vault lives there, so this is the
    // structural reason the exclusion holds.
    expect(source).not.toMatch(/indexedDB/);
    // No enumeration of a store: only literal lookups through `guardedStorage`.
    expect(source).not.toMatch(/\.length\s*;?\s*[\s\S]{0,80}localStorage\.key/);
    expect(source).not.toMatch(
      /Object\.(keys|entries|values)\(\s*(window\.)?localStorage/,
    );
    expect(source).not.toMatch(/for\s*\(\s*const\s+\w+\s+in\s+localStorage/);
    // And it does not name the vault at all. (The object-store name
    // `envelopes` is far too generic to assert the absence of in a 40 KB file,
    // so the unambiguous database name is what gets pinned.)
    expect(source).not.toContain(PII_VAULT_KEY);
  });
});
