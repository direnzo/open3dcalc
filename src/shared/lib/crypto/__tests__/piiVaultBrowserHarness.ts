/**
 * The seam the real-browser vault specs share.
 *
 * Two things every `*.browser.test.ts` in `crypto/__tests__` needs, and neither
 * belongs in a spec body:
 *
 *  1. **A database the spec owns.** The vault's port caches one connection per
 *     `VaultIdbFactory` identity and the vault names its database from the
 *     SPEC-01 constant, so two browser spec FILES running concurrently (Vitest
 *     runs files in parallel, and one origin has one IndexedDB) would share one
 *     record set and clobber each other's fixtures. The harness therefore hands
 *     the vault a factory that resolves the SAME real IndexedDB under a
 *     spec-scoped database name. The store, the transactions, the auto-commit
 *     behaviour and the upgrade handshake are the browser's own; only the name
 *     differs. It is deliberately a name substitution and not a store double —
 *     a double is exactly what W6 exists to stop relying on.
 *
 *  2. **A read that does NOT go through the vault.** "The vault encrypts at
 *     rest" is a claim about bytes, and the vault's own `read()` decrypts, so it
 *     can never witness it. The harness reads the records with the DOM's own
 *     `IDBObjectStore` API, and offers the byte-level helpers a plaintext scan
 *     needs.
 *
 * Synthetic fixtures only, never real PII.
 */

import { PII_VAULT_KEY, PII_VAULT_STORE } from "@/shared/lib/crypto/piiStore";
import type {
  VaultIdbFactory,
  VaultIdbOpenRequest,
} from "@/shared/lib/crypto/indexedDbPort";

/** One sealed record, read straight out of the browser's IndexedDB. */
export interface RawVaultRecord {
  key: string;
  raw: string;
}

export interface PiiVaultBrowserHarness {
  /**
   * The spec-scoped database name. Distinct per spec file, so parallel spec
   * files cannot see each other's records.
   */
  readonly databaseName: string;
  /** What the vault is handed: the real IndexedDB, scoped to `databaseName`. */
  readonly indexedDb: VaultIdbFactory;
  /** Every sealed record in the store, unopened. */
  rawRecords(): Promise<RawVaultRecord[]>;
  /** One sealed record, unopened, or null when there is no record. */
  rawRecord(key: string): Promise<string | null>;
  /** Delete every record in the store. */
  clear(): Promise<void>;
}

/**
 * The vault's declared database name, plus a spec-scoped suffix.
 *
 * `PII_VAULT_KEY` is the production name and stays the single declaration of it;
 * this only makes the SAME store addressable per spec file.
 */
export function specDatabaseName(spec: string): string {
  return `${PII_VAULT_KEY}__browser_spec_${spec}`;
}

export function createPiiVaultBrowserHarness(
  spec: string,
): PiiVaultBrowserHarness {
  const databaseName = specDatabaseName(spec);

  // The cast is confined to this one adapter, the same way
  // `idbFactoryFromGlobal()` confines its own: the browser's `IDBFactory`
  // reports `result: IDBDatabase` where the port declares `unknown`. The
  // substitute name is the ONLY thing this adapter changes.
  const indexedDb: VaultIdbFactory = {
    open: (_name: string, version?: number): VaultIdbOpenRequest =>
      globalThis.indexedDB.open(
        databaseName,
        version,
      ) as unknown as VaultIdbOpenRequest,
  };

  let handle: Promise<IDBDatabase> | null = null;

  /**
   * Open the spec's database, creating the object store on first creation.
   *
   * Opened WITHOUT an explicit version on purpose: the vault opens at its own
   * `VAULT_VERSION`, so a spec must not be the thing that pins the schema
   * version. If the database already exists, this joins it at whatever version
   * the vault asked for; if it does not, this creates it and the upgrade
   * callback below creates the store.
   */
  function openDatabase(): Promise<IDBDatabase> {
    const opening = new Promise<IDBDatabase>((resolve, reject) => {
      const request = globalThis.indexedDB.open(databaseName);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(PII_VAULT_STORE)) {
          db.createObjectStore(PII_VAULT_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("[harness] open failed"));
      request.onblocked = () =>
        reject(new Error("[harness] open blocked by another connection"));
    });
    handle = opening.catch((error: unknown) => {
      // A rejected open must not poison the harness for the rest of the spec.
      handle = null;
      throw error;
    });
    return handle;
  }

  function database(): Promise<IDBDatabase> {
    return handle ?? openDatabase();
  }

  async function rawRecords(): Promise<RawVaultRecord[]> {
    const db = await database();
    return new Promise<RawVaultRecord[]>((resolve, reject) => {
      const tx = db.transaction(PII_VAULT_STORE, "readonly");
      const store = tx.objectStore(PII_VAULT_STORE);
      // Both requests are issued before the queue drains, so one transaction
      // serves the pair and `oncomplete` sees both results.
      const keysRequest = store.getAllKeys();
      const valuesRequest = store.getAll();
      tx.oncomplete = () => {
        const keys = keysRequest.result;
        const values = valuesRequest.result;
        resolve(
          keys.map((key, index) => ({
            key: String(key),
            raw: String(values[index]),
          })),
        );
      };
      tx.onerror = () => reject(tx.error ?? new Error("[harness] read failed"));
      tx.onabort = () =>
        reject(tx.error ?? new Error("[harness] read aborted"));
    });
  }

  async function rawRecord(key: string): Promise<string | null> {
    const db = await database();
    const value = await new Promise<unknown>((resolve, reject) => {
      const tx = db.transaction(PII_VAULT_STORE, "readonly");
      const request = tx.objectStore(PII_VAULT_STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("[harness] get failed"));
    });
    return typeof value === "string" ? value : null;
  }

  async function clear(): Promise<void> {
    const db = await database();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(PII_VAULT_STORE, "readwrite");
      tx.objectStore(PII_VAULT_STORE).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () =>
        reject(tx.error ?? new Error("[harness] clear failed"));
      tx.onabort = () =>
        reject(tx.error ?? new Error("[harness] clear aborted"));
    });
  }

  return { databaseName, indexedDb, rawRecords, rawRecord, clear };
}

/** True when `needle` occurs in `haystack` as a byte sequence. */
export function containsBytes(
  haystack: Uint8Array,
  needle: Uint8Array,
): boolean {
  if (needle.length === 0) return true;
  if (needle.length > haystack.length) return false;
  outer: for (
    let start = 0;
    start <= haystack.length - needle.length;
    start++
  ) {
    for (let offset = 0; offset < needle.length; offset++) {
      if (haystack[start + offset] !== needle[offset]) continue outer;
    }
    return true;
  }
  return false;
}

/** Decode the `ct` field of an envelope record into its raw stored bytes. */
export function ciphertextBytes(envelopeJson: string): Uint8Array {
  const parsed = JSON.parse(envelopeJson) as { ct?: unknown };
  if (typeof parsed.ct !== "string") {
    throw new Error("[harness] record carries no base64 `ct` field");
  }
  const binary = atob(parsed.ct);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
