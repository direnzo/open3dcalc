/**
 * The browser PII vault: sealed PII in IndexedDB, and no plaintext path.
 *
 * This is the web build's counterpart to `electron/cryptoCapability.ts`. Until
 * it existed, the three verified-active browser PII keys
 * (`open3dcalc_customers_v1`, `open3dcalc_quotes_v1`, `open3dcalc_history_v2`)
 * were `zustand` stores persisting through `manifestStorage()` straight into
 * `window.localStorage` in plaintext — the single largest remaining gap in the
 * Beta5 remediation. The Electron side had AES-GCM under an OS-backed key;
 * the web side had no encryption path at all.
 *
 * ## Layout
 *
 * One IndexedDB database, `open3dcalc_pii_vault` (the SPEC-01 key), holding one
 * object store, `envelopes`. A record is keyed by the LOGICAL storage key name
 * — the same `K` that goes into the AAD — so "which record" and "which
 * expectation" cannot drift apart. The record's value is a Wave 1 v2 envelope
 * verbatim, which means `decryptWithPassphrase` can still open it and the
 * vault is a storage layer rather than a second envelope format.
 *
 * ## The one structural difference from Wave 1
 *
 * Wave 1 derives a key per call, because it has no session. The vault derives
 * ONCE per unlock and holds the resulting `CryptoKey` in memory:
 *
 *  - a zustand store writes on every state change, and PBKDF2 at 310,000
 *    iterations costs ~30 ms; re-deriving per write would make persistence
 *    the slowest thing in the app;
 *  - the salt is per STORE, generated on first seal and then carried in each
 *    record, so it survives a page reload without a second metadata record.
 *    Carrying it is also what keeps the record self-describing, hence
 *    Wave 1 reader-compatible;
 *  - the key is derived with `extractable: false`, so it cannot be exported
 *    even from a full heap dump.
 *
 * Nothing else changes. The AAD is still `buildAadBytes(expectation)` with the
 * expectation built from the CALLER's key; the record's own `meta` is still
 * unauthenticated metadata that is compared and never trusted.
 *
 * ## The locked path fails closed, and refuses rather than returns empty
 *
 * `zustand` hydrates synchronously at store creation and no store sets
 * `skipHydration` today, so a locked vault cannot "return empty" without
 * handing the store an empty array that it will then persist back over the
 * user's real data. Returning empty is data loss wearing a lock's clothing.
 * So a locked read/write THROWS a typed refusal, and the wiring that migrates
 * the three stores is expected to set `skipHydration: true` and call
 * `rehydrate()` after unlock. That is the documented design decision, and the
 * alternatives were rejected for the same reason: see the header of
 * `piiPersistStorage` below.
 *
 * Synthetic fixtures only, in tests. Real Web Crypto, no crypto mocks
 * (TEST-MATRIX §0).
 */

import type { PersistStorage, StorageValue } from "zustand/middleware";
import {
  AT_REST_PURPOSE,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  ENVELOPE_VERSION,
  PBKDF2_ITERATIONS,
  buildAadBytes,
  type AtRestEnvelope,
  type EnvelopeExpectation,
} from "./envelope.js";
import { PII_SCHEMA_VERSION } from "./piiSchemaVersion.js";
// Only the WRITE side of the session is used. The vault never calls
// `getSessionPassphrase()`: it holds the non-extractable derived `CryptoKey`,
// so there is no passphrase string to re-read on the hot path, and
// `setSessionPassphrase` records that a session is open for the rest of the app
// (ADR-001 §2.3 "hasPassphrase"), which is consumed by `capability.ts`.
import {
  setSessionPassphrase,
  zeroizeSessionPassphrase,
} from "./passphraseSession.js";
import {
  piiStoreRefusalReason,
  setPiiStoreEnvironment,
  type PiiStoreDenialReason,
  type PiiStoreEnvironment,
} from "./piiStoreCapability.js";
import {
  idbFactoryFromGlobal,
  openVaultIdb,
  type VaultIdb,
  type VaultIdbFactory,
} from "./indexedDbPort.js";

/** SPEC-01 key AND IndexedDB database name. One declared surface. */
export const PII_VAULT_KEY = "open3dcalc_pii_vault";

/** Object store inside the vault. */
export const PII_VAULT_STORE = "envelopes";

/** IDB schema version of the vault. Bump on a structural change. */
const VAULT_VERSION = 1;

/** 128-bit salt, matching the Wave 1 envelope's `SALT_BYTES`. */
const SALT_BYTES = 16;
/** 96-bit nonce, matching the Wave 1 envelope's `IV_BYTES`. */
const IV_BYTES = 12;
/** 128-bit GCM tag, matching the Wave 1 envelope. */
const TAG_BITS = 128;

// ---------------------------------------------------------------------------
//  Typed failures. Every refusal is explicit and carries a reason code that is
//  always a compile-time constant, so nothing derived from a PII value can
//  reach it (TEST-MATRIX §3.2 — logs and errors carry key NAMES, never values).
// ---------------------------------------------------------------------------

/** The gate refused: locked, no capability, insecure context, or declined. */
export class PiiStoreDeniedError extends Error {
  readonly reason: PiiStoreDenialReason;
  constructor(reason: PiiStoreDenialReason) {
    super(`[piiStore] PII vault access denied (${reason})`);
    this.name = "PiiStoreDeniedError";
    this.reason = reason;
  }
}

/**
 * Why a stored record was refused.
 *
 * Deliberately the envelope's own vocabulary plus one addition, so an operator
 * reading a vault refusal and an envelope refusal sees one language:
 *  - `salt_mismatch` is the vault's own: the record carries a salt that is not
 *    this store's. The GCM tag would catch it anyway, but an unnamed
 *    authentication failure on a real record is the worst possible diagnostic,
 *    and the salt is unauthenticated metadata — binding it to the store is a
 *    real check rather than decoration.
 */
export type PiiStoreRecordRejection =
  | "malformed_record"
  | "unknown_envelope_version"
  | "parameter_drift"
  | "metadata_mismatch"
  | "salt_mismatch"
  | "authentication_failed";

export class PiiStoreRecordRejectedError extends Error {
  readonly reason: PiiStoreRecordRejection;
  constructor(reason: PiiStoreRecordRejection) {
    super(`[piiStore] stored record rejected (${reason})`);
    this.name = "PiiStoreRecordRejectedError";
    this.reason = reason;
  }
}

export type PiiStoreWriteRejection =
  /** The value cannot be serialised, so it was never offered to the cipher. */
  | "unserializable_value"
  /** A derived key is not held, so there is nothing to seal with. */
  | "seal_unavailable"
  /** IndexedDB refused or aborted the write. */
  | "commit_failed";

export class PiiStoreWriteError extends Error {
  readonly reason: PiiStoreWriteRejection;
  constructor(reason: PiiStoreWriteRejection) {
    super(`[piiStore] write rejected (${reason})`);
    this.name = "PiiStoreWriteError";
    this.reason = reason;
  }
}

// ---------------------------------------------------------------------------
//  The caller-trusted expectation
// ---------------------------------------------------------------------------

/**
 * The AAD expectation for one logical storage key.
 *
 * `K` is the CALLER's argument. `P`, `S` and `F` come from the pinned shared
 * constants — a vault that hardcoded `S = 1` would look identical today and be
 * silently wrong the day a PII key's schema version moves, with no test failing
 * and no error at runtime. `P`/`S`/`F` are the component of the ADR-001 §3.3
 * `TODO(hermes)` landmine and are pinned by test.
 */
export function vaultExpectationFor(key: string): EnvelopeExpectation {
  return {
    key,
    purpose: AT_REST_PURPOSE,
    schemaVersion: PII_SCHEMA_VERSION,
    envelopeFormatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
  };
}

// ---------------------------------------------------------------------------
//  Byte helpers
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array<ArrayBuffer>): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(
  hex: string,
  expectedBytes: number,
): Uint8Array<ArrayBuffer> | null {
  if (typeof hex !== "string" || !/^[0-9a-f]+$/.test(hex)) return null;
  if (hex.length !== expectedBytes * 2) return null;
  const out = new Uint8Array(new ArrayBuffer(expectedBytes));
  for (let i = 0; i < expectedBytes; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toBase64(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(count: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(count));
  globalThis.crypto.getRandomValues(out);
  return out;
}

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new PiiStoreDeniedError("web_crypto_unavailable");
  return c.subtle;
}

// ---------------------------------------------------------------------------
//  Runtime state: held keys and the write queue
// ---------------------------------------------------------------------------

/**
 * Derived keys, in memory only. `extractable: false` means these cannot be
 * exported, and nothing writes them anywhere: the salt they were derived from
 * travels in the record, and the key never does.
 */
const heldKeys = new Map<
  string,
  { key: CryptoKey; salt: Uint8Array<ArrayBuffer> }
>();

/**
 * One write at a time per store, as a promise chain.
 *
 * A readwrite transaction auto-commits as soon as its request queue drains, so
 * an `await` of the cipher between opening a transaction and issuing its
 * `put` yields `TransactionInactiveError` — and two writers in flight at once
 * could interleave into a record neither of them wrote. The vault never holds a
 * transaction open across crypto: the seal is computed first, and only the
 * single `put` runs inside a transaction. The queue is the second half, and it
 * is what makes "at most one readwrite transaction open" a property rather
 * than a hope.
 */
const writeQueues = new Map<string, Promise<unknown>>();

function enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
  const previous = writeQueues.get(key) ?? Promise.resolve();
  // `then(task, task)`: a failed predecessor must not wedge the queue.
  const next = previous.then(task, task);
  writeQueues.set(
    key,
    next.then(
      () => undefined,
      () => undefined,
    ),
  );
  return next;
}

/**
 * One port per factory, so every store in one database shares one connection.
 * Weak on the factory: a discarded factory takes its handle with it, which is
 * what lets tests run against a fresh in-memory origin without leaking state.
 */
const vaultPorts = new WeakMap<VaultIdbFactory, VaultIdb>();

function portFor(factory: VaultIdbFactory): VaultIdb {
  const existing = vaultPorts.get(factory);
  if (existing) return existing;
  const port = openVaultIdb(
    factory,
    PII_VAULT_KEY,
    PII_VAULT_STORE,
    VAULT_VERSION,
  );
  vaultPorts.set(factory, port);
  return port;
}

// ---------------------------------------------------------------------------
//  Sealing and opening
// ---------------------------------------------------------------------------

interface HeldKey {
  key: CryptoKey;
  salt: Uint8Array<ArrayBuffer>;
}

async function deriveHeldKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  const material = await subtle().importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle().deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    // Non-extractable: the session key cannot leave Web Crypto, so it cannot
    // be written anywhere, logged, or lifted out of a heap dump.
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(
  held: HeldKey,
  plaintext: string,
  expectation: EnvelopeExpectation,
  salt: Uint8Array<ArrayBuffer>,
): Promise<string> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle().encrypt(
    {
      name: "AES-GCM",
      iv,
      // The CALLER's expectation, never the record's metadata.
      additionalData: buildAadBytes(expectation),
      tagLength: TAG_BITS,
    },
    held.key,
    new TextEncoder().encode(plaintext),
  );
  const envelope: AtRestEnvelope = {
    v: ENVELOPE_VERSION,
    kdf: { alg: "PBKDF2-SHA256", it: PBKDF2_ITERATIONS, salt: toHex(salt) },
    cipher: { alg: "AES-256-GCM", iv: toHex(iv) },
    meta: { ...expectation },
    ct: toBase64(new Uint8Array(ciphertext)),
  };
  return JSON.stringify(envelope);
}

/**
 * Parse a stored record, refusing anything this build has no reader for.
 *
 * `meta` is parsed but NOT trusted — it is only ever compared, against the
 * caller's expectation, further down. That asymmetry is the whole point: a
 * reader that re-derived the AAD from these four fields would let a ciphertext
 * be moved to another key and opened cleanly, which is the defect ADR-001 §2.4
 * remediated in Wave 1.
 */
function parseRecord(raw: string): {
  version: string;
  kdfAlg: unknown;
  kdfIterations: unknown;
  salt: Uint8Array<ArrayBuffer> | null;
  cipherAlg: unknown;
  iv: Uint8Array<ArrayBuffer> | null;
  meta: Record<string, unknown>;
  ciphertext: string;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  const record = parsed as Record<string, unknown>;
  const kdf = record.kdf;
  const cipher = record.cipher;
  if (typeof kdf !== "object" || kdf === null || Array.isArray(kdf)) {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  if (typeof cipher !== "object" || cipher === null || Array.isArray(cipher)) {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  const kdfRecord = kdf as Record<string, unknown>;
  const cipherRecord = cipher as Record<string, unknown>;
  if (typeof record.v !== "string") {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  if (typeof record.ct !== "string") {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  // A missing or non-object `meta` is a STRUCTURAL fault, not a disagreement:
  // reporting it as a mismatch would tell an operator the record was written
  // by a different contract, when in fact it carries no identity at all.
  if (
    typeof record.meta !== "object" ||
    record.meta === null ||
    Array.isArray(record.meta)
  ) {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  return {
    version: record.v,
    kdfAlg: kdfRecord.alg,
    kdfIterations: kdfRecord.it,
    salt: fromHex(String(kdfRecord.salt ?? ""), SALT_BYTES),
    cipherAlg: cipherRecord.alg,
    iv: fromHex(String(cipherRecord.iv ?? ""), IV_BYTES),
    meta: record.meta as Record<string, unknown>,
    ciphertext: record.ct,
  };
}

function metaMatches(meta: Record<string, unknown>, key: string): boolean {
  const expectation = vaultExpectationFor(key);
  return (
    meta.key === expectation.key &&
    meta.purpose === expectation.purpose &&
    meta.schemaVersion === expectation.schemaVersion &&
    meta.envelopeFormatVersion === expectation.envelopeFormatVersion
  );
}

async function open(raw: string, held: HeldKey, key: string): Promise<string> {
  const record = parseRecord(raw);
  if (record.version !== ENVELOPE_VERSION) {
    throw new PiiStoreRecordRejectedError("unknown_envelope_version");
  }
  // Parameters are declared by the VERSION, not read from the ciphertext: a
  // record naming a different work factor is refused, never derived with.
  if (
    record.kdfAlg !== "PBKDF2-SHA256" ||
    record.kdfIterations !== PBKDF2_ITERATIONS
  ) {
    throw new PiiStoreRecordRejectedError("parameter_drift");
  }
  if (record.cipherAlg !== "AES-256-GCM") {
    throw new PiiStoreRecordRejectedError("parameter_drift");
  }
  if (record.salt === null || record.iv === null) {
    throw new PiiStoreRecordRejectedError("malformed_record");
  }
  // The salt is unauthenticated metadata in the record, so it is checked
  // against this store's salt rather than trusted to select the key.
  if (toHex(record.salt) !== toHex(held.salt)) {
    throw new PiiStoreRecordRejectedError("salt_mismatch");
  }
  if (!metaMatches(record.meta, key)) {
    throw new PiiStoreRecordRejectedError("metadata_mismatch");
  }
  try {
    const plaintext = await subtle().decrypt(
      {
        name: "AES-GCM",
        iv: record.iv,
        // Built from the CALLER's expectation, full stop.
        additionalData: buildAadBytes(vaultExpectationFor(key)),
        tagLength: TAG_BITS,
      },
      held.key,
      fromBase64(record.ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new PiiStoreRecordRejectedError("authentication_failed");
  }
}

// ---------------------------------------------------------------------------
//  Options and environment sampling
// ---------------------------------------------------------------------------

export interface PiiStoreOptions {
  /**
   * The IndexedDB to write into, injected rather than reached for.
   *
   * EXPLICIT AND INJECTABLE ON PURPOSE. The Electron main process has no
   * IndexedDB, so a module that read the global ambiently would either fail to
   * compile there or, worse, compile and throw at call time. Injected, the
   * absence is a typed refusal (`indexeddb_unavailable`) instead of a crash.
   * Defaults to `globalThis.indexedDB` when one is present.
   */
  indexedDb?: VaultIdbFactory | undefined;
  /**
   * Capability overrides merged over the sampled environment. The vault is
   * fail-closed, so an override is how a caller states "this context is fine"
   * in a runtime that cannot report it — and how a test states a context that
   * is not.
   */
  environment?: Partial<PiiStoreEnvironment> | undefined;
}

function factoryFrom(options: PiiStoreOptions): VaultIdbFactory | null {
  return options.indexedDb ?? idbFactoryFromGlobal();
}

/**
 * Is there a browser here, and is it a secure origin?
 *
 * A guarded read, never a module-scope global: the Electron main process has
 * no `window`, so sampling it at import time would throw there. The
 * `typeof` check makes "no browser" a REPORTED fact (`not_a_browser`) instead
 * of a load-time crash.
 */
function sampleBrowser(): {
  browser: boolean | undefined;
  secureContext: boolean | undefined;
} {
  const scope = globalThis as { window?: { isSecureContext?: boolean } };
  if (typeof scope.window === "undefined" || scope.window === null) {
    return { browser: false, secureContext: undefined };
  }
  return { browser: true, secureContext: scope.window.isSecureContext };
}

/**
 * Sample the runtime and install the snapshot at the choke point.
 *
 * An injected factory counts as an available store: the question the gate asks
 * is "is there somewhere to write", and an injected factory is that somewhere.
 * Without this, jsdom (which has no IndexedDB at all) could never exercise a
 * capable vault.
 */
export function installPiiStoreEnvironment(
  options: PiiStoreOptions = {},
): PiiStoreEnvironment {
  const sampled: PiiStoreEnvironment = {
    ...sampleBrowser(),
    webCryptoAvailable: globalThis.crypto?.subtle !== undefined,
    indexedDbAvailable: factoryFrom(options) !== null,
  };
  const merged: PiiStoreEnvironment = { ...sampled, ...options.environment };
  setPiiStoreEnvironment(merged);
  return merged;
}

// ---------------------------------------------------------------------------
//  Public surface
// ---------------------------------------------------------------------------

/** The held derived key for a store, or null. Exported for the export test. */
export function heldKeyForTests(key: string): CryptoKey | null {
  return heldKeys.get(key)?.key ?? null;
}

/**
 * True while this store's derived session key is held in memory.
 *
 * The locked shell's startup wake reads this to answer "is there a key to
 * rehydrate with?" WITHOUT opening storage: a locked store must not be read,
 * and `createPiiStore(key).isUnlocked()` would need a factory the caller may
 * not have. Keyed by the logical storage key alone, like the held-key map.
 */
export function isPiiStoreUnlocked(key: string): boolean {
  return heldKeys.has(key);
}

/** Drop every held key and pending write chain. Test-only. */
export function resetPiiStoreRuntimeForTests(): void {
  heldKeys.clear();
  writeQueues.clear();
}

/**
 * Derive and hold the session key for one store, verifying the passphrase
 * against the existing record before it is accepted.
 *
 * A wrong passphrase fails HERE, at unlock, rather than on some later read —
 * and a failure never writes. The one copy of the user's data is left exactly
 * as it was, because "retrying" a wrong passphrase by re-sealing the record
 * would destroy it.
 */
export async function unlockPiiStore(
  key: string,
  passphrase: string,
  options: PiiStoreOptions = {},
): Promise<void> {
  installPiiStoreEnvironment(options);
  const factory = factoryFrom(options);
  if (factory === null) {
    throw new PiiStoreDeniedError("indexeddb_unavailable");
  }
  if (passphrase.length === 0) {
    throw new PiiStoreDeniedError("profile_locked");
  }
  // Gate BEFORE touching storage: an insecure context must not even be able to
  // open the database.
  const refusal = piiStoreRefusalReason(false);
  if (refusal !== null) throw new PiiStoreDeniedError(refusal);

  const raw = await portFor(factory).get(key);
  // The store's salt is the one already in the record, or a fresh random one
  // when there is no record yet. Keeping it in the record is what makes the
  // record self-describing across a page reload.
  const salt =
    raw === null
      ? randomBytes(SALT_BYTES)
      : (parseRecord(raw).salt ?? randomBytes(SALT_BYTES));
  const derived = await deriveHeldKey(passphrase, salt);

  if (raw !== null) {
    // Verify before caching: a key derived from the wrong passphrase is
    // indistinguishable from a corrupt record until something tries to use it.
    try {
      await open(raw, { key: derived, salt }, key);
    } catch (error) {
      // Drop any key held from an earlier successful unlock. Leaving it would
      // mean a failed unlock attempt still left the vault READABLE, so a UI
      // reporting "wrong passphrase" would be describing a session that
      // quietly keeps handing the data back.
      heldKeys.delete(key);
      if (error instanceof PiiStoreRecordRejectedError) throw error;
      throw new PiiStoreRecordRejectedError("authentication_failed");
    }
  }

  heldKeys.set(key, { key: derived, salt });
  setSessionPassphrase(passphrase);
}

/** Zeroize one store's held key. Irreversible; the record is untouched. */
export function lockPiiStore(key: string): void {
  heldKeys.delete(key);
}

/** Zeroize every held key and the session passphrase. */
export function lockAllPiiStores(): void {
  heldKeys.clear();
  zeroizeSessionPassphrase();
}

export interface PiiStore {
  /** The logical storage key this handle reads and writes. */
  readonly key: string;
  /** True only while a derived key is held in memory. */
  isUnlocked(): boolean;
  /** The stored plaintext, or null when there is no record. */
  read(): Promise<string | null>;
  /** Seal and store `plaintext`, replacing any existing record. */
  write(plaintext: string): Promise<void>;
  /** Delete the record. Locking is not deletion. */
  remove(): Promise<void>;
  /** Whether a record exists, without opening it. */
  exists(): Promise<boolean>;
}

export function createPiiStore(
  key: string,
  options: PiiStoreOptions = {},
): PiiStore {
  installPiiStoreEnvironment(options);
  // Refuse AT CONSTRUCTION when this environment can never support the vault.
  // Every operation would refuse anyway, but an inert handle is an invitation:
  // a future caller could hold one, assume it works, and ship a path that
  // silently persists nothing. `locked` is deliberately NOT consulted here — a
  // handle is created before any passphrase exists, and the per-operation check
  // covers the lock.
  const refusal = piiStoreRefusalReason(false);
  if (refusal !== null) throw new PiiStoreDeniedError(refusal);
  const factory = factoryFrom(options);

  function requirePort(): VaultIdb {
    if (factory === null) {
      throw new PiiStoreDeniedError("indexeddb_unavailable");
    }
    return portFor(factory);
  }

  /** Every read and write goes through here. A refusal is never silent. */
  function requireAllowed(): void {
    const refusal = piiStoreRefusalReason(!heldKeys.has(key));
    if (refusal !== null) throw new PiiStoreDeniedError(refusal);
  }

  function requireHeld(): HeldKey {
    const held = heldKeys.get(key);
    if (!held) throw new PiiStoreWriteError("seal_unavailable");
    return held;
  }

  return {
    key,

    isUnlocked(): boolean {
      return heldKeys.has(key);
    },

    async read(): Promise<string | null> {
      requireAllowed();
      const held = requireHeld();
      const raw = await requirePort().get(key);
      if (raw === null) return null;
      return open(raw, held, key);
    },

    async write(plaintext: string): Promise<void> {
      requireAllowed();
      if (typeof plaintext !== "string" || plaintext.length === 0) {
        // Refused BEFORE any crypto and before the record is opened, so a
        // rejected write cannot damage the record it failed to replace.
        throw new PiiStoreWriteError("unserializable_value");
      }
      const idb = requirePort();
      const held = requireHeld();
      // Seal outside the queue: the queue exists to serialise TRANSACTIONS,
      // and holding one open across an `await` of the cipher is the
      // auto-commit bug this whole shape is built to avoid.
      const envelope = await seal(
        held,
        plaintext,
        vaultExpectationFor(key),
        held.salt,
      );
      await enqueue(key, async () => {
        try {
          await idb.put(key, envelope);
        } catch {
          throw new PiiStoreWriteError("commit_failed");
        }
      });
    },

    async remove(): Promise<void> {
      requireAllowed();
      const idb = requirePort();
      await enqueue(key, async () => {
        try {
          await idb.delete(key);
        } catch {
          throw new PiiStoreWriteError("commit_failed");
        }
      });
    },

    async exists(): Promise<boolean> {
      requireAllowed();
      return (await requirePort().get(key)) !== null;
    },
  };
}

/**
 * A zustand `PersistStorage` over the vault, ready to drop into `persist({...})`.
 *
 * ## The locked-path decision, stated once
 *
 * Two designs were available and the second one is a data-loss bug:
 *
 *  - **Return empty while locked.** A zustand store that hydrates from an
 *    empty read gets its initial state, and its first `set()` persists that
 *    initial state — an empty customer list written straight over the user's
 *    real one. The store looks healthy, the data is gone, and the failure is
 *    invisible until someone notices their quotes are missing.
 *  - **Refuse, and let the caller choose when to hydrate.** `getItem` rejects
 *    with `PiiStoreDeniedError`, so nothing is ever hydrated from a locked
 *    read, and `setItem` rejects too, so an unhydrated store cannot persist
 *    over what it never read. Migrating a store therefore means
 *    `skipHydration: true` plus an explicit `rehydrate()` after unlock — the
 *    alternative, hydrating with a swallowing `getItem`, is the empty-array bug
 *    with extra steps.
 *
 * `getItem`/`setItem`/`removeItem` are therefore all async, which is also why
 * `skipHydration` is required at the call site: a store must not begin
 * hydration at construction time, before a passphrase exists.
 */
export function piiPersistStorage<S>(
  key: string,
  options: PiiStoreOptions = {},
): PersistStorage<S, Promise<void>> {
  const store = createPiiStore(key, options);
  return {
    // The zustand contract passes the storage key name to all three methods.
    // This vault is bound to ONE key at construction, so the name is not
    // declared and not used: honouring it would let a caller address a record
    // the vault was never opened for, under an expectation built from a
    // different `K`.
    async getItem(): Promise<StorageValue<S> | null> {
      const raw = await store.read();
      if (raw === null) return null;
      return JSON.parse(raw) as StorageValue<S>;
    },
    async setItem(_name: string, value: StorageValue<S>): Promise<void> {
      let serialized: string;
      try {
        // `JSON.stringify(undefined)` returns undefined rather than throwing,
        // so a falsy result is a rejection in its own right: sealing the
        // literal string "undefined" would hand the store back a value it
        // never wrote, on the next read.
        const json = JSON.stringify(value);
        if (typeof json !== "string") {
          throw new PiiStoreWriteError("unserializable_value");
        }
        serialized = json;
      } catch (error) {
        if (error instanceof PiiStoreWriteError) throw error;
        throw new PiiStoreWriteError("unserializable_value");
      }
      await store.write(serialized);
    },
    async removeItem(): Promise<void> {
      await store.remove();
    },
  };
}

// Referenced by the doc comment on `PiiStoreOptions.environment`; re-exported
// so a caller wiring the vault does not have to reach into the capability
// module just for the type.
export type {
  PiiStoreEnvironment,
  PiiStoreDenialReason,
} from "./piiStoreCapability.js";
