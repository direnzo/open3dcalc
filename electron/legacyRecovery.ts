/**
 * ADR-001 §3.6 recovery, and per-key hydration isolation.
 *
 * ## Why this module exists
 *
 * Two shapes of at-rest value reached a packaged build and are refused by name
 * on the normal read path:
 *
 *  - `enc1:safeStorage:<base64>` — the pre-remediation primary path: a raw
 *    `safeStorage.encryptString` output. It carries **no AAD at all**, so it is
 *    bound to nothing, and that is the whole reason it is refused (§3.4).
 *  - `enc1:envelope:{…}` with `v: "1.1"` — the pre-remediation passphrase path,
 *    whose AAD was `canonicalJson({purpose, key})` with **both halves read back
 *    out of the ciphertext** (§3.3).
 *
 * Refusing them is the right crypto call and, on its own, a bad user outcome: the
 * refusal propagated out of `gateLoad` → `db:load` → the renderer's
 * `loadFromDatabase`, so ONE unreadable row rejected the WHOLE hydration,
 * `initPersistenceBridge` never registered its interval or `beforeunload`
 * handler, and the app could not start. The OS keyring was the *default* path
 * before the Wave 2 remediation, so these are the rows a normal upgrading user
 * is most likely to have.
 *
 * This module provides the two halves of the fix:
 *
 *  1. `hydrateAll` — per-key isolation. A key that cannot be read is QUARANTINED
 *     and reported with a reason; every other key still loads.
 *  2. `recoverLegacyKey` — the §3.6 recovery, for both legacy shapes.
 *
 * ## The §3.6 order is enforced by the code, not by a comment
 *
 *   copy → re-seal under the new bound envelope → VERIFY by a fresh
 *   authenticated read-back → only then is the legacy copy resolved
 *
 * `copy` is a real copy: the legacy ciphertext is INSERTed into `legacy_residue`
 * (migration 0005) byte for byte BEFORE the `storage` row is touched, and it is
 * never deleted afterwards. `verify` is a real read-back through the normal
 * bound path, comparing the full payload — a re-seal that "looks fine" is not a
 * recovery, and without the read-back a write that silently wrote the wrong bytes
 * would report success.
 *
 * ## Copy-and-never-delete
 *
 * The legacy blob is RETAINED as disclosed residue. Deleting it is not safe and
 * is not what this module does: no mechanism can prove that an old client is not
 * still writing that row, and the passphrase fallback never replicated the value
 * anywhere else, so a delete is unrecoverable by construction. The user removes
 * the residue through the existing SPEC-02 erasure flow, which covers
 * `legacy_residue` via `PII_ERASURE_TABLES`.
 *
 * ## The reader is QUARANTINED
 *
 * `readLegacyValue` reads the two legacy shapes and nothing else. It is not
 * exported through `cryptoCapability` and it refuses any other input — in
 * particular a CURRENT `2.0` envelope — because a reader that would open those
 * too would be a general-purpose decrypt path that ignores the AAD, i.e. exactly
 * the defect §3.2 exists to remove. The 1.1 reader in particular cannot
 * authenticate provenance at all; that is why §3.3 refuses it, and why the only
 * thing this module does with a 1.1 value is re-seal it under a real AAD.
 *
 * All logging here is metadata only: key NAMES, shapes and reason codes, never a
 * value (§3.2).
 *
 * ## Dependency direction
 *
 * This module DEPENDS ON `persistGate` (for `resolveKeyPolicy` and the per-key
 * load), never the reverse — `persistGate` knows nothing about recovery. The
 * relationship is acyclic and is meant to stay that way: a `persistGate` that
 * imported recovery back would put the §3.6 legacy reader on the ordinary read
 * path, which is the one thing §3.2 and §3.3 exist to prevent.
 *
 * Stated explicitly because these were `await import()` calls at first, on a
 * guess that `persistGate` would grow a dependency on this module. It does not,
 * and the dynamic form was pure cost: it deferred a load error to call time,
 * made the dependency invisible to anyone reading the imports, and gave a
 * bundler no reason to fail loudly on a real cycle. If a cycle ever appears,
 * the fix is to move the SHARED piece into a leaf module — the same move
 * `unavailableClasses.ts` exists for on the renderer side — not to reach for
 * `await import()` again.
 */

import { safeStorage } from "electron";
import {
  CryptoDeniedError,
  LegacyUnboundBlobError,
  encryptForStorage,
  decryptFromStorage,
} from "./cryptoCapability.js";
import { getSessionPassphrase } from "../src/shared/lib/crypto/passphraseSession.js";
import {
  canonicalJson,
  PBKDF2_ITERATIONS,
} from "../src/shared/lib/crypto/envelope.js";
import { LEGACY_RESIDUE_TABLE } from "./piiDomainTables.js";
import {
  resolveKeyPolicy,
  loadRowForHydration,
  type MinimalStorageDb,
} from "./persistGate.js";

/** The pre-remediation primary shape: raw keyring output, no AAD. */
const LEGACY_SAFE_STORAGE_PREFIX = "enc1:safeStorage:";

/** The pre-remediation passphrase shape. */
const LEGACY_ENVELOPE_PREFIX = "enc1:envelope:";

/** The only legacy envelope version this module can read. */
const LEGACY_ENVELOPE_VERSION = "1.1";

/** What a quarantined key is, and why it is not hydrated. */
export type UnreadableReason =
  /** The pre-remediation keyring blob: no AAD, so bound to nothing. */
  | "legacy_unbound_encryption"
  /** A legacy 1.1 envelope: self-asserted AAD, provenance unauthenticable. */
  | "legacy_envelope_v1_1"
  /** The blob is present but no key can open it (rotated keyring, wrong key). */
  | "legacy_undecryptable"
  /** The blob's own metadata names a DIFFERENT storage key — it was moved. */
  | "legacy_key_mismatch"
  /** A current bound envelope failed its own authentication. */
  | "authentication_failed"
  /** The crypto capability resolved DENIED, so nothing can be read. */
  | "no_capability"
  /** The session was locked, so no passphrase-derived value can be read. */
  | "locked"
  /** The key is not in the SPEC-01 manifest (default-deny). */
  | "unknown_key";

export interface UnavailableKey {
  key: string;
  reason: UnreadableReason;
  /**
   * True when §3.6 recovery could still be attempted: the bytes are intact and
   * the blocker is only that the old shape is refused. False means the value is
   * unrecoverable and the user must be told so rather than offered a retry.
   */
  recoverable: boolean;
}

export interface HydrationReport {
  /** Keys that loaded. A quarantined key is ABSENT here, never empty-string. */
  values: Map<string, string>;
  /** Keys that did not, each with a reason. */
  unavailable: UnavailableKey[];
}

/* ------------------------------------------------------------------ */
/*  The quarantined legacy reader                                       */
/* ------------------------------------------------------------------ */

type LegacyShape = "enc1:safeStorage" | "enc1:envelope-v1.1";

/** Raised for anything the quarantined reader will not open. */
export class LegacyUnreadableError extends Error {
  readonly reason: UnreadableReason;
  constructor(reason: UnreadableReason, message: string) {
    super(message);
    this.name = "LegacyUnreadableError";
    this.reason = reason;
  }
}

/**
 * The IPC-facing refusal for "this key exists and cannot be read".
 *
 * It exists because of what `ipcRenderer.invoke` does to an error: Electron
 * flattens a thrown error into the string `Error invoking remote method
 * 'db:load': <message>` and DROPS every structured field, so `reason` and `code`
 * do not survive the boundary and the renderer can only see prose. That is the
 * "reason dropped at the invoke boundary" defect. The reason code is therefore
 * interpolated into the MESSAGE, deliberately, so the one channel that does
 * survive carries it — and `persistence-bridge.refusalCodeFromError` parses that
 * exact code back out.
 *
 * The key NAME is in the message too: a name is metadata, not a value (§3.2),
 * and without it the renderer cannot say which class is unavailable.
 */
export class UnreadablePiiValueError extends Error {
  readonly code = "unreadable_pii_value";
  readonly reason: string;
  readonly key: string;
  constructor(key: string, reason: string) {
    super(
      `[cryptoCapability] ${key} is stored but unreadable (${reason}) — the value is NOT hydrated and NOT deleted`,
    );
    this.name = "UnreadablePiiValueError";
    this.reason = reason;
    this.key = key;
  }
}

function classifyLegacy(blob: string): LegacyShape | null {
  if (blob.startsWith(LEGACY_SAFE_STORAGE_PREFIX)) return "enc1:safeStorage";
  if (!blob.startsWith(LEGACY_ENVELOPE_PREFIX)) return null;
  // Only 1.1. A `2.0` envelope is CURRENT and bound; letting the legacy reader
  // open it would be a decrypt path that ignores the AAD.
  let parsed: unknown;
  try {
    parsed = JSON.parse(blob.slice(LEGACY_ENVELOPE_PREFIX.length));
  } catch {
    return null;
  }
  if (
    typeof parsed === "object" &&
    parsed !== null &&
    (parsed as Record<string, unknown>).v === LEGACY_ENVELOPE_VERSION
  ) {
    return "enc1:envelope-v1.1";
  }
  return null;
}

const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/**
 * `Uint8Array<ArrayBuffer>`, not `Uint8Array<ArrayBufferLike>`.
 *
 * The explicit type argument is what satisfies Web Crypto's `BufferSource`,
 * which narrows to a non-shared buffer. A plain `new Uint8Array(n)` infers
 * `ArrayBuffer` on its own, so this is only needed where the value is produced
 * by a helper whose return type was widened — and widening it back to
 * `ArrayBufferLike` is what breaks `subtle.decrypt`/`digest` at compile time.
 */
const fromHex = (hex: string, bytes: number): Uint8Array<ArrayBuffer> => {
  if (hex.length !== bytes * 2 || /[^0-9a-f]/.test(hex)) {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] malformed legacy field",
    );
  }
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

/**
 * The 1.1 reader.
 *
 * A 1.1 envelope authenticated `canonicalJson({purpose, key})` with BOTH halves
 * taken from the ciphertext's own `meta`, so the tag proves the bytes are
 * internally consistent and proves nothing about where they came from. There is
 * no way to re-authenticate one under the caller-trusted AAD. The single
 * property this reader CAN establish is consistency with the row it was found
 * in: if `meta.key` names a different storage key, the blob was moved, and that
 * is refused.
 */
async function readLegacyV11(
  env: Record<string, unknown>,
  passphrase: string,
  requestedKey: string,
): Promise<string> {
  const meta = env.meta as Record<string, unknown> | undefined;
  if (typeof meta !== "object" || meta === null) {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope has no meta",
    );
  }
  if (typeof meta.key !== "string" || typeof meta.purpose !== "string") {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope meta is malformed",
    );
  }
  if (meta.key !== requestedKey) {
    // The 1.1 AAD was self-asserted, so this is the ONLY relocation check
    // available — and it is a real one: the row says `requestedKey`, the
    // ciphertext says `meta.key`, and they disagree.
    throw new LegacyUnreadableError(
      "legacy_key_mismatch",
      "[legacyRecovery] legacy envelope was found under a different storage key",
    );
  }

  const kdf = env.kdf as Record<string, unknown> | undefined;
  const cipher = env.cipher as Record<string, unknown> | undefined;
  if (
    typeof kdf !== "object" ||
    kdf === null ||
    typeof cipher !== "object" ||
    cipher === null ||
    typeof env.ct !== "string"
  ) {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope is malformed",
    );
  }
  if (kdf.alg !== "PBKDF2-SHA256" || cipher.alg !== "AES-256-GCM") {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope names an unknown algorithm",
    );
  }
  // Derived with the factor the record DECLARES, because a 1.1 value is
  // historical and may name either work factor (ADR-001 §3.5). Bounded to the
  // two factors this repo has ever used: an attacker-declared factor is not a
  // free choice of work, and an unbounded one is a DoS on the main process.
  const iterations = kdf.it;
  if (iterations !== PBKDF2_ITERATIONS && iterations !== 100_000) {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope declares an unknown work factor",
    );
  }
  const salt = fromHex(String(kdf.salt), 16);
  const iv = fromHex(String(cipher.iv), 12);
  const enc = new TextEncoder();
  const base = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const derived = await globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  try {
    const pt = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: enc.encode(
          canonicalJson({ key: meta.key, purpose: meta.purpose }),
        ),
        tagLength: 128,
      },
      derived,
      Buffer.from(env.ct, "base64"),
    );
    return new TextDecoder().decode(pt);
  } catch {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope failed authentication",
    );
  }
}

/**
 * Read a LEGACY value, and only a legacy value.
 *
 * Refuses a current `2.0` envelope, plain text and anything unrecognised, with
 * `LegacyUnboundBlobError` — the same refusal the normal read path uses, so
 * there is no second, quieter way to open a bound value.
 *
 * Held in memory only: the plaintext this returns is never written anywhere by
 * this module except as the input to the re-seal, and never logged.
 */
export async function readLegacyValue(
  key: string,
  blob: string,
): Promise<string> {
  const shape = classifyLegacy(blob);
  if (shape === null) {
    throw new LegacyUnboundBlobError();
  }
  if (shape === "enc1:safeStorage") {
    let opened: string;
    try {
      opened = safeStorage.decryptString(
        Buffer.from(blob.slice(LEGACY_SAFE_STORAGE_PREFIX.length), "base64"),
      );
    } catch {
      throw new LegacyUnreadableError(
        "legacy_undecryptable",
        "[legacyRecovery] the OS keyring will not open this legacy blob",
      );
    }
    // The keyring returning a value is a claim, not a proof: a `basic_text`
    // backend answers for anything. Require the claim to be plausible, and let
    // the re-seal's verify step be the real check.
    if (typeof opened !== "string" || opened.length === 0) {
      throw new LegacyUnreadableError(
        "legacy_undecryptable",
        "[legacyRecovery] the OS keyring returned nothing usable",
      );
    }
    return opened;
  }

  const passphrase = getSessionPassphrase();
  if (passphrase === null) {
    throw new CryptoDeniedError("locked");
  }
  let env: Record<string, unknown>;
  try {
    env = JSON.parse(blob.slice(LEGACY_ENVELOPE_PREFIX.length)) as Record<
      string,
      unknown
    >;
  } catch {
    throw new LegacyUnreadableError(
      "legacy_undecryptable",
      "[legacyRecovery] legacy envelope is not valid JSON",
    );
  }
  return readLegacyV11(env, passphrase, key);
}

/* ------------------------------------------------------------------ */
/*  Per-key hydration isolation                                          */
/* ------------------------------------------------------------------ */

/** Map a thrown error from the normal read path onto a stable reason code. */
function reasonForReadFailure(error: unknown): UnreadableReason {
  if (error instanceof LegacyUnboundBlobError)
    return "legacy_unbound_encryption";
  if (error instanceof CryptoDeniedError) {
    if (error.reason === "locked") return "locked";
    // Anything else the capability refused is "nothing available here", which
    // is the §2.3 table's own row and the honest reading.
    return "no_capability";
  }
  const reason = (error as { reason?: string } | null)?.reason ?? "";
  if (reason === "legacy_self_asserted_aad") return "legacy_envelope_v1_1";
  return "authentication_failed";
}

const RECOVERABLE_REASONS = new Set<UnreadableReason>([
  "legacy_unbound_encryption",
  "legacy_envelope_v1_1",
]);

/**
 * Hydrate every key in the profile, isolating any that cannot be read.
 *
 * The returned `values` map contains ONLY keys that loaded. A quarantined key is
 * absent from it — never present with an empty string — because "we could not
 * read this" and "this is empty" must never render the same, and a store
 * hydrated with an empty value would then overwrite the very row it could not
 * read.
 */
export async function hydrateAll(
  db: MinimalStorageDb,
): Promise<HydrationReport> {
  const rows = db.prepare("SELECT key, value FROM storage").all() as Array<{
    key: string;
    value: string;
  }>;
  const values = new Map<string, string>();
  const unavailable: UnavailableKey[] = [];

  for (const row of rows) {
    const policy = resolveKeyPolicy(row.key);
    if (!policy.allowed || !policy.entry?.pii) {
      // Non-PII and unknown keys are the sweep's business, not the crypto
      // layer's, and are passed through untouched.
      values.set(row.key, row.value);
      continue;
    }
    try {
      const outcome = await loadRowForHydration(row.key, row.value);
      if (outcome.action === "unreadable") {
        unavailable.push({
          key: row.key,
          reason: outcome.reason,
          recoverable: RECOVERABLE_REASONS.has(outcome.reason),
        });
        continue;
      }
      if (outcome.action === "denied") {
        unavailable.push({
          key: row.key,
          reason: "no_capability",
          recoverable: false,
        });
        continue;
      }
      values.set(row.key, outcome.value);
    } catch (error) {
      // The last line of isolation: an unforeseen failure on ONE key is still
      // one key. Re-throwing here is what takes down the whole profile.
      unavailable.push({
        key: row.key,
        reason: reasonForReadFailure(error),
        recoverable: false,
      });
    }
  }
  return { values, unavailable };
}

/* ------------------------------------------------------------------ */
/*  §3.6 recovery                                                       */
/* ------------------------------------------------------------------ */

export type RecoveryFailure =
  | "legacy_undecryptable"
  | "legacy_key_mismatch"
  | "no_capability"
  | "recovery_write_failed"
  | "recovery_residue_failed"
  | "recovery_verification_failed"
  | "not_legacy"
  | "unknown_key"
  | "not_pii"
  | "nothing_to_recover";

export interface RecoveryResult {
  key: string;
  recovered: boolean;
  /**
   * True only after a FRESH read-back through the normal bound path
   * authenticated and matched the full payload. Never true on a write that was
   * not read back.
   */
  verified: boolean;
  /** The legacy shape, when one was recognised. */
  shape?: LegacyShape;
  /** A failure code, or `undefined` on success. */
  reason?: RecoveryFailure | UnreadableReason;
  /** True when the legacy ciphertext was retained as disclosed residue. */
  residueRetained?: boolean;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return toHex(new Uint8Array(digest));
}

/**
 * §3.6 recovery for one key: copy → re-seal → verify, in that order.
 *
 * Nothing here deletes the legacy blob, and every failure path leaves the
 * `storage` row exactly as it was found. The value is either re-sealed under a
 * real AAD and verified by a fresh read-back, or it is reported as unrecoverable
 * and left alone.
 */
export async function recoverLegacyKey(
  db: MinimalStorageDb,
  key: string,
): Promise<RecoveryResult> {
  const policy = resolveKeyPolicy(key);
  if (!policy.allowed)
    return { key, recovered: false, verified: false, reason: "unknown_key" };
  if (!policy.entry?.pii)
    return { key, recovered: false, verified: false, reason: "not_pii" };

  const row = db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
    { value: string } | undefined;
  const stored = row?.value;
  if (stored === undefined) {
    return {
      key,
      recovered: false,
      verified: false,
      reason: "nothing_to_recover",
    };
  }

  const shape = classifyLegacy(stored);
  if (shape === null) {
    return { key, recovered: false, verified: false, reason: "not_legacy" };
  }

  // 1. READ (in memory only). The plaintext below never leaves this function
  //    except as the input to the re-seal.
  let plaintext: string;
  try {
    plaintext = await readLegacyValue(key, stored);
  } catch (error) {
    const reason =
      error instanceof LegacyUnreadableError
        ? error.reason
        : error instanceof CryptoDeniedError && error.reason === "locked"
          ? "no_capability"
          : "legacy_undecryptable";
    // Nothing has been written. The legacy blob is exactly as found.
    return { key, recovered: false, verified: false, shape, reason };
  }

  // 2. COPY — the legacy ciphertext is retained, byte for byte, BEFORE the
  //    storage row is touched. If this fails, the recovery stops here: the row
  //    is still the only copy, and overwriting it would be the one unrecoverable
  //    outcome in this function.
  const digest = await sha256Hex(plaintext);
  try {
    db.prepare(
      `INSERT INTO ${LEGACY_RESIDUE_TABLE} (key, shape, blob, recovered_value_sha, recovered_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO NOTHING`,
    ).run(key, shape, stored, digest, Date.now());
  } catch {
    return {
      key,
      recovered: false,
      verified: false,
      shape,
      reason: "recovery_residue_failed",
    };
  }

  // 3. RE-SEAL through the normal bound path, so the new row is bound to its
  //    key, purpose, schemaVersion and envelopeFormatVersion.
  let sealed: string;
  try {
    sealed = await encryptForStorage(key, plaintext);
  } catch (error) {
    const reason =
      error instanceof CryptoDeniedError
        ? "no_capability"
        : "recovery_write_failed";
    return { key, recovered: false, verified: false, shape, reason };
  }

  // 4. WRITE, and VERIFY by a fresh authenticated read-back of the FULL
  //    payload. A re-seal that was not read back is not a recovery.
  let written: string | null;
  try {
    db.prepare(
      "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    ).run(key, sealed, Date.now());
    // A GENUINE read-back of the row as it now stands on disk, not the value we
    // just sealed. Reading back our own local variable would verify nothing: the
    // failure this catches is a write that landed the wrong bytes, or a
    // constraint/hook that changed them.
    written =
      (
        db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
          { value: string } | undefined
      )?.value ?? null;
  } catch {
    return {
      key,
      recovered: false,
      verified: false,
      shape,
      reason: "recovery_write_failed",
    };
  }

  let readBack: string;
  try {
    readBack = await decryptFromStorage(key, written ?? "");
  } catch {
    // The row we just wrote does not open. The legacy blob is retained as
    // residue, so the value is NOT lost — but this key is not recovered.
    return {
      key,
      recovered: false,
      verified: false,
      shape,
      reason: "recovery_verification_failed",
      residueRetained: true,
    };
  }
  if (readBack !== plaintext) {
    return {
      key,
      recovered: false,
      verified: false,
      shape,
      reason: "recovery_verification_failed",
      residueRetained: true,
    };
  }

  return {
    key,
    recovered: true,
    verified: true,
    shape,
    residueRetained: true,
  };
}

/**
 * The user-visible recovery report: which classes are unavailable, why, and
 * whether recovery can still be attempted. Reuses the main process's own reason
 * codes so the renderer does not have to invent a second vocabulary.
 */
export async function buildRecoveryReport(
  db: MinimalStorageDb,
): Promise<{ scannedAt: string; unavailable: UnavailableKey[] }> {
  const report = await hydrateAll(db);
  return {
    scannedAt: new Date().toISOString(),
    unavailable: report.unavailable,
  };
}
