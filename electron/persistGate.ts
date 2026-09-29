/**
 * Persistence gate (D1.1 S3) — ADR-002 §2.1 default-deny at the write path.
 *
 * Every `db:save`/`db:load` of a manifest-known key is classified before it
 * touches the storage table:
 *
 *  - unknown key ⇒ DENIED (SPEC-01 default-deny);
 *  - `pii: false` ⇒ passthrough (manifest enforces plaintext_allowed only
 *    for non-PII keys);
 *  - `pii: true` ⇒ the value MUST go through the ADR-001 capability layer
 *    (`encryptForStorage`); when no capability exists the write is REFUSED
 *    (fail-closed), never downgraded to plaintext.
 *
 * Legacy plaintext PII (written before D1.1) stays READABLE on load
 * (ADR-002 §2.2.1 — the user must be able to see what exists and choose);
 * the startup scanner (`legacyScan.ts`) is what flags it for the S4
 * quarantine regime. Logs carry key NAMES only, never values (§3.2).
 */

import {
  type ManifestEntry,
  type ManifestIndex,
  isKnownKey,
  getEntry,
} from "../src/shared/lib/dataManifest.js";
import { loadManifestFromDisk } from "./manifestSource.js";
import {
  CryptoDeniedError,
  encryptForStorage,
  decryptFromStorage,
  LegacyUnboundBlobError,
  UnknownBlobError,
} from "./cryptoCapability.js";

/**
 * The two DIFFERENT facts a refusal can represent. They are separate because
 * they call for different handling:
 *
 *  - `unknown_key` — the manifest loaded and this key is not declared
 *    (SPEC-01 default-deny). The classification is known.
 *  - `manifest_unavailable` — the manifest itself could not be loaded, so NO
 *    key can be classified. This is not a statement about the key at all, and
 *    a caller that reads it as "unknown, therefore benign" fails open.
 */
export type PolicyRefusalReason = "unknown_key" | "manifest_unavailable";

export type KeyPolicy =
  | { allowed: true; entry: ManifestEntry }
  | { allowed: false; reason: PolicyRefusalReason };

/**
 * Manifest policy for a key (main-process index; fail-closed on load errors).
 *
 * Fail-closed for BOTH refusal reasons, but the reasons are kept distinct so the
 * caller can tell "this key is not declared" from "I could not read the
 * manifest". Collapsing them is the defect this signature exists to prevent: an
 * unloadable manifest made every key look unknown, and a caller that passes
 * unknown keys through then emitted raw stored ciphertext as a value.
 */
export function resolveKeyPolicy(key: string): KeyPolicy {
  let manifest: ManifestIndex;
  try {
    manifest = loadManifestFromDisk();
  } catch {
    return { allowed: false, reason: "manifest_unavailable" };
  }
  if (!isKnownKey(manifest, key)) {
    return { allowed: false, reason: "unknown_key" };
  }
  // `isKnownKey` is `manifest.has(key)`, so `getEntry` is defined here; the
  // non-null assertion makes the invariant explicit rather than widening the
  // allowed case back to an optional entry.
  return { allowed: true, entry: getEntry(manifest, key)! };
}

export type PersistOutcome =
  | { action: "passthrough"; value: string }
  | { action: "encrypted"; value: string }
  | {
      action: "denied";
      reason: "unknown_key" | "no_capability" | "manifest_unavailable";
    };

/**
 * Decide and transform a value about to be persisted under `key`.
 * Returns the value to write, or a denial (the caller MUST refuse).
 */
export async function gatePersist(
  key: string,
  value: string,
): Promise<PersistOutcome> {
  const policy = resolveKeyPolicy(key);
  if (!policy.allowed) return { action: "denied", reason: policy.reason };
  const entry = policy.entry;
  if (!entry.pii) return { action: "passthrough", value };
  try {
    const blob = await encryptForStorage(key, value);
    return { action: "encrypted", value: blob };
  } catch (error) {
    if (error instanceof CryptoDeniedError) {
      return { action: "denied", reason: "no_capability" };
    }
    throw error;
  }
}

export type LoadOutcome =
  | { action: "passthrough"; value: string }
  | { action: "decrypted"; value: string }
  | { action: "legacy_plaintext"; value: string }
  /**
   * The stored value exists and is a PII blob, but it cannot be read: a
   * pre-remediation `enc1:safeStorage:` blob, a 1.1 envelope, a blob that
   * failed its own authentication, or a refusal because the session is locked.
   *
   * This outcome is the per-key isolation boundary. It used to be a `throw`, and
   * the throw propagated out of `db:load` and out of the renderer's
   * `loadFromDatabase`, so ONE unreadable row rejected the whole profile's
   * hydration and the app could not start. The value is still NOT hydrated and
   * still NOT deleted; it is now quarantined under a name the caller can surface.
   */
  | {
      action: "unreadable";
      reason:
        | "legacy_unbound_encryption"
        | "legacy_envelope_v1_1"
        | "authentication_failed"
        | "locked"
        | "no_capability";
    }
  | {
      action: "denied";
      reason: "unknown_key" | "locked" | "manifest_unavailable";
    };

/**
 * Decide and transform a stored value being read back under `key`.
 * Legacy plaintext PII loads as `legacy_plaintext` (readable — the S4
 * quarantine makes it read-only and surfaces it in the privacy screen).
 *
 * An UNREADABLE PII blob returns `unreadable` with a reason. It is deliberately
 * not `legacy_plaintext` with the stored string as the value: that would hand
 * the customer's raw ciphertext back as if it were their name, which is the
 * specific confusion `LegacyUnboundBlobError`'s own doc records. It is
 * deliberately not a throw either — see `LoadOutcome`.
 */
export async function gateLoad(
  key: string,
  stored: string,
): Promise<LoadOutcome> {
  const policy = resolveKeyPolicy(key);
  if (!policy.allowed) return { action: "denied", reason: policy.reason };
  const entry = policy.entry;
  if (!entry.pii) return { action: "passthrough", value: stored };
  try {
    const plaintext = await decryptFromStorage(key, stored);
    return { action: "decrypted", value: plaintext };
  } catch (error) {
    if (error instanceof UnknownBlobError) {
      return { action: "legacy_plaintext", value: stored };
    }
    if (error instanceof LegacyUnboundBlobError) {
      return {
        action: "unreadable",
        reason: "legacy_unbound_encryption",
      };
    }
    if (error instanceof CryptoDeniedError) {
      return error.reason === "locked"
        ? { action: "unreadable", reason: "locked" }
        : { action: "unreadable", reason: "no_capability" };
    }
    // `EnvelopeRejectedError` and anything unforeseen about ONE value are
    // isolated to that key, for the same reason: re-throwing here is what took
    // down the whole profile.
    if (isEnvelopeRejection(error)) {
      return { action: "unreadable", reason: envelopeReasonFor(error) };
    }
    throw error;
  }
}

function isEnvelopeRejection(error: unknown): boolean {
  const reason = (error as { reason?: unknown } | null)?.reason;
  return (
    reason === "legacy_self_asserted_aad" ||
    reason === "metadata_mismatch" ||
    reason === "authentication_failed" ||
    reason === "parameter_drift" ||
    reason === "malformed_envelope" ||
    reason === "unknown_envelope_version"
  );
}

function envelopeReasonFor(
  error: unknown,
): "legacy_envelope_v1_1" | "authentication_failed" {
  const reason = (error as { reason?: string } | null)?.reason;
  return reason === "legacy_self_asserted_aad"
    ? "legacy_envelope_v1_1"
    : "authentication_failed";
}

/**
 * The single-key read used by bulk hydration, which must distinguish "absent"
 * from "unreadable" — `loadGated`'s `null` return conflates them, and a bulk
 * caller that read `null` as "empty" would write an empty value over a row it
 * could not read.
 */
export async function loadRowForHydration(
  key: string,
  stored: string,
): Promise<LoadOutcome> {
  return gateLoad(key, stored);
}

/* ------------------------------------------------------------------ */
/*  Storage-table operations used by the IPC handlers and the selftest */
/* ------------------------------------------------------------------ */

export interface MinimalStorageDb {
  prepare(sql: string): {
    get(...params: unknown[]): unknown;
    run(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  };
  /** Optional for callers like the real better-sqlite3 client (VACUUM etc.). */
  exec?(sql: string): void;
}

const STORAGE_COLUMNS = "value FROM storage WHERE key = ?";

export function writeStoredRow(
  db: MinimalStorageDb,
  key: string,
  value: string,
): void {
  db.prepare(
    "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
  ).run(key, value, Date.now());
}

/**
 * The raw stored bytes for a key, or null when there is no row.
 *
 * Exported because the IPC read path needs to tell "no such key" (null, and the
 * renderer writes a fresh value) from "a row I could not read" (a refusal, and
 * the renderer must not write anything). `loadGated` collapses both into null,
 * which is the wrong answer for the second case.
 */
export function readStoredRow(
  db: MinimalStorageDb,
  key: string,
): string | null {
  const row = db.prepare(`SELECT ${STORAGE_COLUMNS}`).get(key) as
    { value: string } | undefined;
  return row ? row.value : null;
}

/**
 * Gate and write a key/value pair into the storage table.
 * Throws on denial (fail-closed refusal — ADR-002 §2.1) and on SQL errors.
 * S4 (ADR-002 §2.2.1): a PII key holding legacy plaintext is QUARANTINED —
 * writes to it are refused (read-only) until the user migrates or
 * eliminates it via the privacy screen. Non-PII and encrypted states are
 * unaffected.
 */
export async function saveGated(
  db: MinimalStorageDb,
  key: string,
  value: string,
): Promise<void> {
  const outcome = await gatePersist(key, value);
  if (outcome.action === "denied") {
    throw new CryptoDeniedError(outcome.reason);
  }
  if (outcome.action === "encrypted") {
    const current = readStoredRow(db, key);
    if (current !== null && !current.startsWith("enc1:")) {
      throw new CryptoDeniedError("quarantined_read_only");
    }
  }
  writeStoredRow(db, key, outcome.value);
}

/**
 * Delete a key from the storage table through the manifest policy.
 *
 * A delete does not READ the value, but it still needs the classification: when
 * the manifest itself will not load, NO key can be classified, and an
 * unclassifiable row might be PII. "I could not classify this" is not evidence
 * that the row is stale or unowned, so the delete is REFUSED (fail-closed).
 * This is the same `manifest_unavailable` distinction `gateLoad`/`gatePersist`
 * make; treating the refusal as "not a PII key" and deleting anyway is what
 * turned a broken manifest into destruction of the profile it could not
 * classify.
 *
 * An `unknown_key` row is still deletable: that classification SUCCEEDED, and
 * the renderer's stale-key sweep depends on being able to remove internal rows
 * the manifest deliberately does not declare.
 */
export function deleteGated(db: MinimalStorageDb, key: string): void {
  const policy = resolveKeyPolicy(key);
  if (!policy.allowed && policy.reason === "manifest_unavailable") {
    throw new CryptoDeniedError("manifest_unavailable");
  }
  db.prepare("DELETE FROM storage WHERE key = ?").run(key);
}

/**
 * Read a key from the storage table through the gate.
 * Returns null when the key is unknown (denied) or absent.
 */
export async function loadGated(
  db: MinimalStorageDb,
  key: string,
): Promise<string | null> {
  const row = db.prepare(`SELECT ${STORAGE_COLUMNS}`).get(key) as
    { value: string } | undefined;
  if (!row) return null;
  const outcome = await gateLoad(key, row.value);
  if (outcome.action === "denied" || outcome.action === "unreadable") {
    // An unreadable row is NOT reported as absent. `loadGated` predates the
    // `unreadable` outcome and returns a bare `string | null`, which cannot
    // express "there is a row here and I cannot open it" — and null is the
    // answer a caller would read as "no such key", i.e. as permission to write
    // over it. The typed answer is `gateLoad`; this thin wrapper keeps the old
    // signature for the callers that only need a value, and the IPC read path
    // uses `gateLoad` directly so the distinction survives to the renderer.
    return null;
  }
  return outcome.value;
}
