/**
 * Main-process crypto capability layer (D1.1 S2) — ADR-001 §2.1.
 *
 * Decision flow per write/read of PII:
 *  1. `safeStorage` available ⇒ encrypt/decrypt with the OS-backed key.
 *     Blob format: "enc1:safeStorage:<base64>".
 *  2. Otherwise, session passphrase held in memory ⇒ SPEC-03-parameter
 *     envelope (see shared crypto/envelope). Blob format:
 *     "enc1:envelope:<json envelope>".
 *  3. Neither ⇒ CryptoDeniedError: PII persistence is DENIED (fail-closed);
 *     the app degrades to memory-only for PII, non-PII unaffected.
 *
 * Zero plaintext path: there is no flag, config, or code path here that
 * writes PII unencrypted. The rollback flag below follows OWNERS-RUNBOOK
 * §7: flipping it off disables NEW encrypted writes only — the decrypt
 * path stays enabled so data written encrypted remains readable.
 */

import { safeStorage } from "electron";
import {
  resolveCryptoCapability,
  type CapabilityDecision,
} from "../src/shared/lib/crypto/capability.js";
import {
  encryptWithPassphrase,
  decryptWithPassphrase,
  AT_REST_PURPOSE,
  CURRENT_ENVELOPE_FORMAT_VERSION,
  type EnvelopeExpectation,
} from "../src/shared/lib/crypto/envelope.js";
import {
  setSessionPassphrase,
  hasSessionPassphrase,
  getSessionPassphrase,
  zeroizeSessionPassphrase,
} from "../src/shared/lib/crypto/passphraseSession.js";

/**
 * Rollback flag (OWNERS-RUNBOOK §7, S2 row): when false, NEW encrypted
 * writes are refused (callers fall back to the pre-S2 behavior) while the
 * decrypt path stays enabled — encrypted data never becomes unreadable.
 * There is intentionally no "write-plaintext" mode.
 */
export const CRYPTO_WRITE_PATH_ENABLED = true;

const SAFE_STORAGE_PREFIX = "enc1:safeStorage:";
const ENVELOPE_PREFIX = "enc1:envelope:";

/**
 * `schemaVersion` (S) of the at-rest AAD.
 *
 * The trusted source for S is the per-key `version` in the shipped SPEC-01
 * manifest (`dataManifest.ManifestEntry`). The main process cannot reach that
 * fixture yet — it is loaded over `fs` rather than an ESM JSON import, which is
 * why this layer deliberately does not import the manifest — so the agreed
 * value is pinned here.
 *
 * It is a constant, not a lookup, and that is a KNOWN SHORTCOMING: a constant
 * is only as trusted as the review that pins it. When the manifest becomes
 * reachable from this layer, this MUST become a per-key lookup, or a manifest
 * version bump will silently re-label every existing envelope's `S` and strand
 * it. Tracked as a follow-up with the Electron profile-key work.
 */
const PII_SCHEMA_VERSION = 1;

/**
 * The caller-trusted AAD expectation for one storage key (ADR-001 §2.4).
 *
 * Built from `key` — the argument the CALLER passed, not anything read back
 * out of the ciphertext. The reader treats the envelope's own copy of these
 * four values as unauthenticated metadata and compares it to this.
 */
function expectationFor(key: string): EnvelopeExpectation {
  return {
    key,
    purpose: AT_REST_PURPOSE,
    schemaVersion: PII_SCHEMA_VERSION,
    envelopeFormatVersion: CURRENT_ENVELOPE_FORMAT_VERSION,
  };
}

export class CryptoDeniedError extends Error {
  readonly code = "crypto_denied";
  /**
   * WHY this write was denied, as a code — `write_path_disabled`,
   * `no_capability`, `quarantined_read_only`, `locked`, `unknown_key`, …
   *
   * Carried as a field, not only interpolated into the message. The reason is
   * the only thing that distinguishes a rollback flag from a locked session
   * from a quarantined key, and a consumer that has to `parse` the message to
   * recover it cannot render it, branch on it, or assert on it — which is how
   * the startup failure surface ended up showing every denial as the bare
   * class name `CryptoDeniedError`.
   *
   * A CODE, never a value: these strings are all compile-time constants at the
   * `new CryptoDeniedError(...)` sites, so nothing derived from a PII value
   * reaches this field and it is safe to render (§3.2 — logs carry key NAMES,
   * never values).
   */
  readonly reason: string;
  constructor(reason: string) {
    super(`[cryptoCapability] PII persistence denied (${reason})`);
    this.name = "CryptoDeniedError";
    this.reason = reason;
  }
}

export class UnknownBlobError extends Error {
  readonly code = "legacy_or_unknown_blob";
  constructor() {
    super("[cryptoCapability] value is not an S2-encrypted blob");
    this.name = "UnknownBlobError";
  }
}

/**
 * Probe safeStorage. Fail-closed: an exception or unexpected shape resolves
 * to false (ADR-001 §2.3 — ambiguous state resolves to DENIED).
 */
export function probeSafeStorage(): boolean {
  try {
    return safeStorage.isEncryptionAvailable() === true;
  } catch {
    return false;
  }
}

export function getCapability(): CapabilityDecision {
  return resolveCryptoCapability({
    platform: "electron",
    safeStorageAvailable: probeSafeStorage(),
    hasPassphrase: hasSessionPassphrase(),
  });
}

/**
 * Store the session passphrase in MAIN-process memory only (SPEC-01
 * `session_passphrase_key`: surface memory, sync never, export never).
 * The renderer that sent it keeps no copy beyond the IPC call.
 */
export function adoptSessionPassphrase(passphrase: string): void {
  setSessionPassphrase(passphrase);
}

/** Lock: zeroize the session passphrase. Irreversible. */
export function lockCryptoSession(): void {
  zeroizeSessionPassphrase();
}

/**
 * Encrypt a PII value for at-rest persistence. Throws CryptoDeniedError
 * when the capability table resolves to DENIED (ADR-001 §2.1 deny path).
 */
export async function encryptForStorage(
  key: string,
  plaintext: string,
): Promise<string> {
  if (!CRYPTO_WRITE_PATH_ENABLED) {
    throw new CryptoDeniedError("write_path_disabled");
  }
  const capability = getCapability();
  if (capability.mode === "safe_storage") {
    return (
      SAFE_STORAGE_PREFIX +
      safeStorage.encryptString(plaintext).toString("base64")
    );
  }
  if (capability.mode === "passphrase") {
    const passphrase = getSessionPassphrase();
    if (passphrase === null) throw new CryptoDeniedError(capability.reason);
    const envelope = await encryptWithPassphrase(
      plaintext,
      passphrase,
      expectationFor(key),
    );
    return ENVELOPE_PREFIX + envelope;
  }
  throw new CryptoDeniedError(capability.reason);
}

/**
 * Decrypt a value produced by `encryptForStorage`. Unknown formats (e.g.
 * legacy plaintext written before S2) raise UnknownBlobError — legacy data
 * enters the ADR-002 quarantine regime, it is never silently re-read or
 * re-encrypted here (S4 wires the quarantine flows).
 *
 * `key` is LOAD-BEARING. It becomes the `K` component of the AAD, so a blob
 * written under one storage key cannot be read back under another; the
 * argument was previously accepted and discarded (`_key`), which meant the
 * passphrase envelope was decryptable from any call site.
 *
 * KNOWN LIMITATION — the `safeStorage` branch binds NO AAD at all.
 * `safeStorage.encryptString` takes no associated data, so a value written
 * that way is not bound to its storage key, purpose or schema version: the
 * blob is a sealed string with no authenticated context. Closing that gap
 * needs a `safeStorage`-wrapped PROFILE DATA KEY (a random per-profile key
 * sealed by the OS keyring) with the application envelope layered on top, so
 * the AAD can be bound. Until that exists this branch is explicit about what
 * it does not provide rather than pretending to.
 */
export async function decryptFromStorage(
  key: string,
  blob: string,
): Promise<string> {
  if (blob.startsWith(SAFE_STORAGE_PREFIX)) {
    const restored = safeStorage.decryptString(
      Buffer.from(blob.slice(SAFE_STORAGE_PREFIX.length), "base64"),
    );
    return restored;
  }
  if (blob.startsWith(ENVELOPE_PREFIX)) {
    const passphrase = getSessionPassphrase();
    if (passphrase === null) throw new CryptoDeniedError("locked");
    return decryptWithPassphrase(
      blob.slice(ENVELOPE_PREFIX.length),
      passphrase,
      expectationFor(key),
    );
  }
  throw new UnknownBlobError();
}
