/**
 * The safeStorage-wrapped PROFILE DATA KEY (Beta5 Wave 2, Electron side) —
 * ADR-001 §3.4.
 *
 * ## What it is for
 *
 * `safeStorage.encryptString` takes no associated data. A value sealed by it
 * directly is bound to nothing: not to its storage key, not to its purpose,
 * not to `schemaVersion` or `envelopeFormatVersion`. A blob written for
 * `open3dcalc_customers_v1` decrypts just as cleanly when the row it sits in
 * is renamed to `open3dcalc_quotes_v1`, and nothing in the ciphertext can
 * reveal the move. That was the primary path's entire security property.
 *
 * The fix is a second layer. A random 256-bit key — the PROFILE DATA KEY — is
 * generated once per profile and sealed by the OS keyring; the PII record is
 * then sealed with the ADR-001 §3.1 application envelope under that data key,
 * where the AAD can be supplied. The data key does not need to be memorable,
 * derivable or high-entropy-per-session; it needs to be unwrappable only by the
 * OS keyring that sealed it, and that is exactly what `safeStorage` provides.
 *
 * ## What is on disk
 *
 * One file, `pii-profile-key.json`, in `userData`, mode 0600, holding the
 * keyring's own output and nothing else:
 *
 *   { "v": 1, "w": "<base64 of safeStorage.encryptString(dataKey)>" }
 *
 * The CLEAR key is never written, never logged, and never crosses IPC. It is
 * held in main-process memory as a mutable `Uint8Array` so it can be
 * zeroized on lock; the base64 form handed to the envelope KDF is an immutable
 * JS string, so that copy cannot be scrubbed — the same limitation
 * `passphraseSession.ts` documents, and the reason the durable guarantee is
 * "never persisted", not "never resident".
 *
 * ## The failure that must never happen
 *
 * If the wrapped key cannot be read back — a wiped keyring, a rotated keychain
 * entry, a profile copied to a machine whose keyring has no such secret — the
 * only honest outcome is a named refusal. Generating a replacement here would
 * look exactly like a fresh install and would strand every record already
 * sealed under the old key: the bytes stay on disk, intact, and become
 * unopenable with no trace of why. So every failure to unwrap throws, and the
 * file is left exactly as it was found.
 */

import fs from "node:fs";
import path from "node:path";
import { app, safeStorage } from "electron";

/** Fixed, non-PII file name inside `userData`. */
export const PROFILE_DATA_KEY_FILE = "pii-profile-key.json";

/** Record format version, so a future re-wrap is recognisable. */
const RECORD_VERSION = 1;

/** 256 bits. */
const DATA_KEY_BYTES = 32;

/** Why the data key could not be established. All of them are fail-closed. */
export type ProfileDataKeyFault =
  /** No key is held and none could be loaded or created. */
  | "no_profile_data_key"
  /** The file exists but is not a record this build understands. */
  | "wrapped_key_corrupt"
  /** The record is well-formed but the OS keyring will not open it. */
  | "wrapped_key_unwrappable"
  /** The keyring returned something that is not 256 bits. */
  | "wrapped_key_length";

export class ProfileDataKeyError extends Error {
  readonly code = "profile_data_key_unavailable";
  readonly reason: ProfileDataKeyFault;
  constructor(reason: ProfileDataKeyFault) {
    super(`[profileDataKey] unavailable (${reason})`);
    this.name = "ProfileDataKeyError";
    this.reason = reason;
  }
}

interface WrappedKeyRecord {
  v: number;
  w: string;
}

/**
 * The clear key, in main-process memory only. A `Uint8Array` rather than a
 * string because a string is immutable and cannot be overwritten; this is
 * best-effort zeroization within the platform's limits, and the real guarantee
 * is that nothing is persisted.
 */
let held: Uint8Array | null = null;

export function profileDataKeyFilePath(): string {
  return path.join(app.getPath("userData"), PROFILE_DATA_KEY_FILE);
}

/** True only while the clear key is resident. */
export function hasProfileDataKey(): boolean {
  return held !== null;
}

function zeroizeHeld(): void {
  if (held !== null) held.fill(0);
  held = null;
}

function randomBytes(count: number): Uint8Array {
  const out = new Uint8Array(count);
  // The Web Crypto CSPRNG — the same primitive the shared envelope uses, and
  // the same one available in the Electron main process. Deliberately not
  // `Math.random`, and deliberately not a seedable test seam: a data key
  // generated from anything weaker is not a data key.
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** The base64 form the envelope KDF consumes. Fail-closed when absent. */
export function profileDataKeyBase64(): string {
  if (held === null) throw new ProfileDataKeyError("no_profile_data_key");
  return Buffer.from(held).toString("base64");
}

function readWrappedRecord(): WrappedKeyRecord | null {
  let raw: string;
  try {
    raw = fs.readFileSync(profileDataKeyFilePath(), "utf8");
  } catch {
    // Absent, unreadable, or a permissions problem. The caller distinguishes
    // "no file yet" (generate) from "a file is there and I cannot use it"
    // (refuse) by probing the path itself.
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ProfileDataKeyError("wrapped_key_corrupt");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new ProfileDataKeyError("wrapped_key_corrupt");
  }
  const record = parsed as Record<string, unknown>;
  if (record.v !== RECORD_VERSION || typeof record.w !== "string") {
    throw new ProfileDataKeyError("wrapped_key_corrupt");
  }
  return { v: record.v, w: record.w };
}

function unwrap(record: WrappedKeyRecord): Uint8Array {
  let clear: string;
  try {
    clear = safeStorage.decryptString(Buffer.from(record.w, "base64"));
  } catch {
    throw new ProfileDataKeyError("wrapped_key_unwrappable");
  }
  const bytes = Buffer.from(clear, "base64");
  if (bytes.byteLength !== DATA_KEY_BYTES) {
    throw new ProfileDataKeyError("wrapped_key_length");
  }
  return new Uint8Array(bytes);
}

function wrapAndPersist(key: Uint8Array): void {
  const wrapped = safeStorage.encryptString(
    Buffer.from(key).toString("base64"),
  );
  if (!Buffer.isBuffer(wrapped)) {
    throw new ProfileDataKeyError("wrapped_key_corrupt");
  }
  const record: WrappedKeyRecord = {
    v: RECORD_VERSION,
    w: wrapped.toString("base64"),
  };
  const file = profileDataKeyFilePath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // 0600: the record is a wrapped key, but it is still a secret an attacker
  // with the profile would try first, and there is no reason for it to be
  // world-readable. Windows ignores the mode; nothing else does.
  fs.writeFileSync(file, JSON.stringify(record), {
    encoding: "utf8",
    mode: 0o600,
  });
}

/**
 * The clear data key, unwrapping the persisted one or creating it on first
 * use. Idempotent within a process.
 *
 * Throws `ProfileDataKeyError` rather than falling back to anything. Every
 * caller treats that as "PII is unavailable", which is the correct reading of
 * a keyring that cannot produce the key this profile was written with.
 */
export function ensureProfileDataKey(): Uint8Array {
  if (held !== null) return held;

  const file = profileDataKeyFilePath();
  const fileExists = fs.existsSync(file);
  const record = readWrappedRecord();

  if (record === null) {
    if (fileExists) {
      // There IS a file and we could not parse it as a record. That is a
      // profile whose key we cannot recover, not a profile that has none.
      throw new ProfileDataKeyError("wrapped_key_corrupt");
    }
    const generated = randomBytes(DATA_KEY_BYTES);
    try {
      wrapAndPersist(generated);
    } catch (error) {
      generated.fill(0);
      throw error;
    }
    held = generated;
    return held;
  }

  held = unwrap(record);
  return held;
}

/** Lock: drop the clear key from memory. The wrapped form is untouched. */
export function zeroizeProfileDataKey(): void {
  zeroizeHeld();
}

/**
 * Test-only: return the module to its post-startup state. Distinct from
 * `zeroizeProfileDataKey` so a test can drop a key WITHOUT simulating a lock
 * when it is specifically checking that a lock re-proves the key.
 */
export function resetProfileDataKeyForTests(): void {
  zeroizeHeld();
}
