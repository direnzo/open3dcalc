/**
 * OS-keyring backend gate (Beta5 Wave 2, Electron side) — ADR-001 §3.4.
 *
 * ## Why this exists at all
 *
 * The previous gate was `safeStorage.isEncryptionAvailable() === true`. On
 * Linux that returns `true` for the `basic_text` backend, which Electron
 * selects when it cannot recognise the desktop environment. `basic_text` is a
 * fixed obfuscation key held in the Electron process — no OS credential store,
 * no per-user secret, nothing an attacker with the profile has to defeat but
 * a hardcoded constant. Accepting that probe means the app reports a
 * customer's name as "encrypted at rest" on precisely the machines where it is
 * not, and there is no second gate behind it to notice.
 *
 * ## The gate differs by platform, on purpose
 *
 * `safeStorage.getSelectedStorageBackend()` is annotated `@platform linux` in
 * the Electron API: it does not exist on Windows or macOS. Reading it there is
 * not a stricter check, it is a read of a member the runtime does not have,
 * and a value that cannot exist describes nothing. So:
 *
 *  - **Linux** — gate on the backend NAME against an allowlist. Four names are
 *    real OS keyrings; `basic_text` is not encryption, `unknown` means the
 *    probe ran before `app` was ready, and anything else is a backend this
 *    build has never had a threat model for.
 *  - **Windows/macOS** — there is no name to read, so the only evidence
 *    available is OS-backed availability plus an encrypt/decrypt round-trip
 *    (DPAPI / the Keychain). Behavioural, not nominal.
 *  - **Anything else** — refuse. A platform with no documented gate is not a
 *    platform this layer will encrypt PII on.
 *
 * Every branch is fail-closed: a throw, a missing member, an empty string and
 * an unrecognised value all mean "PII is unavailable here".
 *
 * ## Sync only, deliberately
 *
 * `encryptStringAsync` / `decryptStringAsync` are NOT used. `decryptStringAsync`
 * resolves `{result, shouldReEncrypt}` and its documentation says to call it
 * again when re-encryption is requested — but it returns no replacement
 * ciphertext, so there is no documented way for an application to persist the
 * rewrapped blob. A rotation flow built on it would be an invention, not an
 * implementation, so this layer stays on the sync API and has no key-rotation
 * story. `setUsePlainTextEncryption` is likewise never called: forcing the
 * plaintext backend would manufacture the very condition this gate refuses.
 */

import { safeStorage } from "electron";

/**
 * The approved Linux backends. Anything not in this list is refused, including
 * names a future Electron adds: a new backend is a new threat model, and an
 * allowlist that grows by accident is not an allowlist.
 */
export const ALLOWED_LINUX_BACKENDS = [
  "gnome_libsecret",
  "kwallet",
  "kwallet5",
  "kwallet6",
] as const;

export type AllowedLinuxBackend = (typeof ALLOWED_LINUX_BACKENDS)[number];

/**
 * What the keyring on this machine is, for the report and for the readiness
 * gate. `os_default` means "an OS-backed keyring on a platform that has no
 * backend-name API" — Windows DPAPI or the macOS Keychain, verified by
 * round-trip rather than by name.
 */
export type OsKeyringBackend = AllowedLinuxBackend | "os_default";

/** Why PII cannot be protected here. Every code means PII is UNAVAILABLE. */
export type OsKeyringRefusal =
  /** `isEncryptionAvailable()` was false, or the probe threw. */
  | "encryption_unavailable"
  /** `getSelectedStorageBackend()` does not exist on this Linux build. */
  | "backend_probe_missing"
  /** Reading the backend threw — no session bus, no keyring daemon. */
  | "backend_probe_failed"
  /** The `basic_text` backend: obfuscation, not encryption. */
  | "backend_basic_text"
  /** Electron's own "asked before `app` was ready". */
  | "backend_unknown"
  /** A real-looking name this build has no threat model for. */
  | "backend_not_allowlisted"
  /** Availability claimed, but seal/open did not survive its own round-trip. */
  | "os_round_trip_failed"
  /** A platform with no documented keyring gate at all. */
  | "unsupported_platform";

export type OsKeyringDecision =
  | { available: true; backend: OsKeyringBackend }
  | {
      available: false;
      reason: OsKeyringRefusal;
      /** The raw value, for diagnostics. A backend name is metadata, not PII. */
      reportedBackend?: string;
    };

/**
 * Fixed, non-PII, identical on every run. Round-tripped through the real
 * keyring by the availability probe and by the pre-hydration self-test.
 */
export const OS_KEYRING_PROBE_SENTINEL = "open3dcalc-keyring-probe-0000";

/**
 * Seal and open the sentinel through the OS keyring.
 *
 * This is the only behavioural evidence available on Windows and macOS, where
 * no backend name exists. It also catches a Linux keyring that answers
 * "available" and then hands back something else. Any throw, wrong type or
 * content mismatch is a failure: fail-closed, no distinction between "the
 * Keychain is locked" and "the fake returned garbage", because both mean the
 * same thing to a caller.
 */
export function osKeyringRoundTrip(): boolean {
  try {
    const sealed = safeStorage.encryptString(OS_KEYRING_PROBE_SENTINEL);
    if (!Buffer.isBuffer(sealed)) return false;
    const opened = safeStorage.decryptString(sealed);
    return opened === OS_KEYRING_PROBE_SENTINEL;
  } catch {
    return false;
  }
}

function isAvailable(): boolean {
  try {
    return safeStorage.isEncryptionAvailable() === true;
  } catch {
    return false;
  }
}

/**
 * The gate. `platform` defaults to the runtime's own value and exists as a
 * parameter only so the two platform families can be exercised directly;
 * production callers pass nothing.
 */
export function probeOsKeyring(
  platform: NodeJS.Platform = process.platform,
): OsKeyringDecision {
  if (platform === "win32" || platform === "darwin") {
    if (!isAvailable()) {
      return { available: false, reason: "encryption_unavailable" };
    }
    return osKeyringRoundTrip()
      ? { available: true, backend: "os_default" }
      : { available: false, reason: "os_round_trip_failed" };
  }

  if (platform !== "linux") {
    return { available: false, reason: "unsupported_platform" };
  }

  if (!isAvailable()) {
    return { available: false, reason: "encryption_unavailable" };
  }

  const getter = (safeStorage as { getSelectedStorageBackend?: () => unknown })
    .getSelectedStorageBackend;
  if (typeof getter !== "function") {
    return { available: false, reason: "backend_probe_missing" };
  }

  let reported: unknown;
  try {
    reported = getter.call(safeStorage);
  } catch {
    return { available: false, reason: "backend_probe_failed" };
  }

  if (typeof reported !== "string" || reported.length === 0) {
    return {
      available: false,
      reason: "backend_not_allowlisted",
      reportedBackend: String(reported),
    };
  }
  // Named separately from the allowlist: "the runtime told us it has no
  // keyring" and "the runtime told us about a keyring we do not recognise" are
  // different operator problems with different fixes.
  if (reported === "basic_text" || reported === "unknown") {
    return {
      available: false,
      reason:
        reported === "basic_text" ? "backend_basic_text" : "backend_unknown",
      reportedBackend: reported,
    };
  }
  if (!ALLOWED_LINUX_BACKENDS.includes(reported as AllowedLinuxBackend)) {
    return {
      available: false,
      reason: "backend_not_allowlisted",
      reportedBackend: reported,
    };
  }
  return {
    available: true,
    backend: reported as AllowedLinuxBackend,
  };
}
