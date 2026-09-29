/**
 * Packaged-build OS-keyring probe (Beta5 W6 residue) — ADR-001 §3.4 / §2.3.
 *
 * ## What this answers that nothing else did
 *
 * The §3.4 gate (`probeOsKeyring`) and the §2.3 capability table
 * (`getCapability`) are exercised by the dev/binary self-test
 * (`selftest/crypto-selftest.ts`) — but only ever against an UNPACKAGED tree,
 * spawned from `node_modules/electron` with the sources on disk. Nothing had
 * asked the question inside a PACKAGED Electron build: app running out of an
 * `app.asar`, compiled main bundle, a `safeStorage` backend chosen by a
 * Chromium that was never told what the developer's machine looked like.
 *
 * This entry point emits exactly one machine-readable line and exits:
 *
 *   __PACKAGED_PROBE__ {"schema":"open3dcalc.packaged-keyring-probe/v1", ...}
 *
 * ## Value-free by construction
 *
 * The report carries backend NAMES, reason CODES, booleans and version
 * strings — nothing else. No PII value, no key material, no ciphertext, and no
 * filesystem path: a home-directory path IS a username, which is PII under the
 * same policy this probe exists to enforce, so `app.getAppPath()` is reduced to
 * the single bit "does it end in `.asar`". `/etc/os-release` is reduced to
 * `ID` / `VERSION_ID` / `ID_LIKE` under a conservative charset, because
 * `PRETTY_NAME` is free-form text authored by whoever built the image.
 *
 * The one fixed string this module does hold, `OS_KEYRING_PROBE_SENTINEL`, is a
 * compile-time constant that is identical on every machine and in the public
 * source; it is round-tripped by the gate but never rendered into the report
 * (only the boolean result of the round-trip is).
 *
 * ## Why it runs the real modules and not a reimplementation
 *
 * It imports `probeOsKeyring` / `osKeyringRoundTrip` / `ALLOWED_LINUX_BACKENDS`
 * from `../osKeyring.js` and `getCapability` / `probeSafeStorage` from
 * `../cryptoCapability.js` — the same compiled artifacts the application ships.
 * A probe that re-derived the allowlist would measure itself, not the gate.
 *
 * ## Fail-closed, and it says so
 *
 * `app.whenReady()` first, because `safeStorage.getSelectedStorageBackend()` is
 * meaningless before the app is ready (Electron answers `unknown`). Any throw is
 * reported as `{error: PACKAGED_PROBE_ERROR_CODE}` — a fixed code, never the raw
 * message — and exits non-zero: a probe that cannot run must not be mistaken for
 * a machine that passed.
 */

import { app } from "electron";
import { readFileSync } from "node:fs";
import {
  ALLOWED_LINUX_BACKENDS,
  osKeyringRoundTrip,
  probeOsKeyring,
  type OsKeyringDecision,
} from "../osKeyring.js";
import { getCapability, probeSafeStorage } from "../cryptoCapability.js";
import type { CapabilityDecision } from "../../src/shared/lib/crypto/capability.js";

/** Marker a harness greps for on stdout. Mirrors `__CRYPTO_SELFTEST__`. */
export const PACKAGED_PROBE_PREFIX = "__PACKAGED_PROBE__";

export const PACKAGED_PROBE_SCHEMA = "open3dcalc.packaged-keyring-probe/v1";

/**
 * Fixed, non-PII code for the fail-closed catch-all. The raw `error.message` is
 * deliberately NOT emitted: a throw site is free to build a message from a
 * value (a path, a backend string, an OS error), and this report is value-free
 * by contract. "The probe could not run" is the whole signal a caller needs.
 */
export const PACKAGED_PROBE_ERROR_CODE = "probe_failed";

/** Distro identity, reduced to the three fields that are not free-form prose. */
export interface DistroIdentity {
  id: string;
  versionId: string;
  idLike: string[];
}

export interface PackagedProbeReport {
  schema: typeof PACKAGED_PROBE_SCHEMA;
  /** Proof the probe ran from a packaged bundle, not from the repo tree. */
  packaged: { isPackaged: boolean; asar: boolean };
  versions: { electron: string; chrome: string; node: string };
  runtime: { platform: string; arch: string; systemVersion: string };
  distro: DistroIdentity | null;
  /** The RAW `isEncryptionAvailable()` probe. Not the gate — see §3.4. */
  safeStorageAvailable: boolean;
  /** The §3.4 gate verdict, verbatim (names and reason codes only). */
  keyring: OsKeyringDecision;
  /** The allowlist the gate applied, so the report is self-explaining. */
  allowlist: readonly string[];
  /** Sentinel round-trip through the real OS keyring: boolean only. */
  roundTrip: boolean;
  /** The §2.3 decision table, with no session passphrase held. */
  capability: CapabilityDecision;
  verdict: "encrypted_at_rest" | "denied";
}

/**
 * Conservative token: everything outside this set becomes `-`, and the value is
 * capped. Deliberately narrow — the point is that no image can put arbitrary
 * text (or a path, or an email) into a log line through this field.
 */
function sanitizeToken(raw: string, max = 32): string {
  return raw.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, max);
}

/**
 * `ID`, `VERSION_ID` and `ID_LIKE` from `os-release(5)`. Returns `null` when no
 * readable file exists (e.g. a non-Linux runner) — absence is reported as
 * absence, never invented.
 */
export function readDistroIdentity(): DistroIdentity | null {
  const candidates = ["/etc/os-release", "/usr/lib/os-release"];
  let text: string | null = null;
  for (const file of candidates) {
    try {
      text = readFileSync(file, "utf8");
      break;
    } catch {
      continue;
    }
  }
  if (text === null) return null;

  const fields = new Map<string, string>();
  for (const line of text.split("\n")) {
    const match = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (!match) continue;
    fields.set(match[1], match[2].replace(/^"(.*)"$/, "$1"));
  }

  const id = sanitizeToken(fields.get("ID") ?? "");
  if (id.length === 0) return null;
  return {
    id,
    versionId: sanitizeToken(fields.get("VERSION_ID") ?? ""),
    idLike: (fields.get("ID_LIKE") ?? "")
      .split(/\s+/)
      .map((part) => sanitizeToken(part))
      .filter((part) => part.length > 0),
  };
}

/** True when the running bundle is an `app.asar` (path itself never reported). */
function isAsarPackaged(): boolean {
  try {
    return app.getAppPath().endsWith(".asar");
  } catch {
    return false;
  }
}

/**
 * Build the report. Pure with respect to the process: it reads the gate, the
 * capability table, the runtime versions and the distro identity, and returns
 * them — it logs nothing and stores nothing.
 */
export function buildPackagedProbeReport(): PackagedProbeReport {
  const keyring = probeOsKeyring();
  const capability = getCapability();
  return {
    schema: PACKAGED_PROBE_SCHEMA,
    packaged: { isPackaged: app.isPackaged === true, asar: isAsarPackaged() },
    versions: {
      electron: process.versions.electron ?? "",
      chrome: process.versions.chrome ?? "",
      node: process.versions.node ?? "",
    },
    runtime: {
      platform: process.platform,
      arch: process.arch,
      systemVersion: sanitizeToken(process.getSystemVersion(), 64),
    },
    distro: readDistroIdentity(),
    safeStorageAvailable: probeSafeStorage(),
    keyring,
    allowlist: ALLOWED_LINUX_BACKENDS,
    roundTrip: osKeyringRoundTrip(),
    capability,
    verdict:
      capability.piiPersistence === "encrypted_at_rest"
        ? "encrypted_at_rest"
        : "denied",
  };
}

function emit(payload: unknown): void {
  console.log(`${PACKAGED_PROBE_PREFIX} ${JSON.stringify(payload)}`);
}

app.whenReady().then(() => {
  try {
    emit(buildPackagedProbeReport());
    app.exit(0);
  } catch {
    // A fixed code, never `error.message`: a message is arbitrary text a throw
    // site chose, and this report is value-free by contract. The report must
    // not be able to carry a path or a value through this field.
    emit({
      schema: PACKAGED_PROBE_SCHEMA,
      error: PACKAGED_PROBE_ERROR_CODE,
    });
    app.exit(1);
  }
});
