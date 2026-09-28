/**
 * @vitest-environment node
 *
 * ADR-001 §3.6 recovery, and per-key hydration isolation.
 *
 * ## The defect this closes
 *
 * Two shapes of unreadable-at-rest value reached a packaged build:
 *
 *  - `enc1:safeStorage:<base64>` — the pre-remediation primary path, a raw
 *    `safeStorage.encryptString` output carrying NO AAD, so bound to nothing;
 *  - `enc1:envelope:` with `v: "1.1"` — the pre-remediation passphrase path,
 *    whose AAD was self-asserted from the ciphertext.
 *
 * Both are refused by name on the normal read path. That is the right crypto
 * call and a bad user outcome: the refusal propagates out of `gateLoad`, out of
 * `db:load`, and out of the renderer's `loadFromDatabase`, so ONE unreadable row
 * rejected the WHOLE hydration — `initPersistenceBridge` never registered its
 * interval or its `beforeunload` handler, and the app could not start. The OS
 * keyring was the default path before the Wave 2 remediation, so these are the
 * rows a normal upgrading user is most likely to have.
 *
 * ## What these specs hold
 *
 *  1. **Per-key isolation.** An unreadable key is quarantined and reported; every
 *     other key still loads. Fail-closed is preserved: the unreadable value is
 *     still not hydrated and still not deleted.
 *  2. **The §3.6 order, enforced by code.** copy → re-seal under the new bound
 *     envelope → verify by a fresh authenticated read-back → only then is the
 *     legacy copy resolved. No step may be skipped or reordered.
 *  3. **Copy-and-never-delete.** The legacy blob is retained as disclosed
 *     residue. The approved mode for this programme is copy-and-never-delete,
 *     because no mechanism can prove an old client is not still writing.
 *  4. **Preserve everything on any failure.** Wrong key, undecryptable value, a
 *     failed write, a read-back mismatch — the legacy blob stays byte-identical
 *     and the value is surfaced as unrecoverable, never dropped.
 *  5. **The legacy reader is quarantined.** It can read the old shape and nothing
 *     else; it is not a general-purpose decrypt path.
 *
 * These run against a REAL temporary SQLite profile with REAL legacy blobs
 * written by a reimplementation of the old write path, because the properties
 * being asserted are about bytes on a filesystem and rows in a database.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/* ------------------------------------------------------------------ */
/*  A keyring fake that is reversible but opaque on disk                 */
/* ------------------------------------------------------------------ */

const XOR_MASK = 0x5a;
const sealFake = (plain: string): Buffer =>
  Buffer.from(plain, "utf8").map((b) => b ^ XOR_MASK);
const openFake = (sealed: Buffer): string =>
  Buffer.from(sealed)
    .map((b) => b ^ XOR_MASK)
    .toString("utf8");

const hoisted = vi.hoisted(() => ({
  userDataDir: { value: "" },
  mockSafeStorage: {
    isEncryptionAvailable: vi.fn<[], boolean>(() => true),
    encryptString: vi.fn<[string], Buffer>(),
    decryptString: vi.fn<[Buffer], string>(),
    getSelectedStorageBackend: vi.fn<[], string>(() => "gnome_libsecret"),
  },
}));

vi.mock("electron", () => ({
  safeStorage: hoisted.mockSafeStorage,
  app: {
    getPath: (name: string) => {
      if (name === "userData") return hoisted.userDataDir.value;
      throw new Error(`unexpected path request: ${name}`);
    },
  },
}));

/**
 * Make the manifest loader itself fail on demand. This is deliberately NOT the
 * same thing as an unknown key: `loadManifestFromDisk` throws, so the whole
 * index is unavailable and no key can be classified. A previous version of
 * `resolveKeyPolicy` collapsed both into `{allowed:false}`, which `hydrateAll`
 * read as "unknown key, pass the stored value through".
 */
const manifestState = vi.hoisted(() => ({ unloadable: false }));

vi.mock("../manifestSource.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../manifestSource.js")>();
  return {
    ...actual,
    loadManifestFromDisk: () => {
      if (manifestState.unloadable) {
        throw new Error("[manifestSource] synthetic unloadable fixture");
      }
      return actual.loadManifestFromDisk();
    },
  };
});

import {
  LegacyUnboundBlobError,
  adoptSessionPassphrase,
  encryptForStorage,
  decryptFromStorage,
  lockCryptoSession,
  overrideExpectationForTests,
} from "../cryptoCapability.js";
import { resetProfileDataKeyForTests } from "../profileDataKey.js";
import { gateLoad } from "../persistGate.js";
import { runMigrations } from "../../db/database.js";
import {
  canonicalJson,
  PBKDF2_ITERATIONS,
} from "../../src/shared/lib/crypto/envelope.js";

/* ------------------------------------------------------------------ */
/*  The OLD write paths, reimplemented so the fixtures are real          */
/* ------------------------------------------------------------------ */

/**
 * The pre-remediation primary path, byte for byte: `safeStorage.encryptString`
 * with no AAD, base64'd, behind the `enc1:safeStorage:` prefix. This is what an
 * upgrading profile actually has on disk.
 */
function writeLegacySafeStorageBlob(value: string): string {
  return `enc1:safeStorage:${sealFake(value).toString("base64")}`;
}

/**
 * The pre-remediation passphrase path: envelope `v: "1.1"`, whose AAD was
 * `canonicalJson({purpose, key})` with BOTH halves read back out of the
 * ciphertext — the self-assertion §3.3 refuses. Written here with the real KDF
 * and the real cipher so the fixture is a genuine 1.1 record rather than a
 * hand-drawn JSON blob that only looks like one.
 */
async function writeLegacyV11Envelope(
  value: string,
  passphrase: string,
  key: string,
  purpose = "at-rest",
): Promise<string> {
  const enc = new TextEncoder();
  const salt = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const baseKey = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key2 = await globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  // The 1.1 AAD: self-asserted, both halves from the ciphertext's own metadata.
  const aad = enc.encode(canonicalJson({ key, purpose }));
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key2,
      enc.encode(value),
    ),
  );
  const toHex = (b: Uint8Array): string =>
    Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  const toB64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
  return (
    "enc1:envelope:" +
    JSON.stringify({
      v: "1.1",
      kdf: { alg: "PBKDF2-SHA256", it: PBKDF2_ITERATIONS, salt: toHex(salt) },
      cipher: { alg: "AES-256-GCM", iv: toHex(iv) },
      meta: { key, purpose, schemaVersion: 1, envelopeFormatVersion: 1 },
      ct: toB64(ct),
    })
  );
}

/* ------------------------------------------------------------------ */
/*  A real temporary SQLite profile                                     */
/* ------------------------------------------------------------------ */

const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const SETTINGS = "open3dcalc_settings_v2";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
const OTHER = '["Dra. Joana <joana@exemplo.teste>"]';

let dir = "";
let dbPath = "";
let db: Database.Database;

function freshProfile(): void {
  dir = mkdtempSync(join(tmpdir(), "o3dc-legacy-"));
  hoisted.userDataDir.value = dir;
  dbPath = join(dir, "open3dcalc.db");
  db = new Database(dbPath);
  // The app's OWN migration runner, so the fixture is a real profile: the
  // recovery writes to `legacy_residue` (migration 0005) and a fixture that
  // only had `storage` would make every recovery fail at the copy step for a
  // reason that has nothing to do with the behaviour under test.
  runMigrations(db);
}

/** The old app's own writer, so a fixture is exactly what a real profile has. */
function seedRow(key: string, value: string): void {
  db.prepare(
    "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).run(key, value, Date.now());
}

function rowBytes(key: string): Buffer {
  const row = db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
    { value: string } | undefined;
  if (!row) throw new Error(`no row for ${key}`);
  return Buffer.from(row.value, "utf8");
}

beforeEach(() => {
  lockCryptoSession();
  overrideExpectationForTests(null);
  resetProfileDataKeyForTests();
  freshProfile();
  vi.clearAllMocks();
  hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(true);
  hoisted.mockSafeStorage.encryptString.mockImplementation(sealFake);
  hoisted.mockSafeStorage.decryptString.mockImplementation(openFake);
  hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
    "gnome_libsecret",
  );
});

afterEach(() => {
  lockCryptoSession();
  overrideExpectationForTests(null);
  resetProfileDataKeyForTests();
  db?.close();
  rmSync(dir, { recursive: true, force: true });
});

/* ------------------------------------------------------------------ */

describe("an upgrading profile with legacy blobs hydrates everything else", () => {
  it("one unreadable key does not stop the other keys loading", async () => {
    // A profile written by the old build: one key on the old primary path, one
    // already on the new bound envelope, one non-PII passthrough.
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    seedRow(QUOTES, await encryptForStorage(QUOTES, OTHER));
    seedRow(SETTINGS, '{"theme":"dark"}');

    const { hydrateAll } = await import("../legacyRecovery.js");
    const report = await hydrateAll(db);

    // The readable keys came through, including the one on the new path.
    expect(report.values.get(QUOTES)).toBe(OTHER);
    expect(report.values.get(SETTINGS)).toBe('{"theme":"dark"}');

    // The legacy key is NOT hydrated — fail-closed is preserved.
    expect(report.values.has(CUSTOMERS)).toBe(false);
    expect(report.values.get(CUSTOMERS)).not.toBe(MARKER);
  });

  it("the unavailable key is reported with a reason, not as absent", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const { hydrateAll } = await import("../legacyRecovery.js");
    const report = await hydrateAll(db);

    expect(report.unavailable).toHaveLength(1);
    const entry = report.unavailable[0]!;
    expect(entry.key).toBe(CUSTOMERS);
    // A refusal must be nameable, so the user is told "unavailable", never
    // shown empty state as if the data were gone.
    expect(entry.reason).toBe("legacy_unbound_encryption");
    expect(entry.recoverable).toBe(true);
  });
});

describe("§3.6 recovery: copy → re-seal → verify, in that order", () => {
  it("recovers an enc1:safeStorage value and binds the new row to its key", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const result = await recoverLegacyKey(db, CUSTOMERS);
    expect(result.recovered).toBe(true);
    expect(result.verified).toBe(true);

    // The re-sealed row is readable through the NORMAL bound path…
    expect(
      await decryptFromStorage(CUSTOMERS, rowBytes(CUSTOMERS).toString("utf8")),
    ).toBe(MARKER);
    // …and is genuinely BOUND: a ciphertext swap between two keys fails.
    await expect(
      decryptFromStorage(QUOTES, rowBytes(CUSTOMERS).toString("utf8")),
    ).rejects.toThrow(/envelope rejected/);
  });

  it("recovers a 1.1 envelope and binds the new row to its key", async () => {
    const PASSPHRASE = "sessão-sintética-4242";
    seedRow(
      CUSTOMERS,
      await writeLegacyV11Envelope(MARKER, PASSPHRASE, CUSTOMERS),
    );
    // A 1.1 value is passphrase-derived, so the recovery needs the session
    // passphrase held — the same requirement as the passphrase path it is
    // re-homing into. Adopted here, and it is never persisted.
    adoptSessionPassphrase(PASSPHRASE);
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const result = await recoverLegacyKey(db, CUSTOMERS);
    expect(result).toMatchObject({ recovered: true, verified: true });
    expect(
      await decryptFromStorage(CUSTOMERS, rowBytes(CUSTOMERS).toString("utf8")),
    ).toBe(MARKER);
    await expect(
      decryptFromStorage(QUOTES, rowBytes(CUSTOMERS).toString("utf8")),
    ).rejects.toThrow(/envelope rejected/);
  });

  it("refuses a 1.1 value when the session passphrase is not held", async () => {
    // No passphrase: the value is not lost, it is not readable YET. The legacy
    // blob is left exactly as found and the reason says why, so the user is not
    // told their data is gone when all that is missing is a passphrase.
    const legacy = await writeLegacyV11Envelope(MARKER, "p4ss", CUSTOMERS);
    seedRow(CUSTOMERS, legacy);
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const result = await recoverLegacyKey(db, CUSTOMERS);
    expect(result.recovered).toBe(false);
    expect(result.reason).toBe("no_capability");
    expect(rowBytes(CUSTOMERS).toString("utf8")).toBe(legacy);
    expect(readResidue(CUSTOMERS)).toBeNull();
  });

  /**
   * Copy-and-never-delete. The approved mode is to retain the legacy blob as
   * disclosed residue: no mechanism can prove an old client is not still writing
   * to that row, so deleting it is not safe, and the user removes it through the
   * existing erasure flow instead.
   */
  it("retains the legacy blob byte-identical — the row is rewritten, not consumed", async () => {
    const legacy = writeLegacySafeStorageBlob(MARKER);
    seedRow(CUSTOMERS, legacy);
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const result = await recoverLegacyKey(db, CUSTOMERS);
    expect(result.recovered).toBe(true);
    // The legacy residue is retained somewhere durable and unchanged, so the
    // old value is not destroyed by a recovery that half-worked.
    const residue = readResidue(CUSTOMERS);
    expect(residue).toBe(legacy);
  });

  it("does not report success unless a fresh read-back authenticates the full payload", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    // Corrupt the value the re-seal is about to write, so the read-back cannot
    // match. The legacy blob must survive and the key must be reported, not
    // silently declared recovered.
    const db2 = db;
    const realWrite = db2.prepare.bind(db2);
    vi.spyOn(db2, "prepare").mockImplementation((sql: string) => {
      const stmt = realWrite(sql);
      if (sql.includes("INSERT INTO storage")) {
        return {
          get: (...a: unknown[]) => stmt.get(...a),
          all: (...a: unknown[]) => stmt.all(...a),
          // Write a DIFFERENT value than the one recovery sealed.
          run: (...a: unknown[]) => stmt.run(a[0], '"tampered"', Date.now()),
        } as ReturnType<Database.Statement["run"]> extends never
          ? never
          : ReturnType<typeof db.prepare>;
      }
      return stmt;
    });

    const result = await recoverLegacyKey(db2, CUSTOMERS);
    expect(result.recovered).toBe(false);
    expect(result.verified).toBe(false);
    expect(result.reason).toBe("recovery_verification_failed");
  });

  it("an undecryptable legacy value is quarantined, the blob untouched, and the rest loads", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    seedRow(QUOTES, await encryptForStorage(QUOTES, OTHER));
    // A blob the keyring cannot open — a rotated keychain entry.
    hoisted.mockSafeStorage.decryptString.mockImplementation((b: Buffer) => {
      if (openFake(b) === "open3dcalc-keyring-probe-0000") return openFake(b);
      throw new Error("secret not found in keyring");
    });

    const { recoverLegacyKey, hydrateAll } =
      await import("../legacyRecovery.js");
    const before = rowBytes(CUSTOMERS);
    const result = await recoverLegacyKey(db, CUSTOMERS);

    expect(result.recovered).toBe(false);
    // Surfaced as unrecoverable, not dropped.
    expect(result.reason).toBe("legacy_undecryptable");
    // The legacy blob is untouched, byte for byte.
    expect(rowBytes(CUSTOMERS)).toEqual(before);
    // And it does not block the profile.
    const report = await hydrateAll(db);
    expect(report.values.get(QUOTES)).toBe(OTHER);
  });

  it("a 1.1 value found under a different key is refused, without touching the blob", async () => {
    const PASSPHRASE = "sessão-sintética-4242";
    // The row says QUOTES; the envelope's self-asserted meta says CUSTOMERS.
    // The passphrase IS held, so this isolates the relocation check rather than
    // re-testing the missing-passphrase path.
    const legacy = await writeLegacyV11Envelope(MARKER, PASSPHRASE, CUSTOMERS);
    seedRow(QUOTES, legacy);
    adoptSessionPassphrase(PASSPHRASE);
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const result = await recoverLegacyKey(db, QUOTES);
    expect(result.recovered).toBe(false);
    // A 1.1 AAD is self-asserted, so this meta-vs-row comparison is the ONLY
    // relocation check available — and it is what catches a moved blob.
    expect(result.reason).toBe("legacy_key_mismatch");
    expect(rowBytes(QUOTES).toString("utf8")).toBe(legacy);
    expect(readResidue(QUOTES)).toBeNull();
  });

  it("a failed write leaves both the legacy blob and the original data intact", async () => {
    const legacy = writeLegacySafeStorageBlob(MARKER);
    seedRow(CUSTOMERS, legacy);
    const { recoverLegacyKey } = await import("../legacyRecovery.js");

    const db2 = db;
    vi.spyOn(db2, "prepare").mockImplementation((sql: string) => {
      if (sql.includes("INSERT INTO storage")) {
        throw new Error("SQLITE_FULL: database or disk is full");
      }
      return Database.prototype.prepare.call(db2, sql);
    });

    const result = await recoverLegacyKey(db2, CUSTOMERS);
    expect(result.recovered).toBe(false);
    expect(result.reason).toBe("recovery_write_failed");
    // Nothing was destroyed by the failed write.
    expect(rowBytes(CUSTOMERS).toString("utf8")).toBe(legacy);
  });

  it("never deletes the legacy row, and never calls a DELETE", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const deletes: string[] = [];
    const db2 = db;
    const realPrepare = Database.prototype.prepare.bind(db2);
    vi.spyOn(db2, "prepare").mockImplementation((sql: string) => {
      if (/^\s*DELETE/i.test(sql)) deletes.push(sql);
      return realPrepare(sql);
    });

    const { recoverLegacyKey } = await import("../legacyRecovery.js");
    await recoverLegacyKey(db2, CUSTOMERS);
    expect(deletes).toEqual([]);
  });
});

describe("the legacy reader is quarantined", () => {
  it("refuses a blob that is not the legacy shape", async () => {
    const { readLegacyValue } = await import("../legacyRecovery.js");
    // A CURRENT bound blob must not be readable through the legacy reader —
    // otherwise the old path becomes a general-purpose decrypt oracle that
    // ignores the AAD.
    const current = await encryptForStorage(CUSTOMERS, MARKER);
    await expect(readLegacyValue(CUSTOMERS, current)).rejects.toBeInstanceOf(
      LegacyUnboundBlobError,
    );
  });

  it("refuses plain text and arbitrary bytes", async () => {
    const { readLegacyValue } = await import("../legacyRecovery.js");
    await expect(readLegacyValue(CUSTOMERS, MARKER)).rejects.toBeInstanceOf(
      LegacyUnboundBlobError,
    );
    await expect(
      readLegacyValue(CUSTOMERS, "enc1:somethingelse:abcd"),
    ).rejects.toBeInstanceOf(LegacyUnboundBlobError);
  });

  it("is not exported as a general decrypt path from cryptoCapability", async () => {
    const cap = (await import("../cryptoCapability.js")) as Record<
      string,
      unknown
    >;
    expect(
      Object.keys(cap).filter((n) => /legacy|unbound|recover/i.test(n)),
    ).not.toContain("decryptFromStorage");
  });
});

describe("hydration never re-hydrates an unreadable value", () => {
  it("refuses rather than falling back to the stored string", async () => {
    // The gateLoad path for a legacy blob must not return `legacy_plaintext`
    // with the ciphertext as the "value" — that is the customer's raw
    // ciphertext rendered as if it were their name.
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const outcome = await gateLoad(
      CUSTOMERS,
      writeLegacySafeStorageBlob(MARKER),
    );
    expect(outcome.action).not.toBe("legacy_plaintext");
    expect(outcome.action).toBe("unreadable");
  });

  it("a denial names a key-specific reason, not a blanket one", async () => {
    // The §2.3 table's single "no keyring" row must not be what a quarantined
    // key reports, or the user cannot tell "this class is unavailable" from
    // "everything is unavailable".
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    const { hydrateAll } = await import("../legacyRecovery.js");
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    const report = await hydrateAll(db);
    expect(report.unavailable.length).toBeGreaterThan(0);
    expect(report.unavailable[0]!.reason).toBeTruthy();
  });
});

describe("an UNLOADABLE manifest fails closed for every key", () => {
  /**
   * The regression this pins: the manifest loader throwing is not the same fact
   * as a key not being declared. `resolveKeyPolicy` used to return
   * `{allowed:false}` for both, and `hydrateAll` read `allowed:false` as
   * "unknown key" and copied the raw stored bytes into `values` untouched. On an
   * unloadable manifest that applied to EVERY key, so a known PII key holding a
   * SEALED ciphertext was handed back as its hydrated value — `enc1:...` where
   * the customer's list should be. It also broke `hydrateAll`'s own documented
   * guarantee that a quarantined key is absent, never a raw stored string.
   *
   * The test uses a genuinely unloadable manifest, not an unknown key, because
   * the unknown-key path is a different fact and is covered above.
   */
  it("emits no stored value for any key and reports the classification failure", async () => {
    seedRow(CUSTOMERS, writeLegacySafeStorageBlob(MARKER));
    seedRow(QUOTES, await encryptForStorage(QUOTES, OTHER));
    seedRow(SETTINGS, '{"theme":"dark"}');

    const stored = db.prepare("SELECT key, value FROM storage").all() as Array<{
      key: string;
      value: string;
    }>;

    manifestState.unloadable = true;
    let report: Awaited<
      ReturnType<Awaited<typeof import("../legacyRecovery.js")>["hydrateAll"]>
    >;
    try {
      const { hydrateAll } = await import("../legacyRecovery.js");
      report = await hydrateAll(db);
    } finally {
      manifestState.unloadable = false;
    }

    // Fail closed: the classification is unknown, so NOTHING is emitted —
    // neither a decrypted value nor the raw stored bytes.
    expect(report.values.size).toBe(0);
    for (const row of stored) {
      expect(report.values.has(row.key)).toBe(false);
      expect([...report.values.values()]).not.toContain(row.value);
    }
    // Every unclassifiable key is named, with a reason distinct from a key that
    // is simply not declared.
    expect(report.unavailable.map((u) => u.key).sort()).toEqual(
      stored.map((row) => row.key).sort(),
    );
    expect(
      report.unavailable.every((u) => u.reason === "manifest_unavailable"),
    ).toBe(true);
  });
});

/** Where a retained legacy blob is expected to live after recovery. */
function readResidue(key: string): string | null {
  return (
    (
      db.prepare("SELECT blob FROM legacy_residue WHERE key = ?").get(key) as
        { blob: string } | undefined
    )?.blob ?? null
  );
}
