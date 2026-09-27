/**
 * @vitest-environment node
 *
 * Unit tests for the persistence gate (D1.1 S3 — ADR-002 §2.1). The
 * `electron` module is mocked to drive the layer across capability rows;
 * the real end-to-end behavior is covered by crypto.selftest.test.ts
 * (real Electron binary, real SQLite file, no mocks).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Since Wave 2 the `safeStorage` branch of the capability layer needs a real OS
 * keyring AND somewhere to keep the wrapped profile data key, so the `electron`
 * mock has to stand in for the whole main-process surface the layer touches —
 * not just `safeStorage`. Without `getSelectedStorageBackend` the Linux
 * allowlist refuses everything (correctly), and without `app.getPath` there is
 * nowhere to persist the wrapped key, so the layer denies PII and these specs
 * would be asserting a failure rather than the gate's behaviour.
 */
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

import {
  resolveKeyPolicy,
  gatePersist,
  gateLoad,
  saveGated,
  loadGated,
  type MinimalStorageDb,
} from "../persistGate.js";
import { CryptoDeniedError } from "../cryptoCapability.js";
import { resetProfileDataKeyForTests } from "../profileDataKey.js";
import { zeroizeSessionPassphrase } from "../../src/shared/lib/crypto/passphraseSession.js";

const PII_KEY = "open3dcalc_customers_v1";
const NON_PII_KEY = "open3dcalc_settings_v2";
const UNKNOWN_KEY = "open3dcalc_not_in_manifest";
const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";

beforeEach(() => {
  zeroizeSessionPassphrase();
  // A fresh profile per spec: the wrapped data key is cached in process memory
  // and persisted per `userData`, so a shared directory would let one spec's
  // key silently satisfy another's.
  hoisted.userDataDir.value = mkdtempSync(join(tmpdir(), "o3dc-gate-"));
  resetProfileDataKeyForTests();
  vi.clearAllMocks();
  hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(true);
  hoisted.mockSafeStorage.encryptString.mockImplementation((s: string) =>
    Buffer.from(`safe:${s}`, "utf8"),
  );
  hoisted.mockSafeStorage.decryptString.mockImplementation((b: Buffer) =>
    Buffer.from(b).toString("utf8").slice(5),
  );
  hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
    "gnome_libsecret",
  );
});

afterEach(() => {
  resetProfileDataKeyForTests();
  rmSync(hoisted.userDataDir.value, { recursive: true, force: true });
});

describe("resolveKeyPolicy (manifest as source of truth)", () => {
  it("classifies PII, non-PII and unknown keys from the fixture", () => {
    const pii = resolveKeyPolicy(PII_KEY);
    expect(pii.allowed).toBe(true);
    expect(pii.entry?.pii).toBe(true);

    const nonPii = resolveKeyPolicy(NON_PII_KEY);
    expect(nonPii.allowed).toBe(true);
    expect(nonPii.entry?.pii).toBe(false);

    expect(resolveKeyPolicy(UNKNOWN_KEY).allowed).toBe(false);
  });
});

describe("gatePersist (ADR-002 §2.1 default-deny)", () => {
  it("PII with capability ⇒ encrypted blob", async () => {
    const out = await gatePersist(PII_KEY, MARKER);
    expect(out.action).toBe("encrypted");
    if (out.action === "encrypted") {
      expect(out.value.startsWith("enc1:")).toBe(true);
      expect(out.value).not.toContain(MARKER);
    }
  });

  it("PII without capability ⇒ DENIED, never downgraded to plaintext", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    const out = await gatePersist(PII_KEY, MARKER);
    expect(out).toEqual({ action: "denied", reason: "no_capability" });
  });

  it("non-PII ⇒ passthrough plaintext (manifest allows it)", async () => {
    const out = await gatePersist(NON_PII_KEY, '{"a":1}');
    expect(out).toEqual({ action: "passthrough", value: '{"a":1}' });
  });

  it("unknown key ⇒ DENIED (SPEC-01 default-deny)", async () => {
    const out = await gatePersist(UNKNOWN_KEY, MARKER);
    expect(out).toEqual({ action: "denied", reason: "unknown_key" });
  });
});

describe("gateLoad (legacy plaintext stays readable — ADR-002 §2.2.1)", () => {
  it("decrypts an S2/S3 blob back to plaintext", async () => {
    const blob = (await gatePersist(PII_KEY, MARKER)) as {
      action: "encrypted";
      value: string;
    };
    const out = await gateLoad(PII_KEY, blob.value);
    expect(out).toEqual({ action: "decrypted", value: MARKER });
  });

  it("returns legacy plaintext flagged, not silently re-encrypted", async () => {
    const out = await gateLoad(PII_KEY, MARKER);
    expect(out).toEqual({ action: "legacy_plaintext", value: MARKER });
  });

  it("non-PII passthrough and unknown key denial", async () => {
    expect(await gateLoad(NON_PII_KEY, "plain")).toEqual({
      action: "passthrough",
      value: "plain",
    });
    expect((await gateLoad(UNKNOWN_KEY, "x")).action).toBe("denied");
  });
});

describe("saveGated / loadGated against a storage table", () => {
  function makeDb(): { db: MinimalStorageDb; rows: Map<string, string> } {
    const rows = new Map<string, string>();
    const db: MinimalStorageDb = {
      prepare(sql: string) {
        return {
          get(...params: unknown[]) {
            if (sql.startsWith("SELECT value")) {
              const key = params[0] as string;
              return rows.has(key) ? { value: rows.get(key) } : undefined;
            }
            return undefined;
          },
          run(...params: unknown[]) {
            if (sql.startsWith("INSERT INTO storage")) {
              rows.set(params[0] as string, params[1] as string);
            }
            return undefined;
          },
        };
      },
    };
    return { db, rows };
  }

  it("writes PII as ciphertext and round-trips; refuses unknown keys", async () => {
    const { db, rows } = makeDb();
    await saveGated(db, PII_KEY, MARKER);
    expect(rows.get(PII_KEY)?.startsWith("enc1:")).toBe(true);
    expect(await loadGated(db, PII_KEY)).toBe(MARKER);

    await expect(saveGated(db, UNKNOWN_KEY, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
    expect(rows.has(UNKNOWN_KEY)).toBe(false);

    expect(await loadGated(db, "open3dcalc_missing_key")).toBeNull();
  });
});
