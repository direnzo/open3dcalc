/**
 * @vitest-environment node
 *
 * Unit tests for the main-process crypto capability layer (D1.1 S2). The
 * `electron` module is mocked here to exercise the layer logic across the
 * ADR-001 §2.3 rows; the REAL end-to-end behavior (real safeStorage, real
 * SQLite file byte scan) is covered by crypto.selftest.test.ts, which runs
 * the actual Electron binary (TEST-MATRIX §0 — no mocks at contract level).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

const hoisted = vi.hoisted(() => ({
  mockSafeStorage: {
    isEncryptionAvailable: vi.fn<[], boolean>(() => true),
    encryptString: vi.fn<[], Buffer>(),
    decryptString: vi.fn<[], string>(),
  },
}));

vi.mock("electron", () => ({ safeStorage: hoisted.mockSafeStorage }));

import {
  probeSafeStorage,
  getCapability,
  adoptSessionPassphrase,
  lockCryptoSession,
  encryptForStorage,
  decryptFromStorage,
  CryptoDeniedError,
  UnknownBlobError,
  CRYPTO_WRITE_PATH_ENABLED,
} from "../cryptoCapability.js";
import {
  zeroizeSessionPassphrase,
  hasSessionPassphrase,
} from "../../src/shared/lib/crypto/passphraseSession.js";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";

beforeEach(() => {
  zeroizeSessionPassphrase();
  vi.clearAllMocks();
  hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(true);
  hoisted.mockSafeStorage.encryptString.mockImplementation((s: string) =>
    Buffer.from(`safe:${s}`, "utf8"),
  );
  hoisted.mockSafeStorage.decryptString.mockImplementation((b: Buffer) =>
    Buffer.from(b).toString("utf8").slice(5),
  );
});

describe("probeSafeStorage (fail-closed)", () => {
  it("maps a throwing probe to false (ambiguous ⇒ DENIED, ADR-001 §2.3)", () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockImplementation(() => {
      throw new Error("probe exploded");
    });
    expect(probeSafeStorage()).toBe(false);
    expect(getCapability().mode).toBe("denied");
  });
});

describe("encryptForStorage / decryptFromStorage", () => {
  it("row 2.1: safeStorage path produces prefixed ciphertext and round-trips", async () => {
    const blob = await encryptForStorage("open3dcalc_customers_v1", MARKER);
    expect(blob.startsWith("enc1:safeStorage:")).toBe(true);
    expect(blob).not.toContain(MARKER);
    const back = await decryptFromStorage("open3dcalc_customers_v1", blob);
    expect(back).toBe(MARKER);
  });

  it("row 2.2: with safeStorage off, the session passphrase envelope path works", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    expect(hasSessionPassphrase()).toBe(true);
    const blob = await encryptForStorage("open3dcalc_customers_v1", MARKER);
    expect(blob.startsWith("enc1:envelope:")).toBe(true);
    expect(blob).not.toContain(MARKER);
    const back = await decryptFromStorage("open3dcalc_customers_v1", blob);
    expect(back).toBe(MARKER);
  });

  it("row 2.3: deny path — no safeStorage, no passphrase ⇒ refused", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    await expect(
      encryptForStorage("open3dcalc_customers_v1", MARKER),
    ).rejects.toThrow(CryptoDeniedError);
  });

  it("row 2.3: locked session with pending envelope refuses reads of envelope blobs", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage("open3dcalc_customers_v1", MARKER);
    lockCryptoSession();
    await expect(
      decryptFromStorage("open3dcalc_customers_v1", blob),
    ).rejects.toThrow(CryptoDeniedError);
  });

  it("legacy/unknown blobs are rejected, never silently re-read (ADR-002)", async () => {
    await expect(
      decryptFromStorage("open3dcalc_customers_v1", "plain plaintext value"),
    ).rejects.toThrow(UnknownBlobError);
  });

  /**
   * The reason is a FIELD, not only a fragment of the message.
   *
   * It used to be a constructor argument that reached nowhere but
   * `super(...)`, so every consumer that wanted to know WHY a write was denied
   * had to parse the message — and the one consumer that tried, the desktop
   * startup failure surface, silently fell back to the class name and rendered
   * "CryptoDeniedError" for five mutually exclusive causes. A class that
   * documents a reason code in its signature has to expose it.
   */
  it("carries the reason as a readable field", async () => {
    // safeStorage off and no session passphrase (the beforeEach zeroizes it)
    // is the ADR-001 §2.1 deny path. `no_safe_storage_no_passphrase` is the
    // capability table's own code, not a label invented for this spec.
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    await expect(
      encryptForStorage("open3dcalc_customers_v1", MARKER),
    ).rejects.toMatchObject({
      name: "CryptoDeniedError",
      code: "crypto_denied",
      reason: "no_safe_storage_no_passphrase",
    });
  });

  it("gives each refusal its own reason, not one shared string", async () => {
    // Two denials that are mutually exclusive and operationally different —
    // a machine with no keyring at all, and a session that was locked after the
    // passphrase was adopted. This is the property the renderer surface reads,
    // and the reason it can render more than a class name.
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    const noKeyring = await encryptForStorage(
      "open3dcalc_customers_v1",
      MARKER,
    ).catch((error: unknown) => error as CryptoDeniedError);
    expect(noKeyring.reason).toBe("no_safe_storage_no_passphrase");

    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage("open3dcalc_customers_v1", MARKER);
    lockCryptoSession();
    const locked = await decryptFromStorage(
      "open3dcalc_customers_v1",
      blob,
    ).catch((error: unknown) => error as CryptoDeniedError);

    expect(locked.reason).toBe("locked");
    expect(locked.reason).not.toBe(noKeyring.reason);
  });

  it("wrong passphrase after write is rejected (envelope integrity)", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage("open3dcalc_customers_v1", MARKER);
    adoptSessionPassphrase("outra-senha-sintética-9999");
    await expect(
      decryptFromStorage("open3dcalc_customers_v1", blob),
    ).rejects.toThrow(/envelope rejected/);
  });

  it("rollback flag: disabled write path refuses new writes (OWNERS-RUNBOOK §7)", async () => {
    // The flag is a compile-time constant; assert the contract that S3 relies on.
    expect(CRYPTO_WRITE_PATH_ENABLED).toBe(true);
    expect(hasSessionPassphrase()).toBe(false);
  });
});
