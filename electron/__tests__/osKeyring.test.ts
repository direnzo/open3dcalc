/**
 * @vitest-environment node
 *
 * Unit tests for the OS-keyring backend allowlist (Beta5 Wave 2, Electron side)
 * — ADR-001 §3.4.
 *
 * The defect this closes: `isEncryptionAvailable()` alone was the whole gate,
 * and on Linux it returns `true` for the `basic_text` backend — Electron's
 * "the desktop environment was not recognised" fallback, which keeps a
 * symmetric key in an in-memory obfuscation scheme with no OS credential store
 * behind it. Accepting that probe means the desktop app reports PII as
 * "encrypted at rest" on exactly the machines where it is not.
 *
 * Two properties are asserted here, and they are not the same property:
 *
 *  1. **Linux is gated by NAME.** `getSelectedStorageBackend()` is a
 *     `@platform linux` member — it does not exist on Windows or macOS, and
 *     calling it there is not "harmless", it is a call to a member the runtime
 *     does not have. So the allowlist test runs on Linux and the
 *     "never called" test runs on Windows/macOS.
 *  2. **Windows/macOS are gated by BEHAVIOUR.** There is no backend name to
 *     read there, so the only evidence available is OS-backed availability plus
 *     an encrypt/decrypt round-trip. Pretending the Linux getter describes
 *     those platforms would be inventing a check that cannot run.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const hoisted = vi.hoisted(() => ({
  mockSafeStorage: {
    isEncryptionAvailable: vi.fn<[], boolean>(() => true),
    encryptString: vi.fn<[string], Buffer>(),
    decryptString: vi.fn<[Buffer], string>(),
    getSelectedStorageBackend: vi.fn<[], string>(),
  },
}));

vi.mock("electron", () => ({ safeStorage: hoisted.mockSafeStorage }));

import {
  probeOsKeyring,
  ALLOWED_LINUX_BACKENDS,
  OS_KEYRING_PROBE_SENTINEL,
} from "../osKeyring.js";

/**
 * A stand-in for the OS keyring that is reversible by the fake but does NOT
 * leave the plaintext readable in the bytes it "writes", so a "the clear key
 * reached the disk" assertion stays meaningful. XOR is not a cipher; it stands
 * in for "the OS does something we cannot see", which is the property the real
 * backend has and the only one these tests rely on.
 */
function sealFake(plain: string): Buffer {
  return Buffer.from(plain, "utf8").map((b) => b ^ 0x5a);
}

function openFake(sealed: Buffer): string {
  return Buffer.from(sealed)
    .map((b) => b ^ 0x5a)
    .toString("utf8");
}

const REAL_PLATFORM = process.platform;

function setPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", {
    value: value,
    configurable: true,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(true);
  hoisted.mockSafeStorage.encryptString.mockImplementation(sealFake);
  hoisted.mockSafeStorage.decryptString.mockImplementation(openFake);
  hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
    "gnome_libsecret",
  );
});

afterEach(() => {
  setPlatform(REAL_PLATFORM);
});

describe("Linux: the gate is the backend NAME, not isEncryptionAvailable()", () => {
  /**
   * The headline case. `isEncryptionAvailable()` is `true` — the app's current
   * gate accepts it — and the answer must still be "PII unavailable", because
   * `basic_text` is not encryption. If this test ever comes back green with
   * `available: true`, the whole gate is decorative.
   */
  it("rejects basic_text even when isEncryptionAvailable() returns true", () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    expect(probeOsKeyring("linux")).toEqual({
      available: false,
      reason: "backend_basic_text",
      reportedBackend: "basic_text",
    });
  });

  it("rejects unknown (the probe ran before app ready)", () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "unknown",
    );
    expect(probeOsKeyring("linux")).toEqual({
      available: false,
      reason: "backend_unknown",
      reportedBackend: "unknown",
    });
  });

  it("rejects an empty backend value", () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue("");
    expect(probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "backend_not_allowlisted",
    });
  });

  /**
   * Fail-closed on anything this build does not recognise, including values
   * Electron gained after this allowlist was written. A new backend name is a
   * new threat model, and an allowlist that grows by accident is not an
   * allowlist.
   */
  it.each([
    "secretservice",
    "kwallet4",
    "gnome-keyring",
    "GNOME_LIBSECRET",
    "gnome_libsecret ",
    "passwordstore",
  ])("rejects the unrecognised backend %j", (backend) => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(backend);
    expect(probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "backend_not_allowlisted",
      reportedBackend: backend,
    });
  });

  it("rejects a probe that throws", () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockImplementation(() => {
      throw new Error("no dbus");
    });
    expect(probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "backend_probe_failed",
    });
  });

  /**
   * A missing getter on Linux is not a "skip the check" condition. If the
   * runtime ever stops exposing it, PII is unavailable — silently degrading to
   * "assume it is fine" here is the exact failure this gate exists to stop.
   */
  it("rejects when the getter is absent on linux", async () => {
    const without = { ...hoisted.mockSafeStorage } as Record<string, unknown>;
    delete without.getSelectedStorageBackend;
    vi.doMock("electron", () => ({ safeStorage: without }));
    vi.resetModules();
    const fresh =
      (await import("../osKeyring.js")) as typeof import("../osKeyring.js");
    expect(fresh.probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "backend_probe_missing",
    });
    vi.doUnmock("electron");
    vi.resetModules();
  });

  it("rejects an allowlisted backend when isEncryptionAvailable() is false", () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    expect(probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "encryption_unavailable",
    });
  });

  it("rejects a throwing availability probe", () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockImplementation(() => {
      throw new Error("probe exploded");
    });
    expect(probeOsKeyring("linux")).toMatchObject({
      available: false,
      reason: "encryption_unavailable",
    });
  });

  it.each(ALLOWED_LINUX_BACKENDS)("accepts the %s backend", (backend) => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(backend);
    expect(probeOsKeyring("linux")).toEqual({
      available: true,
      backend,
    });
  });

  /**
   * The allowlist is exactly four names. A test that reads the exported list
   * proves the loop is self-consistent, not that the list is right — this
   * pins the list itself, so adding a name is a deliberate edit.
   */
  it("the allowlist is exactly the four approved OS keyrings", () => {
    expect([...ALLOWED_LINUX_BACKENDS]).toEqual([
      "gnome_libsecret",
      "kwallet",
      "kwallet5",
      "kwallet6",
    ]);
  });
});

describe("Windows/macOS: the getter is never called", () => {
  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "does not call getSelectedStorageBackend() on %s",
    (platform) => {
      expect(probeOsKeyring(platform)).toEqual({
        available: true,
        backend: "os_default",
      });
      expect(
        hoisted.mockSafeStorage.getSelectedStorageBackend,
      ).not.toHaveBeenCalled();
    },
  );

  /**
   * The same property through the REAL entry point, with no platform argument —
   * the default reads `process.platform`, so a caller cannot accidentally
   * exercise the allowlist on the wrong platform by passing one.
   */
  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "does not call it on %s when the platform comes from the runtime",
    (platform) => {
      setPlatform(platform);
      expect(probeOsKeyring()).toEqual({
        available: true,
        backend: "os_default",
      });
      expect(
        hoisted.mockSafeStorage.getSelectedStorageBackend,
      ).not.toHaveBeenCalled();
    },
  );

  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "gates %s on a round-trip, not on a name",
    (platform) => {
      // A round-trip that returns the wrong plaintext is the only evidence
      // available here that the keyring is real, so it has to be checked.
      hoisted.mockSafeStorage.decryptString.mockReturnValue("something else");
      expect(probeOsKeyring(platform)).toMatchObject({
        available: false,
        reason: "os_round_trip_failed",
      });
    },
  );

  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "refuses %s when the round-trip throws",
    (platform) => {
      hoisted.mockSafeStorage.encryptString.mockImplementation(() => {
        throw new Error("keychain locked");
      });
      expect(probeOsKeyring(platform)).toMatchObject({
        available: false,
        reason: "os_round_trip_failed",
      });
    },
  );

  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "refuses %s when OS-backed availability is false",
    (platform) => {
      hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
      expect(probeOsKeyring(platform)).toMatchObject({
        available: false,
        reason: "encryption_unavailable",
      });
      expect(hoisted.mockSafeStorage.encryptString).not.toHaveBeenCalled();
    },
  );
});

describe("platforms with no documented keyring gate", () => {
  /**
   * Not defensive padding: this is the only code path where the app would be
   * asked to encrypt PII with an unexamined keyring. It refuses, and it says
   * why.
   */
  it("refuses a platform that is neither linux, win32 nor darwin", () => {
    expect(probeOsKeyring("freebsd")).toEqual({
      available: false,
      reason: "unsupported_platform",
    });
    expect(
      hoisted.mockSafeStorage.isEncryptionAvailable,
    ).not.toHaveBeenCalled();
  });
});

describe("the sync-only decision is enforced, not just documented", () => {
  it("never touches the async safeStorage surface", async () => {
    const asyncFns = {
      decryptStringAsync: vi.fn(() => {
        throw new Error("async decrypt must not be used");
      }),
      encryptStringAsync: vi.fn(() => {
        throw new Error("async encrypt must not be used");
      }),
      isAsyncEncryptionAvailable: vi.fn(() => {
        throw new Error("async availability must not be used");
      }),
      setUsePlainTextEncryption: vi.fn(() => {
        throw new Error("must never force the plaintext backend");
      }),
    };
    const without = { ...hoisted.mockSafeStorage, ...asyncFns };
    vi.doMock("electron", () => ({ safeStorage: without }));
    vi.resetModules();
    const fresh =
      (await import("../osKeyring.js")) as typeof import("../osKeyring.js");
    expect(fresh.probeOsKeyring("linux")).toEqual({
      available: true,
      backend: "gnome_libsecret",
    });
    expect(fresh.probeOsKeyring("win32")).toEqual({
      available: true,
      backend: "os_default",
    });
    for (const fn of Object.values(asyncFns)) expect(fn).not.toHaveBeenCalled();
    vi.doUnmock("electron");
    vi.resetModules();
  });

  it("the probe sentinel is a fixed, non-PII string", () => {
    // It is round-tripped through the real keyring, so it must never be a
    // user's value and must be identical on every run.
    expect(OS_KEYRING_PROBE_SENTINEL).toBe("open3dcalc-keyring-probe-0000");
  });
});
