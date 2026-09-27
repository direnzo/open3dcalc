/**
 * @vitest-environment node
 *
 * Unit tests for the safeStorage-wrapped PROFILE DATA KEY (Beta5 Wave 2,
 * Electron side) — ADR-001 §3.4.
 *
 * The shape of the thing:
 *
 *   - 256 bits from `crypto.getRandomValues`, generated once per profile.
 *   - sealed with `safeStorage.encryptString`; ONLY the sealed form is written
 *     to `userData`, and the clear key lives in main-process memory.
 *   - the clear key is what the application envelope (§3.1 AAD) is sealed under,
 *     which is the whole reason it exists: `safeStorage` takes no associated
 *     data, so a blob written directly by it is bound to nothing.
 *
 * The property most of these tests exist for is the FAIL-CLOSED one: a wrapped
 * key that cannot be read back must never be quietly replaced. Generating a
 * fresh key over an unreadable one looks identical to starting fresh from a
 * user's point of view and strands every record already sealed under it — the
 * bytes are on disk, intact, and now unopenable.
 *
 * These tests write to a real temp directory on purpose: "the clear key is
 * never persisted" is a statement about bytes on a filesystem, and a mock
 * filesystem cannot make that claim.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  ensureProfileDataKey,
  hasProfileDataKey,
  profileDataKeyFilePath,
  profileDataKeyBase64,
  zeroizeProfileDataKey,
  resetProfileDataKeyForTests,
  ProfileDataKeyError,
  PROFILE_DATA_KEY_FILE,
} from "../profileDataKey.js";

/**
 * Reversible-by-the-fake, opaque-on-disk stand-in for the OS keyring: XOR is
 * not encryption, but it is the one property these tests need — the bytes the
 * app writes are NOT the clear key, so an assertion that the clear key never
 * reaches the filesystem is not trivially true of the fake.
 */
const XOR_MASK = 0x5a;
const sealFake = (plain: string): Buffer =>
  Buffer.from(plain, "utf8").map((b) => b ^ XOR_MASK);
const openFake = (sealed: Buffer): string =>
  Buffer.from(sealed)
    .map((b) => b ^ XOR_MASK)
    .toString("utf8");

function writeWrappedFile(contents: string): string {
  const file = profileDataKeyFilePath();
  writeFileSync(file, contents, "utf8");
  return file;
}

beforeEach(() => {
  hoisted.userDataDir.value = mkdtempSync(join(tmpdir(), "o3dc-datakey-"));
  vi.clearAllMocks();
  hoisted.mockSafeStorage.encryptString.mockImplementation(sealFake);
  hoisted.mockSafeStorage.decryptString.mockImplementation(openFake);
  hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
    "gnome_libsecret",
  );
  resetProfileDataKeyForTests();
});

afterEach(() => {
  resetProfileDataKeyForTests();
  rmSync(hoisted.userDataDir.value, { recursive: true, force: true });
});

describe("generation and persistence", () => {
  it("generates 256 bits of key material", () => {
    const key = ensureProfileDataKey();
    expect(key.byteLength).toBe(32);
    expect(Buffer.from(key).toString("base64")).toBe(profileDataKeyBase64());
  });

  it("two profiles (two directories) get different keys", () => {
    const firstDir = hoisted.userDataDir.value;
    ensureProfileDataKey();
    const first = profileDataKeyBase64();

    const secondDir = mkdtempSync(join(tmpdir(), "o3dc-datakey-"));
    hoisted.userDataDir.value = secondDir;
    resetProfileDataKeyForTests();
    ensureProfileDataKey();
    const second = profileDataKeyBase64();

    expect(second).not.toBe(first);
    resetProfileDataKeyForTests();
    hoisted.userDataDir.value = firstDir;
    rmSync(secondDir, { recursive: true, force: true });
  });

  it("wraps the key with safeStorage and writes only the wrapped form", () => {
    ensureProfileDataKey();
    const clear = profileDataKeyBase64();
    const file = profileDataKeyFilePath();
    expect(existsSync(file)).toBe(true);
    expect(hoisted.mockSafeStorage.encryptString).toHaveBeenCalledWith(clear);

    const record = JSON.parse(readFileSync(file, "utf8")) as {
      v: number;
      w: string;
    };
    expect(record.v).toBe(1);
    // The persisted `w` is the keyring's own output, byte for byte — and NOT
    // the clear key under any encoding, which is the property that matters.
    expect(record.w).toBe(sealFake(clear).toString("base64"));
    expect(record.w).not.toBe(clear);
    expect(record.w).not.toBe(Buffer.from(clear, "base64").toString("base64"));
  });

  /**
   * The central confidentiality claim, checked against the actual bytes on
   * disk in both plausible encodings. A base64 comparison alone would miss a
   * leak written as hex or as raw bytes.
   */
  it("the clear key never appears in the file it wrote", () => {
    ensureProfileDataKey();
    const clear = profileDataKeyBase64();
    const raw = Buffer.from(clear, "base64");
    const bytes = readFileSync(profileDataKeyFilePath());
    const asText = bytes.toString("latin1");

    expect(asText).not.toContain(clear);
    expect(asText).not.toContain(raw.toString("hex"));
    expect(bytes.includes(raw)).toBe(false);
  });

  it("reuses the persisted key instead of generating a new one", () => {
    ensureProfileDataKey();
    const first = profileDataKeyBase64();
    // Simulate a restart: memory is gone, the file is not.
    zeroizeProfileDataKey();
    expect(hasProfileDataKey()).toBe(false);

    ensureProfileDataKey();
    expect(profileDataKeyBase64()).toBe(first);
    expect(hoisted.mockSafeStorage.encryptString).toHaveBeenCalledTimes(1);
  });

  it("the file lives in userData under a fixed, non-PII name", () => {
    ensureProfileDataKey();
    expect(profileDataKeyFilePath()).toBe(
      join(hoisted.userDataDir.value, PROFILE_DATA_KEY_FILE),
    );
  });
});

describe("an unreadable wrapped key is never replaced", () => {
  it("refuses a file that is not the record shape", () => {
    writeWrappedFile("not json at all");
    expect(() => ensureProfileDataKey()).toThrow(ProfileDataKeyError);
    expect(() => ensureProfileDataKey()).toThrow(/corrupt/);
  });

  it("refuses an unknown record version", () => {
    writeWrappedFile(JSON.stringify({ v: 99, w: "AAAA" }));
    expect(() => ensureProfileDataKey()).toThrow(/corrupt/);
  });

  it("refuses a record with no wrapped key", () => {
    writeWrappedFile(JSON.stringify({ v: 1 }));
    expect(() => ensureProfileDataKey()).toThrow(/corrupt/);
  });

  /**
   * The keyring itself refuses — a rotated keychain entry, a wiped keyring, a
   * profile moved to a machine whose keyring has no such secret. Every one of
   * those means the user's PII cannot be opened. Generating a replacement here
   * would make the app look healthy while silently orphaning every record, so
   * the failure is named and the file is left exactly as it was.
   */
  it("refuses when the keyring cannot unwrap it, and rewrites nothing", () => {
    hoisted.mockSafeStorage.encryptString.mockImplementation(sealFake);
    ensureProfileDataKey();
    const file = profileDataKeyFilePath();
    const before = readFileSync(file);
    const originalKey = profileDataKeyBase64();

    zeroizeProfileDataKey();
    hoisted.mockSafeStorage.decryptString.mockImplementation(() => {
      throw new Error("secret not found in keyring");
    });
    expect(() => ensureProfileDataKey()).toThrow(/unwrappable/);
    expect(readFileSync(file)).toEqual(before);
    expect(hoisted.mockSafeStorage.encryptString).toHaveBeenCalledTimes(1);

    // …and the memory copy is empty, not half-populated with a new key.
    expect(hasProfileDataKey()).toBe(false);
    zeroizeProfileDataKey();
    hoisted.mockSafeStorage.decryptString.mockImplementation(openFake);
    ensureProfileDataKey();
    expect(profileDataKeyBase64()).toBe(originalKey);
  });

  it("refuses unwrapped material of the wrong length", () => {
    hoisted.mockSafeStorage.decryptString.mockImplementation(() =>
      Buffer.from("too short", "utf8")
        .map((b) => b ^ XOR_MASK)
        .toString("utf8"),
    );
    writeWrappedFile(
      JSON.stringify({ v: 1, w: sealFake("too short").toString("base64") }),
    );
    expect(() => ensureProfileDataKey()).toThrow(/length/);
  });
});

describe("in-memory lifetime", () => {
  it("zeroize empties the held key and it can be unwrapped again", () => {
    ensureProfileDataKey();
    const original = profileDataKeyBase64();
    zeroizeProfileDataKey();
    expect(hasProfileDataKey()).toBe(false);
    ensureProfileDataKey();
    expect(profileDataKeyBase64()).toBe(original);
    expect(hoisted.mockSafeStorage.decryptString).toHaveBeenCalledTimes(1);
  });

  /**
   * The getter does not lazily establish a key. Callers are forced through
   * `ensureProfileDataKey`, which is also where the unwrap can fail — a getter
   * that quietly created a key would be a second, un-audited way to mint one.
   */
  it("the getter is fail-closed before a key has been established", () => {
    expect(() => profileDataKeyBase64()).toThrow(ProfileDataKeyError);
    expect(() => profileDataKeyBase64()).toThrow(/no_profile_data_key/);
  });
});
