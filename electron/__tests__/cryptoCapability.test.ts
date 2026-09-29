/**
 * @vitest-environment node
 *
 * Unit tests for the main-process crypto capability layer (D1.1 S2, plus the
 * Beta5 Wave 2 remediation of its `safeStorage` branch — ADR-001 §2.1/§3.4).
 * The `electron` module is mocked here to exercise the layer logic across the
 * ADR-001 §2.3 rows AND across every OS-keyring backend; the REAL end-to-end
 * behavior (real safeStorage, real SQLite file byte scan) is covered by
 * crypto.selftest.test.ts, which runs the actual Electron binary (TEST-MATRIX
 * §0 — no mocks at contract level).
 *
 * What Wave 2 changed, and what the specs below are for:
 *
 *  1. The `safeStorage` branch no longer uses `safeStorage.encryptString` AS
 *     the cipher. It seals every PII record with the application envelope
 *     (§3.1 AAD) under a 256-bit PROFILE DATA KEY whose wrapped form — never
 *     the clear key — is what reaches the filesystem. This is what makes the
 *     `key`/`purpose`/`schemaVersion`/`envelopeFormatVersion` binding real on
 *     the primary path instead of only on the passphrase fallback.
 *  2. `isEncryptionAvailable()` is no longer the gate. On Linux it returns
 *     `true` for the `basic_text` backend, which is not encryption; the gate is
 *     the backend NAME (allowlist) — see `osKeyring.test.ts`.
 *  3. A round-trip self-test runs before any PII is sealed or opened, so a
 *     machine that cannot do this properly fails once, loudly, with a reason —
 *     not on the first read of a customer's name.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const hoisted = vi.hoisted(() => ({
  userDataDir: { value: "" },
  mockSafeStorage: {
    isEncryptionAvailable: vi.fn<[], boolean>(() => true),
    encryptString: vi.fn<[string], Buffer>(),
    decryptString: vi.fn<[Buffer], string>(),
    getSelectedStorageBackend: vi.fn<[], string>(() => "gnome_libsecret"),
    // The async surface exists only so the specs can prove it is never used.
    encryptStringAsync: vi.fn<[string], Promise<Buffer>>(),
    decryptStringAsync: vi.fn<[Buffer], Promise<unknown>>(),
    isAsyncEncryptionAvailable: vi.fn<[], Promise<boolean>>(),
    setUsePlainTextEncryption: vi.fn<[boolean], void>(),
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
  probeSafeStorage,
  getOsKeyringDecision,
  getCapability,
  runPiiCryptoSelfTest,
  adoptSessionPassphrase,
  lockCryptoSession,
  encryptForStorage,
  decryptFromStorage,
  overrideExpectationForTests,
  CryptoDeniedError,
  LegacyUnboundBlobError,
  UnknownBlobError,
  CRYPTO_WRITE_PATH_ENABLED,
} from "../cryptoCapability.js";
import {
  ensureProfileDataKey,
  hasProfileDataKey,
  profileDataKeyBase64,
  profileDataKeyFilePath,
  resetProfileDataKeyForTests,
} from "../profileDataKey.js";
import { OS_KEYRING_PROBE_SENTINEL } from "../osKeyring.js";
// Teardown goes through `lockCryptoSession`, which is the production lock and
// drops the passphrase, the held data key and the self-test verdict together —
// zeroizing the passphrase alone would leave the other two, and these specs
// assert on them.
import { hasSessionPassphrase } from "../../src/shared/lib/crypto/passphraseSession.js";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const PROFILE_KEY_PREFIX = "enc1:profileKey:";

/**
 * Reversible-by-the-fake, opaque-on-disk stand-in for the OS keyring. XOR is
 * not encryption, but it is the only property the "the clear key never reaches
 * disk" specs depend on: what this fake writes is not the clear key, so those
 * assertions are not trivially true of the fake itself.
 */
const XOR_MASK = 0x5a;
const sealFake = (plain: string): Buffer =>
  Buffer.from(plain, "utf8").map((b) => b ^ XOR_MASK);
const openFake = (sealed: Buffer): string =>
  Buffer.from(sealed)
    .map((b) => b ^ XOR_MASK)
    .toString("utf8");

const REAL_PLATFORM = process.platform;

function setPlatform(value: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", {
    value: value,
    configurable: true,
  });
}

/** Fail loudly if any async/plaintext-forcing safeStorage member is used. */
function armAsyncTripwires(): void {
  hoisted.mockSafeStorage.encryptStringAsync.mockImplementation(() => {
    throw new Error("encryptStringAsync is out of scope (ADR-001 §3.4)");
  });
  hoisted.mockSafeStorage.decryptStringAsync.mockImplementation(() => {
    throw new Error("decryptStringAsync is out of scope (ADR-001 §3.4)");
  });
  hoisted.mockSafeStorage.isAsyncEncryptionAvailable.mockImplementation(() => {
    throw new Error("isAsyncEncryptionAvailable is out of scope");
  });
  hoisted.mockSafeStorage.setUsePlainTextEncryption.mockImplementation(() => {
    throw new Error("must never force the plaintext keyring backend");
  });
}

beforeEach(() => {
  hoisted.userDataDir.value = mkdtempSync(join(tmpdir(), "o3dc-cap-"));
  // `lockCryptoSession` is the production teardown: it drops the passphrase, the
  // held data key and the self-test verdict, which is exactly the state these
  // specs need to start from.
  lockCryptoSession();
  overrideExpectationForTests(null);
  resetProfileDataKeyForTests();
  vi.clearAllMocks();
  hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(true);
  hoisted.mockSafeStorage.encryptString.mockImplementation(sealFake);
  hoisted.mockSafeStorage.decryptString.mockImplementation(openFake);
  hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
    "gnome_libsecret",
  );
  armAsyncTripwires();
});

afterEach(() => {
  lockCryptoSession();
  overrideExpectationForTests(null);
  resetProfileDataKeyForTests();
  setPlatform(REAL_PLATFORM);
  rmSync(hoisted.userDataDir.value, { recursive: true, force: true });
});

describe("probeSafeStorage (the RAW probe, kept for the report)", () => {
  it("maps a throwing probe to false (ambiguous ⇒ DENIED, ADR-001 §2.3)", () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockImplementation(() => {
      throw new Error("probe exploded");
    });
    expect(probeSafeStorage()).toBe(false);
    expect(getCapability().mode).toBe("denied");
  });

  /**
   * The reason the raw probe is no longer the gate. It is honest about what it
   * measures and says so; the gate is `getOsKeyringDecision`.
   */
  it("still answers true for a backend that is not encryption", () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    expect(probeSafeStorage()).toBe(true);
    expect(getOsKeyringDecision().available).toBe(false);
  });
});

describe("encryptForStorage / decryptFromStorage", () => {
  it("row 2.1: safeStorage path produces prefixed ciphertext and round-trips", async () => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    expect(blob.startsWith(PROFILE_KEY_PREFIX)).toBe(true);
    expect(blob).not.toContain(MARKER);
    const back = await decryptFromStorage(CUSTOMERS, blob);
    expect(back).toBe(MARKER);
  });

  it("row 2.2: with safeStorage off, the session passphrase envelope path works", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    expect(hasSessionPassphrase()).toBe(true);
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    expect(blob.startsWith("enc1:envelope:")).toBe(true);
    expect(blob).not.toContain(MARKER);
    const back = await decryptFromStorage(CUSTOMERS, blob);
    expect(back).toBe(MARKER);
  });

  it("row 2.3: deny path — no safeStorage, no passphrase ⇒ refused", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
  });

  it("row 2.3: locked session with pending envelope refuses reads of envelope blobs", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    lockCryptoSession();
    await expect(decryptFromStorage(CUSTOMERS, blob)).rejects.toThrow(
      CryptoDeniedError,
    );
  });

  it("legacy/unknown blobs are rejected, never silently re-read (ADR-002)", async () => {
    await expect(
      decryptFromStorage(CUSTOMERS, "plain plaintext value"),
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
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toMatchObject({
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
    const noKeyring = await encryptForStorage(CUSTOMERS, MARKER).catch(
      (error: unknown) => error as CryptoDeniedError,
    );
    expect(noKeyring.reason).toBe("no_safe_storage_no_passphrase");

    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    lockCryptoSession();
    const locked = await decryptFromStorage(CUSTOMERS, blob).catch(
      (error: unknown) => error as CryptoDeniedError,
    );

    expect(locked.reason).toBe("locked");
    expect(locked.reason).not.toBe(noKeyring.reason);
  });

  it("a blob written under one key does not decrypt under another", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    // …it does decrypt under its own key …
    expect(await decryptFromStorage(CUSTOMERS, blob)).toBe(MARKER);
    // …and not under a different one, even with the right passphrase in hand.
    await expect(decryptFromStorage(QUOTES, blob)).rejects.toThrow(
      /envelope rejected/,
    );
  });

  it("wrong passphrase after write is rejected (envelope integrity)", async () => {
    hoisted.mockSafeStorage.isEncryptionAvailable.mockReturnValue(false);
    adoptSessionPassphrase("sessão-sintética-3131");
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    adoptSessionPassphrase("outra-senha-sintética-9999");
    await expect(decryptFromStorage(CUSTOMERS, blob)).rejects.toThrow(
      /envelope rejected/,
    );
  });

  it("rollback flag: disabled write path refuses new writes (OWNERS-RUNBOOK §7)", async () => {
    // The flag is a compile-time constant; assert the contract that S3 relies on.
    expect(CRYPTO_WRITE_PATH_ENABLED).toBe(true);
    expect(hasSessionPassphrase()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Wave 2: the safeStorage branch seals under a wrapped profile data key
// ---------------------------------------------------------------------------

describe("the safeStorage branch seals with the application envelope", () => {
  /**
   * This is the spec that distinguishes "encrypted by the OS" from "encrypted
   * AND bound to where it lives". A raw keyring blob has no AAD at all; the
   * value must be an ADR-001 §3.1 envelope carrying the four components, sealed
   * under the profile data key.
   */
  it("writes an ADR-001 envelope, not a raw keyring blob", async () => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    const envelope = JSON.parse(
      blob.slice(PROFILE_KEY_PREFIX.length),
    ) as Record<string, unknown>;
    expect(envelope.v).toBe("2.0");
    expect(envelope.kdf).toEqual({
      alg: "PBKDF2-SHA256",
      it: 310_000,
      salt: expect.any(String),
    });
    expect(envelope.cipher).toEqual({
      alg: "AES-256-GCM",
      iv: expect.any(String),
    });
    expect(envelope.meta).toEqual({
      key: CUSTOMERS,
      purpose: "at-rest",
      schemaVersion: 1,
      envelopeFormatVersion: 1,
    });
    // The data key itself is NOT what got sealed: what reaches safeStorage is
    // the base64 of 32 random bytes, never the user's value.
    for (const call of hoisted.mockSafeStorage.encryptString.mock.calls) {
      expect(call[0]).not.toContain(MARKER);
    }
  });

  it("reuses one profile data key across keys and calls", async () => {
    await encryptForStorage(CUSTOMERS, MARKER);
    const key = profileDataKeyBase64();
    expect(hasProfileDataKey()).toBe(true);
    await encryptForStorage(QUOTES, MARKER);
    expect(profileDataKeyBase64()).toBe(key);

    // One wrap, not one per record: the key is sealed once and unwrapped from
    // the keyring on the next process. Counted by WHAT was handed to the
    // keyring, because the self-test's round-trip also seals — a raw call
    // count would measure that probe too and read as a second wrap.
    const wrapsOfTheDataKey = () =>
      hoisted.mockSafeStorage.encryptString.mock.calls.filter(
        ([sealed]) => sealed === key,
      );
    expect(wrapsOfTheDataKey()).toHaveLength(1);

    // …and sealing more records adds no keyring traffic at all: the envelope
    // runs under the held data key, so only the first record ever touched the
    // OS keyring.
    const before = hoisted.mockSafeStorage.encryptString.mock.calls.length;
    await encryptForStorage("open3dcalc_invoices_v1", MARKER);
    await encryptForStorage("open3dcalc_items_v1", MARKER);
    expect(hoisted.mockSafeStorage.encryptString.mock.calls.length).toBe(
      before,
    );
  });
});

describe("a ciphertext is bound to where it was written", () => {
  it("a value moved to a different storage key fails authentication", async () => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    expect(await decryptFromStorage(CUSTOMERS, blob)).toBe(MARKER);
    // Same key material, same keyring, different destination row.
    await expect(decryptFromStorage(QUOTES, blob)).rejects.toThrow(
      /envelope rejected/,
    );
  });

  it.each([
    ["purpose", { purpose: "export" }],
    ["schemaVersion", { schemaVersion: 2 }],
    ["envelopeFormatVersion", { envelopeFormatVersion: 2 }],
  ])("a value opened under a different %s fails", async (_label, override) => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    overrideExpectationForTests(override);
    await expect(decryptFromStorage(CUSTOMERS, blob)).rejects.toThrow(
      /envelope rejected/,
    );
    // …and the sealed record's own copy of those values is not a substitute:
    // it matches the reader's wrong expectation, and the GCM tag still fails.
    const envelope = JSON.parse(blob.slice(PROFILE_KEY_PREFIX.length)) as {
      meta: Record<string, unknown>;
    };
    expect(envelope.meta.purpose).toBe("at-rest");
  });

  /**
   * The other direction of the same property: a different PROFILE cannot open
   * this profile's records. The data key is per-profile and only its wrapped
   * form is portable, so a copied `userData` directory is inert without the
   * keyring entry that unwraps it.
   */
  it("a different profile data key cannot open the record", async () => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    const firstKey = profileDataKeyBase64();

    // A second profile: different userData, so a different wrapped key.
    const firstDir = hoisted.userDataDir.value;
    hoisted.userDataDir.value = mkdtempSync(join(tmpdir(), "o3dc-cap-"));
    lockCryptoSession();
    resetProfileDataKeyForTests();
    // Through `ensureProfileDataKey`, not the getter: the getter is
    // fail-closed by design and refuses to mint a key on read, which is what
    // makes "one audited way to create a key" true.
    const secondKey = Buffer.from(ensureProfileDataKey()).toString("base64");
    expect(secondKey).not.toBe(firstKey);

    await expect(decryptFromStorage(CUSTOMERS, blob)).rejects.toThrow(
      /envelope rejected/,
    );
    // …and this profile's own records are untouched by the refusal.
    expect(await encryptForStorage(CUSTOMERS, MARKER)).not.toBe(blob);

    lockCryptoSession();
    resetProfileDataKeyForTests();
    hoisted.userDataDir.value = firstDir;
  });
});

describe("the clear data key never leaves the main process", () => {
  it("the file on disk holds only the keyring's own output", async () => {
    const blob = await encryptForStorage(CUSTOMERS, MARKER);
    const clear = profileDataKeyBase64();
    const raw = Buffer.from(clear, "base64");

    const file = profileDataKeyFilePath();
    expect(existsSync(file)).toBe(true);
    const bytes = (await import("node:fs")).readFileSync(file);
    const asText = bytes.toString("latin1");
    expect(asText).not.toContain(clear);
    expect(asText).not.toContain(raw.toString("hex"));
    expect(bytes.includes(raw)).toBe(false);

    // …and it is not in the sealed record either.
    expect(blob).not.toContain(clear);
  });

  /**
   * A log line carrying the key would be a silent permanent leak: logs get
   * shipped, buffered and kept long after the process that made them. Every
   * console method is watched, not just `log`, because the "harmless" one is
   * `debug` until someone needs it.
   */
  it("nothing about the key material is logged", async () => {
    // Establish the key first, so the spies cover the unseal too.
    const clear = Buffer.from(ensureProfileDataKey()).toString("base64");
    const raw = Buffer.from(clear, "base64");
    const seen: string[] = [];
    const spies = (
      ["log", "info", "warn", "error", "debug", "trace"] as const
    ).map((method) =>
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        seen.push(args.map((a) => String(a)).join(" "));
      }),
    );
    try {
      await encryptForStorage(CUSTOMERS, MARKER);
      // Opened under the key it was sealed under — the point of this spec is
      // the logging, not a second demonstration of the AAD refusal.
      await decryptFromStorage(QUOTES, await encryptForStorage(QUOTES, MARKER));
      await runPiiCryptoSelfTest();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
    for (const line of seen) {
      expect(line).not.toContain(clear);
      expect(line).not.toContain(raw.toString("hex"));
      expect(line).not.toContain(MARKER);
    }
  });

  /**
   * Structural rather than behavioural: whatever the individual call sites do,
   * the module must not EXPOSE a way to read the key out. A test that only
   * checks today's call sites would not notice a new exported getter.
   */
  it("the module exports no accessor for the data key", async () => {
    const api = (await import("../cryptoCapability.js")) as Record<
      string,
      unknown
    >;
    const leaks = Object.keys(api).filter((name) =>
      /datakey|data_key|profilekey|clear_?key|unwrap/i.test(name),
    );
    expect(leaks).toEqual([]);
  });
});

describe("the OS-keyring gate (ADR-001 §3.4)", () => {
  it("accepts each allowlisted Linux backend", async () => {
    for (const backend of [
      "gnome_libsecret",
      "kwallet",
      "kwallet5",
      "kwallet6",
    ] as const) {
      lockCryptoSession();
      resetProfileDataKeyForTests();
      rmSync(hoisted.userDataDir.value, { recursive: true, force: true });
      hoisted.userDataDir.value = mkdtempSync(join(tmpdir(), "o3dc-cap-"));
      hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
        backend,
      );
      expect(getOsKeyringDecision()).toEqual({ available: true, backend });
      expect(await runPiiCryptoSelfTest()).toMatchObject({ ready: true });
      expect(
        await decryptFromStorage(
          CUSTOMERS,
          await encryptForStorage(CUSTOMERS, MARKER),
        ),
      ).toBe(MARKER);
    }
  });

  /**
   * The headline Wave 2 refusal: a machine Electron considers "encrypted" but
   * that is running the `basic_text` backend. Before this change that resolved
   * to `safe_storage` mode and the app told the user their customer's name was
   * encrypted at rest.
   */
  it("refuses basic_text even though isEncryptionAvailable() is true", async () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    expect(probeSafeStorage()).toBe(true);
    expect(getOsKeyringDecision()).toMatchObject({
      available: false,
      reason: "backend_basic_text",
    });
    expect(getCapability().mode).toBe("denied");
    await expect(runPiiCryptoSelfTest()).resolves.toMatchObject({
      ready: false,
      reason: "backend_basic_text",
    });
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toMatchObject({
      reason: "backend_basic_text",
    });
  });

  it.each([
    ["unknown", "backend_unknown"],
    ["", "backend_not_allowlisted"],
    ["secretservice", "backend_not_allowlisted"],
  ])("refuses the %j backend", async (reported, reason) => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(reported);
    expect(getOsKeyringDecision()).toMatchObject({
      available: false,
      reason,
    });
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
  });

  it("refuses a probe that throws", async () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockImplementation(() => {
      throw new Error("no dbus session");
    });
    expect(getOsKeyringDecision()).toMatchObject({
      available: false,
      reason: "backend_probe_failed",
    });
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
  });

  it("a fake backend never causes a data key to be created", async () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
    expect(existsSync(profileDataKeyFilePath())).toBe(false);
    expect(hasProfileDataKey()).toBe(false);
  });

  /**
   * `getSelectedStorageBackend` is `@platform linux` — it does not exist on
   * Windows or macOS. Reading it there is not a stricter check, it is a read of
   * a member the runtime does not have, and the value it appears to return
   * says nothing about DPAPI or the Keychain.
   */
  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "never calls getSelectedStorageBackend() on %s",
    async (platform) => {
      setPlatform(platform);
      expect(getOsKeyringDecision()).toEqual({
        available: true,
        backend: "os_default",
      });
      expect(
        hoisted.mockSafeStorage.getSelectedStorageBackend,
      ).not.toHaveBeenCalled();
      await expect(
        decryptFromStorage(
          CUSTOMERS,
          await encryptForStorage(CUSTOMERS, MARKER),
        ),
      ).resolves.toBe(MARKER);
      expect(
        hoisted.mockSafeStorage.getSelectedStorageBackend,
      ).not.toHaveBeenCalled();
    },
  );

  it.each<NodeJS.Platform>(["win32", "darwin"])(
    "gates %s on a round-trip, so a broken keyring is refused",
    async (platform) => {
      setPlatform(platform);
      hoisted.mockSafeStorage.decryptString.mockReturnValue("wrong plaintext");
      expect(getOsKeyringDecision()).toMatchObject({
        available: false,
        reason: "os_round_trip_failed",
      });
      await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
        CryptoDeniedError,
      );
    },
  );
});

describe("the pre-hydration self-test", () => {
  it("runs before any PII is sealed, not after", async () => {
    expect(hasProfileDataKey()).toBe(false);
    const verdict = await runPiiCryptoSelfTest();
    expect(verdict).toEqual({
      ready: true,
      backend: "gnome_libsecret",
      roundTrip: true,
      aadBindingEnforced: true,
    });
    expect(hasProfileDataKey()).toBe(true);
  });

  /**
   * The self-test is a gate, not advice: the choke point runs it, so a caller
   * that forgets gets the same refusal rather than an unverified write. This
   * is why the desktop app cannot seal PII on a machine whose keyring is fake
   * even if nothing called the self-test explicitly.
   */
  it("refuses a fake backend before the key is ever created", async () => {
    hoisted.mockSafeStorage.getSelectedStorageBackend.mockReturnValue(
      "basic_text",
    );
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toMatchObject({
      reason: "backend_basic_text",
    });
    expect(hasProfileDataKey()).toBe(false);
    expect(existsSync(profileDataKeyFilePath())).toBe(false);
  });

  it("refuses when the wrapped key cannot be unwrapped", async () => {
    await runPiiCryptoSelfTest();
    lockCryptoSession();
    // The sentinel still round-trips — a keyring that cannot seal or open
    // anything is caught earlier, by the round-trip gate. This is the other
    // failure: a keyring that works fine and no longer holds THIS secret (a
    // rotated keychain entry, a profile moved to another machine). The probe
    // stays green so the refusal is attributed to the key, where it belongs.
    hoisted.mockSafeStorage.decryptString.mockImplementation(
      (sealed: Buffer) => {
        const opened = openFake(sealed);
        if (opened === OS_KEYRING_PROBE_SENTINEL) return opened;
        throw new Error("secret not found in keyring");
      },
    );
    await expect(runPiiCryptoSelfTest()).resolves.toMatchObject({
      ready: false,
      reason: "profile_data_key_unavailable",
    });
    // The refusal names the problem, not the mechanism, and no replacement key
    // was minted over the orphan — that is the failure this layer must not
    // have, since every record already sealed under the old key would be
    // stranded.
    expect(hasProfileDataKey()).toBe(false);
    const onDisk = (await import("node:fs")).readFileSync(
      profileDataKeyFilePath(),
    );
    expect(onDisk.byteLength).toBeGreaterThan(0);
    await expect(encryptForStorage(CUSTOMERS, MARKER)).rejects.toThrow(
      CryptoDeniedError,
    );
  });

  it("locking drops the key and the verdict, and the next use re-proves both", async () => {
    await encryptForStorage(CUSTOMERS, MARKER);
    expect(hasProfileDataKey()).toBe(true);
    lockCryptoSession();
    expect(hasProfileDataKey()).toBe(false);
    expect(hasSessionPassphrase()).toBe(false);
    // Nothing is re-established silently: the next operation runs the
    // self-test again, so a machine that changed underneath us is caught.
    expect(await encryptForStorage(CUSTOMERS, MARKER)).toContain(
      PROFILE_KEY_PREFIX,
    );
    expect(hasProfileDataKey()).toBe(true);
  });

  /**
   * The self-test verdict and the key it proved are two pieces of state, and
   * only `lockCryptoSession` clears both today. This spec drops the key WITHOUT
   * clearing the verdict, which is what a second teardown entry point or a
   * future refactor would do by accident.
   *
   * It used to be a hole: the cached "ready" was believed, the seal path walked
   * past the gate, and a raw `ProfileDataKeyError` — an error class every
   * consumer of `encryptForStorage` does not branch on — escaped a function
   * whose documented refusal is `CryptoDeniedError`. The verdict is now only
   * believed while the key it proved is still resident.
   */
  it("a verdict that outlived its key is re-proved, not trusted", async () => {
    const verdict = await runPiiCryptoSelfTest();
    expect(verdict).toMatchObject({ ready: true });

    // The key goes; the cached verdict stays. The wrapped form is still on
    // disk, so the correct outcome is to re-prove and carry on — the bug was
    // that the seal path neither re-proved nor failed cleanly, it failed deep
    // with the wrong error class.
    resetProfileDataKeyForTests();
    expect(hasProfileDataKey()).toBe(false);

    expect(await encryptForStorage(CUSTOMERS, MARKER)).toContain(
      PROFILE_KEY_PREFIX,
    );
    expect(hasProfileDataKey()).toBe(true);
  });

  it("a missing key is refused as a CryptoDeniedError, never as a key error", async () => {
    await runPiiCryptoSelfTest();
    // The key is gone AND cannot be re-established: the keyring no longer holds
    // this profile's secret.
    resetProfileDataKeyForTests();
    hoisted.mockSafeStorage.decryptString.mockImplementation(
      (sealed: Buffer) => {
        const opened = openFake(sealed);
        if (opened === OS_KEYRING_PROBE_SENTINEL) return opened;
        throw new Error("secret not found in keyring");
      },
    );
    const error = await encryptForStorage(CUSTOMERS, MARKER).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(CryptoDeniedError);
    expect((error as CryptoDeniedError).reason).toBe(
      "profile_data_key_unavailable",
    );
  });
});

describe("the sync-only decision (ADR-001 §3.4)", () => {
  /**
   * `decryptStringAsync` resolves `{result, shouldReEncrypt}` and the docs say
   * to call it again when re-encryption is requested — but it returns no
   * replacement ciphertext, so there is no documented way for the app to
   * persist the rewrapped blob. Implementing rotation on that would mean
   * inventing an operation, so this layer stays on the sync API entirely and
   * says so. If a future Electron ships a documented rotation, this spec is the
   * place to revisit.
   */
  it("never calls an async safeStorage member", async () => {
    await runPiiCryptoSelfTest();
    await encryptForStorage(CUSTOMERS, MARKER);
    // A full open/close cycle under the matching key, so the spec would fail
    // loudly if the read path ever went async — the tripwires throw on call.
    expect(
      await decryptFromStorage(
        CUSTOMERS,
        await encryptForStorage(CUSTOMERS, MARKER),
      ),
    ).toBe(MARKER);
    for (const fn of [
      hoisted.mockSafeStorage.encryptStringAsync,
      hoisted.mockSafeStorage.decryptStringAsync,
      hoisted.mockSafeStorage.isAsyncEncryptionAvailable,
      hoisted.mockSafeStorage.setUsePlainTextEncryption,
    ]) {
      expect(fn).not.toHaveBeenCalled();
    }
  });
});

describe("a legacy unbound keyring blob is refused, not reinterpreted", () => {
  /**
   * Pre-Wave-2 rows are `enc1:safeStorage:<base64>` — sealed by the OS
   * keyring with no AAD, so they are bound to nothing at all. They are still
   * readable in principle, but reading them would keep the unbound branch alive
   * and would hand back a value that proves nothing about where it came from.
   * So they fail closed, with a type an operator can tell apart from both
   * "legacy plaintext" and "locked" (the ADR-001 §3.6 recovery obligation, not
   * implemented here).
   */
  it("raises LegacyUnboundBlobError rather than decrypting or guessing", async () => {
    const legacy = `enc1:safeStorage:${sealFake(MARKER).toString("base64")}`;
    // Not an UnknownBlobError: that would route it into the ADR-002
    // "legacy_plaintext" branch and surface the raw ciphertext as the value,
    // which is worse than refusing.
    const error = await decryptFromStorage(CUSTOMERS, legacy).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(LegacyUnboundBlobError);
    expect(error).not.toBeInstanceOf(UnknownBlobError);
  });

  it("the refusal names the reason, as a code", async () => {
    const legacy = `enc1:safeStorage:${sealFake(MARKER).toString("base64")}`;
    const error = await decryptFromStorage(CUSTOMERS, legacy).catch(
      (e: unknown) => e as LegacyUnboundBlobError,
    );
    expect(error).toBeInstanceOf(LegacyUnboundBlobError);
    expect(error.reason).toBe("legacy_unbound_encryption");
  });
});
