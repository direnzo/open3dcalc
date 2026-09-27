/**
 * The PII vault's capability/lock gate — ADR-001 §2.3, fail-closed.
 *
 * The gate is the ONLY thing between a caller and the encrypted vault, so its
 * job is to be boring and total: every state in which the vault must not read
 * or write PII has exactly one reason code, and the code is a compile-time
 * constant (nothing derived from a PII value ever reaches it — TEST-MATRIX
 * §3.2, key names only).
 *
 * Two failure modes this file exists to prevent:
 *
 *  1. **A silent refusal.** A gate that returns a boolean and logs nothing
 *     turns "PII persistence is denied" into "the app forgot your data" with
 *     no way to tell the two apart. Every refusal is a typed error carrying a
 *     reason, asserted here.
 *  2. **Two choke points.** `manifestStorage` already owns the demo-session
 *     suppression predicate. If the vault consulted its own flag, a demo
 *     session would suppress localStorage writes but still seal PII into
 *     IndexedDB — and a demo session is defined as holding nothing at all
 *     (LGPD ephemeral data). So the predicate lives in the same region and the
 *     same decision function composes both.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  resolvePiiStoreRefusal,
  type PiiStoreDenialReason,
  type PiiStoreEnvironment,
} from "@/shared/lib/crypto/piiStoreCapability";
import { setDemoPersistenceSuppressed } from "@/shared/lib/manifestStorage";
import {
  isPiiPersistenceDeclined,
  isPiiStoreAllowed,
  piiStoreRefusalReason,
  setPiiPersistenceDeclined,
  setPiiStoreEnvironment,
} from "@/shared/lib/crypto/piiStoreCapability";
import {
  createPiiStore,
  lockAllPiiStores,
  resetPiiStoreRuntimeForTests,
  PiiStoreDeniedError,
  PiiStoreWriteError,
  unlockPiiStore,
} from "@/shared/lib/crypto/piiStore";
import {
  createFakeIndexedDb,
  type FakeIndexedDb,
} from "@/shared/test/fakeIndexedDb";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";

const PASS = "senha-sintética-de-teste-4242";
const KEY = "open3dcalc_customers_v1";

/** A fully capable environment — the baseline each denial is measured against. */
const CAPABLE: PiiStoreEnvironment = {
  browser: true,
  secureContext: true,
  webCryptoAvailable: true,
  indexedDbAvailable: true,
};

describe("PII vault gate: refusal is typed and total", () => {
  it("allows a capable, unlocked, consenting session", () => {
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: CAPABLE,
        declined: false,
        locked: false,
      }),
    ).toBeNull();
  });

  it("denies the four required states, each with its own reason", () => {
    const cases: Array<
      [
        string,
        Parameters<typeof resolvePiiStoreRefusal>[0],
        PiiStoreDenialReason,
      ]
    > = [
      [
        "locked",
        {
          demoSuppressed: false,
          environment: CAPABLE,
          declined: false,
          locked: true,
        },
        "profile_locked",
      ],
      [
        "Web Crypto absent",
        {
          demoSuppressed: false,
          environment: { ...CAPABLE, webCryptoAvailable: false },
          declined: false,
          locked: false,
        },
        "web_crypto_unavailable",
      ],
      [
        "IndexedDB absent",
        {
          demoSuppressed: false,
          environment: { ...CAPABLE, indexedDbAvailable: false },
          declined: false,
          locked: false,
        },
        "indexeddb_unavailable",
      ],
      [
        "insecure context",
        {
          demoSuppressed: false,
          environment: { ...CAPABLE, secureContext: false },
          declined: false,
          locked: false,
        },
        "insecure_context",
      ],
      [
        "not a browser",
        {
          demoSuppressed: false,
          environment: { ...CAPABLE, browser: false },
          declined: false,
          locked: false,
        },
        "not_a_browser",
      ],
      [
        "user declined",
        {
          demoSuppressed: false,
          environment: CAPABLE,
          declined: true,
          locked: false,
        },
        "consent_declined",
      ],
      [
        "no probe installed",
        {
          demoSuppressed: false,
          environment: null,
          declined: false,
          locked: false,
        },
        "capability_unknown",
      ],
      [
        "demo session",
        {
          demoSuppressed: true,
          environment: CAPABLE,
          declined: false,
          locked: false,
        },
        "demo_session",
      ],
    ];
    for (const [label, input, expected] of cases) {
      expect(resolvePiiStoreRefusal(input), label).toBe(expected);
    }
  });

  it("fails closed on an AMBIGUOUS probe, not just a negative one", () => {
    // ADR-001 §2.3: an undefined probe resolves to DENIED. A gate that treated
    // `undefined` as "probably fine" would turn a jsdom/old-browser gap into
    // plaintext-by-accident the moment a fallback were ever added.
    const ambiguous: PiiStoreEnvironment = {
      browser: undefined,
      secureContext: undefined,
      webCryptoAvailable: undefined,
      indexedDbAvailable: undefined,
    };
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: ambiguous,
        declined: false,
        locked: false,
      }),
    ).toBe("not_a_browser");
    // Still true once the browser question is settled: an undefined secure
    // context on a real browser is a denial too.
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: { ...ambiguous, browser: true },
        declined: false,
        locked: false,
      }),
    ).toBe("insecure_context");
  });

  it("names a non-browser runtime as such, not as an insecure context", () => {
    // The Electron main process has no `window` at all. It is not an insecure
    // context, and telling a desktop user their context is insecure sends them
    // looking for a TLS problem they do not have.
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: {
          browser: false,
          secureContext: undefined,
          webCryptoAvailable: true,
          indexedDbAvailable: false,
        },
        declined: false,
        locked: false,
      }),
    ).toBe("not_a_browser");
  });

  it("reports the most fundamental refusal, and session state last", () => {
    // Everything is wrong at once. "You cannot write here at all" is more
    // actionable than "you are locked out right now", and the locked state is
    // the only one the user can fix by unlocking — so it must not mask a
    // capability the user cannot act on.
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: true,
        environment: { ...CAPABLE, secureContext: false },
        declined: true,
        locked: true,
      }),
    ).toBe("demo_session");
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: { ...CAPABLE, indexedDbAvailable: false },
        declined: true,
        locked: true,
      }),
    ).toBe("consent_declined");
    expect(
      resolvePiiStoreRefusal({
        demoSuppressed: false,
        environment: CAPABLE,
        declined: false,
        locked: true,
      }),
    ).toBe("profile_locked");
  });
});

describe("PII vault gate: one choke point with demo suppression", () => {
  beforeEach(() => {
    setPiiStoreEnvironment(CAPABLE);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setPiiPersistenceDeclined(false);
    setDemoPersistenceSuppressed(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  it("is installed next to the demo predicate, and reads it live", () => {
    expect(piiStoreRefusalReason(false)).toBeNull();
    setDemoPersistenceSuppressed(true);
    expect(piiStoreRefusalReason(false)).toBe("demo_session");
    expect(isPiiStoreAllowed(false)).toBe(false);
    setDemoPersistenceSuppressed(false);
    expect(piiStoreRefusalReason(false)).toBeNull();
  });

  it("refuses when no capability probe was ever installed", () => {
    setPiiStoreEnvironment(null);
    expect(piiStoreRefusalReason(false)).toBe("capability_unknown");
    expect(isPiiStoreAllowed(false)).toBe(false);
  });

  it("SAMPLES the real runtime, so a capability gap is a denial and not a default", () => {
    // The gate above is fed a hand-written environment; this proves the
    // production path that builds one actually reads the platform, so a
    // browser without IndexedDB is denied instead of silently allowed.
    setPiiStoreEnvironment(null);
    vi.stubGlobal("indexedDB", undefined);
    // jsdom reports `isSecureContext` as undefined, and undefined is a denial.
    // Refused at CONSTRUCTION, not on first use: an inert handle is an
    // invitation for a caller to assume it works.
    expect(() => createPiiStore(KEY)).toThrow(PiiStoreDeniedError);
    expect(piiStoreRefusalReason(false)).toBe("insecure_context");

    // A real global factory is picked up: only the unobservable context denies.
    vi.stubGlobal("indexedDB", createFakeIndexedDb().factory);
    expect(() => createPiiStore(KEY)).toThrow(PiiStoreDeniedError);
    expect(piiStoreRefusalReason(false)).toBe("insecure_context");
    createPiiStore(KEY, { environment: { secureContext: true } });
    expect(piiStoreRefusalReason(false)).toBeNull();

    // And removing it again is the other half of the sample.
    vi.stubGlobal("indexedDB", undefined);
    expect(() =>
      createPiiStore(KEY, { environment: { secureContext: true } }),
    ).toThrow(PiiStoreDeniedError);
    expect(piiStoreRefusalReason(false)).toBe("indexeddb_unavailable");
    vi.unstubAllGlobals();
  });

  it("refuses to construct in a NON-BROWSER runtime, naming it as such", () => {
    // The Electron main process: Node, no `window`, no IndexedDB. The module
    // must LOAD there (it is inside the electron tsconfig include glob) and
    // then refuse, with a reason that does not tell a desktop user their
    // context is insecure.
    const nonBrowser: PiiStoreEnvironment = {
      browser: false,
      secureContext: undefined,
      webCryptoAvailable: true,
      indexedDbAvailable: false,
    };
    const error = (() => {
      try {
        createPiiStore(KEY, { environment: nonBrowser });
        return null;
      } catch (e: unknown) {
        return e;
      }
    })();
    expect(error).toBeInstanceOf(PiiStoreDeniedError);
    expect((error as PiiStoreDeniedError).reason).toBe("not_a_browser");
  });

  it("reads the declined flag live, so a consent change takes effect at once", () => {
    // The environment is a snapshot; consent is not. If `declined` were baked
    // into the snapshot, a withdrawal would not take effect until the store
    // was rebuilt — which is exactly when it is too late.
    expect(isPiiPersistenceDeclined()).toBe(false);
    setPiiPersistenceDeclined(true);
    expect(isPiiPersistenceDeclined()).toBe(true);
    expect(piiStoreRefusalReason(false)).toBe("consent_declined");
  });
});

describe("PII vault gate: the three denials reach the caller as typed errors", () => {
  let idb: FakeIndexedDb;

  beforeEach(() => {
    idb = createFakeIndexedDb();
    setDemoPersistenceSuppressed(false);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    setPiiStoreEnvironment(null);
    setDemoPersistenceSuppressed(false);
    setPiiPersistenceDeclined(false);
    lockAllPiiStores();
    zeroizeSessionPassphrase();
  });

  async function reasonOf(run: () => Promise<unknown>): Promise<string> {
    const error = await run().then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(PiiStoreDeniedError);
    return (error as PiiStoreDeniedError).reason;
  }

  it("denies a WRITE when the profile is locked", async () => {
    setPiiStoreEnvironment(CAPABLE);
    const store = createPiiStore(KEY, {
      indexedDb: idb.factory,
      environment: CAPABLE,
    });
    // Never unlocked: no passphrase, no held key.
    expect(store.isUnlocked()).toBe(false);
    expect(await reasonOf(() => store.write("[]"))).toBe("profile_locked");
  });

  it("denies a WRITE when the capability is absent", async () => {
    // No injected factory and no global IndexedDB: the vault has nowhere to
    // write. jsdom has no IndexedDB, so this is the real state, not a mock.
    setPiiStoreEnvironment({ ...CAPABLE, indexedDbAvailable: false });
    expect(
      await reasonOf(() =>
        unlockPiiStore(KEY, PASS, {
          environment: { ...CAPABLE, indexedDbAvailable: false },
        }),
      ),
    ).toBe("indexeddb_unavailable");
  });

  it("denies a WRITE in an insecure context", async () => {
    // Everything else capable, so the reason is unambiguously the context.
    const insecure: PiiStoreEnvironment = { ...CAPABLE, secureContext: false };
    setPiiStoreEnvironment(insecure);
    expect(
      await reasonOf(() =>
        unlockPiiStore(KEY, PASS, {
          indexedDb: idb.factory,
          environment: insecure,
        }),
      ),
    ).toBe("insecure_context");
  });

  it("denies a WRITE when the user has declined", async () => {
    setPiiStoreEnvironment(CAPABLE);
    setPiiPersistenceDeclined(true);
    expect(
      await reasonOf(() =>
        unlockPiiStore(KEY, PASS, {
          indexedDb: idb.factory,
          environment: CAPABLE,
        }),
      ),
    ).toBe("consent_declined");
  });

  it("a refusal is a PiiStoreDeniedError, not a swallowed write", async () => {
    setPiiStoreEnvironment(CAPABLE);
    const store = createPiiStore(KEY, {
      indexedDb: idb.factory,
      environment: CAPABLE,
    });
    const error = await store.write("[]").then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(PiiStoreDeniedError);
    // Not the write error type: a denial must not be mistaken for a failed
    // commit, which would send a caller into a retry loop it can never win.
    expect(error).not.toBeInstanceOf(PiiStoreWriteError);
    // The refusal happened before the vault was even OPENED, so there is no
    // database, no object store and nothing persisted.
    expect(idb.databaseNames()).toEqual([]);
  });
});
