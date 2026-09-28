/**
 * A single unreadable key must not stop the app from starting.
 *
 * ## The regression this pins
 *
 * `loadFromDatabase()` awaited `db().load(key)` per key inside a bare loop. A
 * `LegacyUnboundBlobError` or an `EnvelopeRejectedError` from a single row
 * propagated all the way out, so `initPersistenceBridge()` rejected BEFORE
 * reaching its step 3 and 4. That means the app never registered:
 *
 *   - the `beforeunload` save-on-close handler, and
 *   - the `AUTO_SAVE_INTERVAL_MS` auto-save interval and stale-key sweep,
 *
 * and `main.tsx` rendered `<StartupBridgeFailure/>` instead of `<App/>`. One
 * unreadable row took down the whole application, and a user who could not
 * start the app could not reach the UI that would have told them which class was
 * unavailable.
 *
 * The OS keyring was the DEFAULT path before the Wave 2 remediation, so
 * `enc1:safeStorage:` rows are exactly what a normal upgrading user has. This is
 * the most likely first-run experience of the upgrade.
 *
 * ## What is NOT being changed here
 *
 * A structural failure still refuses to start: if `listKeys` itself fails, or the
 * manifest will not load, the bridge has no key set to work from and hydration
 * must not be applied from stale localStorage. That contract is unchanged and is
 * covered by `main.bridge-failure.test.tsx`. The change is narrower: a refusal
 * about ONE VALUE is isolated to that key.
 *
 * The `electronAPI.db` seam here is backed by real better-sqlite3 over a real
 * temporary file migrated by the app's own runner, and every statement is the
 * statement `electron/main.ts` runs for the same IPC channel.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ElectronAPI } from "@/platform/desktop/types/electron";
import { initPersistenceBridge } from "../persistence-bridge";
import { runMigrations } from "../../../../../db/database";

const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const SETTINGS = "open3dcalc_settings_v2";
const HISTORY = "open3dcalc_history_v2";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
const OTHER = '["Dra. Joana <joana@exemplo.teste>"]';
const SETTINGS_VALUE = '{"theme":"dark"}';
const HISTORY_VALUE = '["encerrado"]';

/**
 * A stand-in for the OS keyring: reversible by the fake, opaque in the bytes it
 * writes. XOR is not a cipher — it stands in for "the OS does something we
 * cannot see", which is the only property the seam needs.
 *
 * Written as an explicit loop rather than `Buffer.from(…).map(…)`: that
 * resolves to `Uint8Array.prototype.map`, whose result's `toString()` takes no
 * arguments, so the obvious one-liner does not typecheck.
 */
const XOR_MASK = 0x5a;
function sealFake(plain: string): Buffer {
  const bytes = Buffer.from(plain, "utf8");
  const out = Buffer.alloc(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i]! ^ XOR_MASK;
  return out;
}

/** The pre-remediation primary shape: raw safeStorage output, no AAD. */
const LEGACY_BLOB = `enc1:safeStorage:${sealFake(MARKER).toString("base64")}`;

let dir: string;
let db: Database.Database;
let registered: Array<[string, EventListenerOrEventListenerObject]>;
let deleteCalls: string[];

function storedValue(key: string): string | null {
  return (
    (
      db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
        { value: string } | undefined
    )?.value ?? null
  );
}

/**
 * The `db:hydrate` seam, backed by the real table. `load` REJECTS for a legacy
 * blob exactly as the main process does today — that rejection crossing
 * `ipcRenderer.invoke` is the mechanism the fix has to survive.
 */
function sqliteBackedDb(): ElectronAPI["db"] {
  return {
    load: async (key: string): Promise<string | null> => {
      const row = db
        .prepare("SELECT value FROM storage WHERE key = ?")
        .get(key) as { value: string } | undefined;
      if (!row) return null;
      if (row.value.startsWith("enc1:safeStorage:")) {
        throw new Error(
          "Error invoking remote method 'db:load': Error: [cryptoCapability] value is a pre-AAD keyring blob",
        );
      }
      if (row.value.startsWith("enc1:plain:")) {
        return Buffer.from(
          row.value.slice("enc1:plain:".length),
          "base64",
        ).toString("utf8");
      }
      return row.value;
    },
    save: async (key: string, value: string) => {
      db.prepare(
        "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
      ).run(key, value, Date.now());
    },
    delete: async (key: string) => {
      deleteCalls.push(key);
      db.prepare("DELETE FROM storage WHERE key = ?").run(key);
    },
    listKeys: async () =>
      (
        db.prepare("SELECT key FROM storage ORDER BY key").all() as Array<{
          key: string;
        }>
      ).map((row) => row.key),
  } as unknown as ElectronAPI["db"];
}

function seedProfile(): void {
  db.prepare("INSERT OR REPLACE INTO storage VALUES (?, ?, ?)").run(
    CUSTOMERS,
    LEGACY_BLOB,
    1,
  );
  db.prepare("INSERT OR REPLACE INTO storage VALUES (?, ?, ?)").run(
    QUOTES,
    `enc1:plain:${Buffer.from(OTHER, "utf8").toString("base64")}`,
    1,
  );
  db.prepare("INSERT OR REPLACE INTO storage VALUES (?, ?, ?)").run(
    SETTINGS,
    SETTINGS_VALUE,
    1,
  );
  db.prepare("INSERT OR REPLACE INTO storage VALUES (?, ?, ?)").run(
    HISTORY,
    HISTORY_VALUE,
    1,
  );
}

beforeEach(() => {
  registered = [];
  deleteCalls = [];
  localStorage.clear();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "o3dc-hydrate-iso-"));
  db = new Database(path.join(dir, "live.sqlite3"));
  runMigrations(db);
  seedProfile();

  (
    window as unknown as { electronAPI: { db: ElectronAPI["db"] } }
  ).electronAPI = { db: sqliteBackedDb() };

  const add = window.addEventListener.bind(window);
  vi.spyOn(window, "addEventListener").mockImplementation(
    (
      type: string,
      listener: EventListenerOrEventListenerObject,
      options?: boolean | AddEventListenerOptions,
    ) => {
      registered.push([type, listener]);
      add(type, listener, options);
    },
  );
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  for (const [type, listener] of registered) {
    window.removeEventListener(type, listener);
  }
  vi.restoreAllMocks();
  localStorage.clear();
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("one unreadable key does not brick the app", () => {
  it("registers the beforeunload handler and the auto-save interval anyway", async () => {
    // THE specific failure. Before the fix this rejected at step 2, so neither
    // handler was ever registered and `<App/>` never mounted.
    await expect(initPersistenceBridge()).resolves.toBeUndefined();

    expect(
      registered.map(([type]) => type),
      "the save-on-close handler must register even with an unreadable key",
    ).toContain("beforeunload");
  });

  it("hydrates every key it CAN read", async () => {
    await initPersistenceBridge();

    expect(localStorage.getItem(QUOTES)).toBe(OTHER);
    expect(localStorage.getItem(SETTINGS)).toBe(SETTINGS_VALUE);
    expect(localStorage.getItem(HISTORY)).toBe(HISTORY_VALUE);
  });

  it("does not hydrate the unreadable key, and does not show it as empty", async () => {
    await initPersistenceBridge();

    // Fail-closed: the unreadable value is NOT materialized.
    expect(localStorage.getItem(CUSTOMERS)).toBeNull();
    // …and it is not the raw ciphertext either. A refusal must never look like
    // data: the renderer's store would otherwise hold the customer's raw
    // ciphertext as if it were their name. `?? ""` because `toContain` throws on
    // a null receiver, which would make this a vacuous pass.
    expect(localStorage.getItem(CUSTOMERS) ?? "").not.toContain(MARKER);
    expect(localStorage.getItem(CUSTOMERS) ?? "").not.toContain("enc1:");
  });

  it("leaves the unreadable row on disk, untouched, across sweep cycles", async () => {
    // The row's absence from localStorage is a REFUSAL, not staleness. If the
    // 10 s sweep reads it as stale it deletes the very §3.6 recovery target the
    // refusal exists to preserve, within one cycle. Two cycles here, because a
    // single one cannot distinguish "survived the sweep" from "the sweep never
    // ran" — which is the vacuous pass this test used to be.
    vi.useFakeTimers();
    try {
      await initPersistenceBridge();
      expect(storedValue(CUSTOMERS)).toBe(LEGACY_BLOB);

      for (let cycle = 0; cycle < 2; cycle++) {
        await vi.advanceTimersByTimeAsync(10_000);
        expect(storedValue(CUSTOMERS), `cycle ${cycle + 1}`).toBe(LEGACY_BLOB);
      }

      expect(
        deleteCalls,
        "the sweep must never issue a delete for a key it could not read",
      ).not.toContain(CUSTOMERS);
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it("preserves a declared key whose read failed for a reason that is not the legacy shape", async () => {
    // The fix must not pattern-match `enc1:safeStorage:`. ANY per-key read
    // failure leaves the key absent from localStorage, and absence caused by a
    // failure is not evidence of staleness — whatever the failure's shape. The
    // failure below is deliberately an unforeseen one: its code is not in the
    // known set, so the reason falls back to the generic `unreadable`.
    const dbApi = (
      window as unknown as { electronAPI: { db: ElectronAPI["db"] } }
    ).electronAPI.db;
    const originalLoad = dbApi.load.bind(dbApi);
    dbApi.load = async (key: string): Promise<string | null> => {
      if (key === HISTORY) {
        throw new Error(
          "Error invoking remote method 'db:load': Error: a_failure_reason_that_did_not_exist_at_head",
        );
      }
      return originalLoad(key);
    };

    vi.useFakeTimers();
    try {
      await initPersistenceBridge();
      expect(storedValue(HISTORY)).toBe(HISTORY_VALUE);

      for (let cycle = 0; cycle < 2; cycle++) {
        await vi.advanceTimersByTimeAsync(10_000);
        expect(storedValue(HISTORY), `cycle ${cycle + 1}`).toBe(HISTORY_VALUE);
      }

      expect(
        deleteCalls,
        "a new failure reason must be covered by the same exclusion",
      ).not.toContain(HISTORY);
    } finally {
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it("surfaces WHICH classes are unavailable and why, in a way the UI can read", async () => {
    const seen: Array<unknown> = [];
    const listener = (event: Event): void => {
      seen.push((event as CustomEvent).detail);
    };
    window.addEventListener("open3dcalc:pii-unavailable", listener);

    await initPersistenceBridge();

    expect(
      seen.length,
      "an unavailable class must be announced, not silently skipped",
    ).toBeGreaterThan(0);
    const detail = seen[0] as {
      unavailable: Array<{ key: string; reason: string }>;
    };
    expect(detail.unavailable.map((u) => u.key)).toContain(CUSTOMERS);
    // The refusal reuses the main process's own codes rather than inventing
    // renderer-side wording.
    expect(detail.unavailable[0]!.reason).toBeTruthy();
    window.removeEventListener("open3dcalc:pii-unavailable", listener);
  });

  it("still auto-saves: the handler is live and a good key persists", async () => {
    // Init FIRST: each spec gets its own registration, because the handler is
    // installed by the call and an assertion placed before it asserts on an
    // empty array and looks like a bridge that registered nothing.
    await initPersistenceBridge();

    const beforeunload = registered.filter(([t]) => t === "beforeunload");
    expect(
      beforeunload,
      "the save-on-close handler must be registered exactly once",
    ).toHaveLength(1);

    localStorage.setItem(SETTINGS, '{"theme":"light"}');
    const saved = new Map<string, string>();
    const dbApi = (
      window as unknown as {
        electronAPI: {
          db: { save: (k: string, v: string) => Promise<void> };
        };
      }
    ).electronAPI.db;
    dbApi.save = async (k: string, v: string) => {
      saved.set(k, v);
    };

    // Fire the REAL registered listener — the assertion is that the handler the
    // bridge installed actually works, not that a stub was called.
    const listener = beforeunload[0]![1];
    if (typeof listener === "function") {
      (listener as EventListener)(new Event("beforeunload"));
    }
    await vi.waitFor(() =>
      expect(saved.get(SETTINGS), "a readable key must still persist").toBe(
        '{"theme":"light"}',
      ),
    );
  });

  it("registers the auto-save interval, not just the beforeunload handler", async () => {
    // The interval is a different failure from the handler: it is what makes
    // saves happen at all if `beforeunload` never fires. Both were skipped by
    // the same throw, so both are asserted.
    const setIntervalSpy = vi.spyOn(globalThis, "setInterval");
    await initPersistenceBridge();
    expect(
      setIntervalSpy.mock.calls.length,
      "the auto-save interval must be registered despite the unreadable key",
    ).toBeGreaterThan(0);
  });

  it("a structural failure is still terminal — this fix is not a blanket catch", async () => {
    // If `listKeys` itself fails there is no key set to isolate, and hydrating
    // from stale localStorage would look like success and then lose every write.
    (
      window as unknown as {
        electronAPI: { db: ElectronAPI["db"] };
      }
    ).electronAPI.db.listKeys = async () => {
      throw new Error("SQLITE_CANTOPEN: unable to open database file");
    };

    await expect(initPersistenceBridge()).rejects.toThrow();
    expect(
      registered.map(([type]) => type),
      "a structural failure must not register handlers either",
    ).not.toContain("beforeunload");
  });
});
