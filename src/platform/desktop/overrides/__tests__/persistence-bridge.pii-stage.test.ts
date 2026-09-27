/**
 * The `pii_stage` preimage must survive the 10 s stale-key sweep.
 *
 * This is the whole reason the preimage lives in its own table instead of a row
 * in `storage`, and it is asserted here against the REAL bridge rather than a
 * description of it. `initPersistenceBridge()` registers a `setInterval` on
 * `AUTO_SAVE_INTERVAL_MS` (10 s) whose sweep (`deleteStaleKeys`) deletes every
 * `storage` key that is absent from renderer `localStorage`, and whose startup
 * pass (`loadFromDatabase`) materializes every manifest-ALLOWED `storage` row
 * into renderer `localStorage`. A preimage parked in `storage` therefore has
 * exactly two fates, both fatal:
 *
 *   - its key is not in the renderer (an internal staging key) ⇒ the sweep
 *     DELETES it within one poll. Not a race; a certainty;
 *   - its key IS manifest-allowed ⇒ `loadFromDatabase` decrypts it and writes
 *     it into the renderer as PLAINTEXT, which is the exact mirror this
 *     remediation removes, recreated on the next launch.
 *
 * Both fates are demonstrated in the SAME test run, from the SAME sweep, as
 * controls: a non-manifest `storage` row is gone after one interval, and a
 * manifest-allowed `storage` row is sitting in `localStorage` decrypted. The
 * `pii_stage` row, written through the real `stagePreimage`, is untouched by
 * both.
 *
 * The `electronAPI.db` seam is backed by REAL better-sqlite3 over a real
 * temporary file migrated by the app's own runner, and every statement it runs
 * is the statement `electron/main.ts` runs for the same IPC channel
 * (`db:load` :230, `db:save` :249, `db:delete` :271, `db:list-keys` :286).
 * `load` additionally mirrors `loadGated`'s contract — a PII row stored as an
 * `enc1:` envelope is handed back decrypted — because that decryption is the
 * second half of the hazard and the test has to see it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { ElectronAPI } from "@/platform/desktop/types/electron";
import { initPersistenceBridge } from "../persistence-bridge";
import { runMigrations } from "../../../../../db/database";
import { stagePreimage, type StageDb } from "../../../../../electron/piiStage";

/** Synthetic PII marker — never real personal data. */
const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
/** A sealed envelope, in the shape `loadGated` would hand back decrypted. */
const SEALED = `enc1:plain:${Buffer.from(MARKER, "utf8").toString("base64")}`;
/** Manifest-allowed PII key (SPEC-01): the renderer is ALLOWED to hold it. */
const ALLOWED_KEY = "open3dcalc_customers_v1";
/** A key the manifest does not know: default-deny, never materialized. */
const INTERNAL_KEY = "open3dcalc_pii_stage_tx1";

let dir: string;
let dbPath: string;
let db: Database.Database;
let registered: Array<[string, EventListenerOrEventListenerObject]>;

/** The value `storage` holds for a key, straight off disk. */
function storedValue(key: string): string | null {
  return (
    (
      db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
        { value: string } | undefined
    )?.value ?? null
  );
}

function stageRowCount(): number {
  return (
    db.prepare("SELECT COUNT(*) AS c FROM pii_stage").get() as { c: number }
  ).c;
}

function storedStageBlob(): string | undefined {
  return (
    db
      .prepare(
        "SELECT blob FROM pii_stage WHERE transaction_id = ? AND generation = ?",
      )
      .get("tx-0001", 1) as { blob: string } | undefined
  )?.blob;
}

/** Every `storage` key currently holding the sealed preimage, in key order. */
async function preimageHolders(): Promise<string[]> {
  const keys = await sqliteBackedDb().listKeys();
  return keys.filter((k) => storedValue(k) === SEALED);
}

/**
 * `window.electronAPI.db` over a real SQLite file, statement for statement the
 * handlers in `electron/main.ts` use.
 */
function sqliteBackedDb(): ElectronAPI["db"] {
  return {
    load: async (key: string) => {
      const row = db
        .prepare("SELECT value FROM storage WHERE key = ?")
        .get(key) as { value: string } | undefined;
      if (!row) return null;
      // Mirrors loadGated: a PII row is stored sealed and read back decrypted.
      return row.value.startsWith("enc1:plain:")
        ? Buffer.from(row.value.slice("enc1:plain:".length), "base64").toString(
            "utf8",
          )
        : row.value;
    },
    save: async (key: string, value: string) => {
      db.prepare(
        "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
      ).run(key, value, Date.now());
    },
    delete: async (key: string) => {
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

beforeEach(() => {
  // First: the teardown loop iterates `registered`, so it must be iterable even
  // when the setup below throws. Assigned further down, it was `undefined` here
  // and a failing `beforeEach` made `afterEach` throw
  // `TypeError: registered is not iterable` — which replaced the test's own
  // failure with a teardown failure two stacks deeper.
  registered = [];

  vi.useFakeTimers();
  localStorage.clear();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "o3dc-stage-sweep-"));
  dbPath = path.join(dir, "live.sqlite3");
  db = new Database(dbPath);
  runMigrations(db);

  // The real stage write, through the real state machine.
  stagePreimage(db as unknown as StageDb, {
    transactionId: "tx-0001",
    generation: 1,
    privacyEpoch: 2,
    schemaVersion: 1,
    envelopeVersion: 3,
    state: "staged",
    blob: SEALED,
    createdAt: 1_700_000_000_000,
  });

  // Control A: what a `storage`-table stage would look like for a key the
  // renderer never has — the manifest does not know it, so it is never
  // materialized and the sweep owns it.
  db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
    INTERNAL_KEY,
    SEALED,
    1,
  );
  // Control B: …and for a key the manifest DOES allow, where the danger is not
  // deletion but the plaintext copy the renderer is entitled to hold.
  db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
    ALLOWED_KEY,
    SEALED,
    1,
  );

  (
    window as unknown as { electronAPI: { db: ElectronAPI["db"] } }
  ).electronAPI = { db: sqliteBackedDb() };

  // initPersistenceBridge() adds one beforeunload listener per call; they close
  // over this spec's db, so they are torn down per spec.
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
});

afterEach(() => {
  for (const [type, listener] of registered) {
    window.removeEventListener(type, listener);
  }
  vi.restoreAllMocks();
  vi.clearAllTimers();
  vi.useRealTimers();
  delete (window as unknown as { electronAPI?: unknown }).electronAPI;
  localStorage.clear();
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("pii_stage vs. the 10 s persistence-bridge sweep", () => {
  it("leaves the staged preimage intact while a storage-table stage is destroyed", async () => {
    await initPersistenceBridge();

    // FATE 2, already visible at startup: the manifest-allowed `storage` row is
    // decrypted into the renderer as plaintext before any interval fires. This
    // is the mirror the remediation exists to remove.
    expect(localStorage.getItem(ALLOWED_KEY)).toBe(MARKER);

    // FATE 1: one 10 s cycle, and the internal `storage` row is gone.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(storedValue(INTERNAL_KEY)).toBeNull();

    // The staged preimage: still there, byte for byte, and never materialized
    // in the renderer. The renderer holds only what the app is entitled to hold
    // (the manifest-allowed control, plus the `open3dcalc_theme` row migration
    // 0001 seeds) — nothing stage-related, and no sealed envelope anywhere.
    expect(storedStageBlob()).toBe(SEALED);
    expect(stageRowCount()).toBe(1);
    expect(Object.keys(localStorage)).not.toContain("pii_stage");
    expect(Object.keys(localStorage).join(",")).not.toContain("tx-0001");
    for (let i = 0; i < localStorage.length; i++) {
      expect(
        localStorage.getItem(localStorage.key(i) ?? ""),
        `renderer key ${localStorage.key(i)} must not hold the sealed preimage`,
      ).not.toBe(SEALED);
    }
  });

  it("survives repeated sweep cycles, and the sweep really is the 10 s one", async () => {
    await initPersistenceBridge();

    // Nothing before the interval fires.
    expect(storedStageBlob()).toBe(SEALED);

    // Several cycles, the way a long session runs.
    for (let cycle = 0; cycle < 3; cycle++) {
      await vi.advanceTimersByTimeAsync(10_000);
      expect(storedStageBlob(), `cycle ${cycle + 1}`).toBe(SEALED);
    }
    expect(stageRowCount()).toBe(1);
    // The bytes are on disk, not just in a returned object.
    expect(fs.readFileSync(dbPath).includes(Buffer.from(SEALED, "utf8"))).toBe(
      true,
    );
    // The control is gone by now: the sweep ran, and it is the sweep that
    // removed the storage row while leaving the stage row alone.
    expect(storedValue(INTERNAL_KEY)).toBeNull();
  });

  it("never puts the sealed preimage on the key surface the sweep enumerates", async () => {
    // `deleteStaleKeys` iterates `db().listKeys()` — the `storage` keys. A
    // `storage`-backed stage is on that surface BY CONSTRUCTION, whether or not
    // the pass goes on to delete it, so the surface is checked on the VALUE:
    // which keys hold the sealed preimage. The only ones allowed to are the two
    // controls this test inserted itself.
    //
    // Asserting on key NAMES cannot do this, and the reason is worth recording:
    // no `storage` key is ever literally called "pii_stage", so
    // `expect(keys).not.toContain("pii_stage")` is a tautology over the schema
    // and passes against a stage that IS a `storage` row. Equally, a
    // `not.toBe(SEALED)` over `load(k)` does not discriminate either, because
    // this spec's `load` shim mirrors `loadGated` and hands `enc1:plain:` back
    // DECRYPTED — a storage-backed stage reads back as the marker, not the
    // sealed bytes. The stored bytes are the only thing that tells them apart.
    await initPersistenceBridge();
    expect(await preimageHolders()).toEqual([ALLOWED_KEY, INTERNAL_KEY]);

    // One cycle later the preimage is nowhere on the surface the sweep walks:
    // control A is deleted (fate 1) and control B's row has been REWRITTEN as
    // plaintext by `saveToDatabase`, which mirrors the renderer copy the
    // startup pass just decrypted (fate 2, completing). Neither control is a
    // stage, and a stage adds a third holder before the sweep even runs.
    await vi.advanceTimersByTimeAsync(10_000);
    const holders = await preimageHolders();
    expect(holders).toEqual([]);
  });
});
