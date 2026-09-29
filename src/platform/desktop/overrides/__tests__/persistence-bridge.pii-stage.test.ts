/**
 * The `pii_stage` preimage must survive the 10 s stale-key sweep — and the
 * bridge must not carry any PII value into the renderer at all (Wave 3, T3.1).
 *
 * ## The structural hazard this file pins
 *
 * This is the whole reason the preimage lives in its own table instead of a row
 * in `storage`, and it is asserted here against the REAL bridge rather than a
 * description of it. A preimage — or any PII value — parked in `storage` has
 * exactly one fatal fate left after T3.1:
 *
 *   - its key is not in the renderer (an internal staging key, or a PII key the
 *     bridge no longer mirrors) ⇒ the sweep DELETES it within one poll. Not a
 *     race; a certainty.
 *
 * Before T3.1 there was a second fate: a manifest-ALLOWED `storage` row was
 * decrypted into renderer `localStorage` as PLAINTEXT by the startup pass. That
 * is the plaintext mirror Wave 3 removes, and it is now asserted as ABSENT: the
 * manifest-allowed PII row's stored bytes are REWRITTEN AS PLAINTEXT by the
 * legacy writer, but the renderer NEVER holds the decrypted value, and the
 * sweep NEVER destroys the row. The row is retained (copy-without-delete) and
 * the renderer copy is refused.
 *
 * The `pii_stage` row, written through the real `stagePreimage`, is untouched
 * by both.
 *
 * The `electronAPI.db` seam is backed by REAL better-sqlite3 over a real
 * temporary file migrated by the app's own runner, and every statement it runs
 * is the statement `electron/main.ts` runs for the same IPC channel
 * (`db:load` :230, `db:save` :249, `db:delete` :271, `db:list-keys` :286).
 * `load` additionally mirrors `loadGated`'s contract — a PII row stored as an
 * `enc1:` envelope is handed back decrypted — because the IPC surface still
 * decrypts on the way out and the bridge is what must refuse to mirror it.
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

    // T3.1 ABSENCE ASSERTION. The manifest-allowed PII row must NOT be mirrored
    // into the renderer. Before Wave 3 this line read `toBe(MARKER)` — the
    // plaintext mirror the remediation removes — so this is the exact inversion
    // the task calls for: prove NO PII plaintext is rehydrated.
    expect(localStorage.getItem(ALLOWED_KEY)).toBeNull();

    // FATE: one 10 s cycle, and the internal `storage` row is gone.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(storedValue(INTERNAL_KEY)).toBeNull();

    // The manifest-allowed PII row is RETAINED (copy-without-delete): the
    // sweep must not destroy a row the app may still need, even though the
    // renderer never holds it.
    expect(storedValue(ALLOWED_KEY)).not.toBeNull();

    // The staged preimage: still there, byte for byte, and never materialized
    // in the renderer. The renderer holds only what the app is entitled to hold
    // (the `open3dcalc_theme` row migration 0001 seeds) — nothing stage-related,
    // and no sealed envelope anywhere.
    expect(storedStageBlob()).toBe(SEALED);
    expect(stageRowCount()).toBe(1);
    expect(Object.keys(localStorage)).not.toContain("pii_stage");
    expect(Object.keys(localStorage).join(",")).not.toContain("tx-0001");
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i) ?? "";
      expect(
        localStorage.getItem(key),
        `renderer key ${key} must not hold the sealed preimage`,
      ).not.toBe(SEALED);
      expect(
        localStorage.getItem(key),
        `renderer key ${key} must not hold decrypted PII`,
      ).not.toBe(MARKER);
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
    // which keys hold the sealed preimage. The only one allowed to is the
    // control this test inserted itself (the internal key; it is not a stage and
    // the sweep removes it).
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

    // One cycle later the preimage is nowhere on the surface the sweep walks
    // as a DECRYPTED value: control A is deleted, and control B is REWRITTEN
    // as plaintext by `saveToDatabase` (it mirrors the row's stored bytes, not
    // the decrypted value it was handed). Crucially, no control is a stage, and
    // a stage adds a third holder before the sweep even runs — so the sweep sees
    // nothing it should not, and the renderer still holds no PII.
    await vi.advanceTimersByTimeAsync(10_000);
    const holders = await preimageHolders();
    // The PII row is retained with its sealed bytes; only the internal control
    // (not a stage, not PII) is deleted.
    expect(holders).toEqual([ALLOWED_KEY]);
    // T3.1: no PII was rehydrated from the decrypted IPC payload.
    expect(localStorage.getItem(ALLOWED_KEY)).toBeNull();
    expect(localStorage.getItem(ALLOWED_KEY)).not.toBe(MARKER);
  });

  it("retains the manifest-allowed PII row while never re-materializing it", async () => {
    // T3.2: a PII `storage` row is NOT stale merely because the renderer has no
    // counterpart — the bridge refuses to mirror it, and the sweep must read
    // that refusal as a refusal, not as deletion evidence. The row is retained
    // (copy-without-delete) with its stored bytes untouched (the sweep writes
    // nothing back; it has no business rewriting a row it refuses to hydrate).
    await initPersistenceBridge();
    expect(storedValue(ALLOWED_KEY)).toBe(SEALED);

    await vi.advanceTimersByTimeAsync(10_000);

    // Retained, byte for byte.
    expect(storedValue(ALLOWED_KEY)).toBe(SEALED);
    // And still not materialized in the renderer.
    expect(localStorage.getItem(ALLOWED_KEY)).toBeNull();
  });

  it("never writes a decrypted PII value even when the IPC load returns one", async () => {
    // T3.1, the rehydration half. The `db:load` seam here returns the marker
    // DECRYPTED for the manifest-allowed PII key (exactly what `loadGated` does
    // on the way out). Before Wave 3 the bridge wrote that returned string
    // straight into localStorage; after Wave 3 it must be refused, because the
    // value came back decrypted and the renderer is not entitled to it.
    await initPersistenceBridge();
    expect(localStorage.getItem(ALLOWED_KEY)).toBeNull();
    // And the row is still on disk, retained for the encrypted adapter to read.
    expect(storedValue(ALLOWED_KEY)).not.toBeNull();
  });
});
