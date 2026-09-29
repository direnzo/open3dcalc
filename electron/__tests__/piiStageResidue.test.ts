/**
 * @vitest-environment node
 *
 * Beta5 Wave 1 — the `pii_stage` table must not become a new silent-residue
 * class.
 *
 * `history_entries` is the precedent this file exists to prevent: a PII-bearing
 * table absent from five hardcoded lists, so the SPEC-02 §6 post-condition
 * reported "clean" while the rows survived. `pii_stage` is the same shape of
 * hazard with a different payload — a staged row carries the SEALED preimage of
 * a value mid-re-homing — so it is exercised here against the REAL adapters
 * over a real migrated database, at every site that has to leave no PII:
 *
 *  - the §3 purge and the §6 rescan post-condition (`erasureStores`),
 *  - the §5 snapshot payload and its rollback restore (`erasurePayload`),
 *  - the ADR-003 §2.2.2 diagnostic-backup redaction (`diagnosticBackup`),
 *  - the appData reporting path, for a stage file if one is ever written to
 *    disk (`appdataFilesAdapter`), including the recorded purge/rescan
 *    asymmetry for the `open3dcalc-backup` prefix.
 *
 * The database is migrated with the app's own runner, so a `pii_stage` that
 * changed shape would fail here rather than pass against a stale fixture.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  appdataFilesAdapter,
  sqliteDomainTablesAdapter,
} from "../erasureStores.js";
import {
  snapshotPayload,
  restoreSnapshotPayload,
  type PayloadDb,
} from "../erasurePayload.js";
import { createDiagnosticBackup } from "../diagnosticBackup.js";
import { resetDiagnosticGateForTests } from "../diagnosticGate.js";
import { PII_ERASURE_TABLES, PII_STAGE_TABLE } from "../piiDomainTables.js";
import { stagePreimage, type StageDb } from "../piiStage.js";
import { runMigrations } from "../../db/database.js";
import type { MinimalStorageDb } from "../persistGate.js";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
const SEALED = `enc1:envelope:${Buffer.from(MARKER, "utf8").toString("base64")}`;
const KEY = "open3dcalc_customers_v1";

let dir: string;
let dbPath: string;
let db: Database.Database;

function asStorageDb(): MinimalStorageDb {
  return db as unknown as MinimalStorageDb;
}

function asPayloadDb(): PayloadDb {
  return { $client: db as unknown as PayloadDb["$client"] };
}

function stageCount(): number {
  return (
    db.prepare(`SELECT COUNT(*) AS c FROM ${PII_STAGE_TABLE}`).get() as {
      c: number;
    }
  ).c;
}

function seedStagedPreimage(): void {
  const client = db as unknown as StageDb;
  stagePreimage(client, {
    transactionId: "tx-0001",
    generation: 1,
    privacyEpoch: 2,
    schemaVersion: 1,
    envelopeVersion: 3,
    state: "staged",
    blob: SEALED,
    createdAt: 1_700_000_000_000,
  });
  // The plaintext sources the preimage was taken from.
  db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
    KEY,
    '{"name":"Fernanda Sintética"}',
    1,
  );
  db.prepare(
    "INSERT INTO customers (id, name, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  ).run("c1", MARKER, "fernanda@exemplo.teste", 1, 1);
  db.prepare(
    "INSERT INTO history_entries (id, timestamp, type, name, result_json) VALUES (?, ?, ?, ?, ?)",
  ).run("h1", 1_700_000_000_000, "fdm", MARKER, "{}");
}

beforeEach(() => {
  delete process.env.OPEN3DCALC_DIAGNOSTIC;
  resetDiagnosticGateForTests();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "o3dc-pii-stage-residue-"));
  dbPath = path.join(dir, "live.sqlite3");
  db = new Database(dbPath);
  runMigrations(db);
  seedStagedPreimage();
});

afterEach(() => {
  delete process.env.OPEN3DCALC_DIAGNOSTIC;
  resetDiagnosticGateForTests();
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("the erasure list is one constant, and it includes the stage table", () => {
  it("every table the erasure paths handle is in PII_ERASURE_TABLES", () => {
    expect([...PII_ERASURE_TABLES]).toContain(PII_STAGE_TABLE);
    // The domain tables stay in the list — the stage table is additive, never a
    // replacement for them. `legacy_residue` joined at policy_version 1.8: the
    // retained legacy ciphertext is PII-bearing and must be purgeable.
    expect([...PII_ERASURE_TABLES]).toEqual([
      "customers",
      "quotes",
      "quote_items",
      "history_entries",
      "pii_stage",
      "legacy_residue",
    ]);
  });
});

describe("SPEC-02 §3 purge + §6 rescan over the stage table", () => {
  it("purges the staged preimage and the rescan reports clean", async () => {
    const adapter = sqliteDomainTablesAdapter(asStorageDb());
    await adapter.purge();

    expect(await adapter.rescan()).toEqual([]);
    expect(stageCount()).toBe(0);
  });

  it("REPORTS a staged row that survives the purge (the post-condition is not vacuous)", async () => {
    // The `history_entries` failure mode exactly: a rescan that cannot name a
    // surviving row is a rescan that lets the saga commit over residue.
    db.prepare("DELETE FROM customers").run();
    db.prepare("DELETE FROM history_entries").run();
    db.prepare(`DELETE FROM ${PII_STAGE_TABLE}`).run();
    const adapter = sqliteDomainTablesAdapter(asStorageDb());
    expect(await adapter.rescan()).toEqual([]);

    stagePreimage(db as unknown as StageDb, {
      transactionId: "tx-0002",
      generation: 1,
      privacyEpoch: 2,
      schemaVersion: 1,
      envelopeVersion: 3,
      state: "staged",
      blob: SEALED,
      createdAt: 1_700_000_000_001,
    });

    expect(await adapter.rescan()).toContain("pii_stage: 1 rows");
  });

  it("takes the sealed preimage out of the FILE, not just out of the table", async () => {
    const adapter = sqliteDomainTablesAdapter(asStorageDb());
    await adapter.purge();
    // The envelope is base64, so the sealed preimage is a real artifact in the
    // file: a row that is merely unlinked would leave it recoverable.
    expect(fs.readFileSync(dbPath).includes(Buffer.from(SEALED, "utf8"))).toBe(
      false,
    );
    expect(fs.readFileSync(dbPath).includes(Buffer.from(MARKER, "utf8"))).toBe(
      false,
    );
  });
});

describe("SPEC-02 §5 snapshot payload + rollback restore over the stage table", () => {
  it("captures the staged preimage so a rollback can restore it", () => {
    const parsed = JSON.parse(snapshotPayload(asPayloadDb())) as {
      domain: Record<string, Array<Record<string, unknown>>>;
    };
    expect(parsed.domain).toHaveProperty(PII_STAGE_TABLE);
    expect(parsed.domain[PII_STAGE_TABLE]).toHaveLength(1);
    expect(parsed.domain[PII_STAGE_TABLE][0]).toMatchObject({
      transaction_id: "tx-0001",
      generation: 1,
      privacy_epoch: 2,
      state: "staged",
      blob: SEALED,
    });
    // Every table the erasure paths handle gets a slot, present or empty.
    for (const table of PII_ERASURE_TABLES) {
      expect(parsed.domain).toHaveProperty(table);
    }
  });

  it("restores the stage row after a purge, so the post-condition is satisfiable again", async () => {
    const payload = snapshotPayload(asPayloadDb());
    const adapter = sqliteDomainTablesAdapter(asStorageDb());
    await adapter.purge();
    expect(stageCount()).toBe(0);

    restoreSnapshotPayload(asPayloadDb(), payload);

    expect(
      db
        .prepare(
          "SELECT blob FROM pii_stage WHERE transaction_id = ? AND generation = ?",
        )
        .get("tx-0001", 1),
    ).toEqual({ blob: SEALED });
    // …and the rescan names it again, which is what makes a re-run of the
    // erasure (the resume path) able to finish the job.
    expect(await adapter.rescan()).toContain("pii_stage: 1 rows");
  });

  it("a rollback does NOT destroy what was written after the snapshot", () => {
    // The old restore did `DELETE FROM storage` and re-inserted the payload, so
    // every write that landed between snapshot_taken and the failure was
    // silently annihilated — data loss caused by the recovery path itself. The
    // restore is now a merge: captured rows are put back, later ones stay.
    // (0001 seeds `open3dcalc_theme`, so the payload already carries a
    // pre-snapshot row that is neither PII nor part of the seed.)
    const payload = snapshotPayload(asPayloadDb());

    // The saga deletes everything…
    db.prepare("DELETE FROM storage").run();
    db.prepare("DELETE FROM customers").run();
    db.prepare("DELETE FROM history_entries").run();
    db.prepare(`DELETE FROM ${PII_STAGE_TABLE}`).run();
    // …and the app keeps working for the seconds before the failure, writing a
    // new row (the 10 s auto-save pass is exactly this).
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
      "open3dcalc_dashboard_v1",
      '{"written":"after the snapshot"}',
      2,
    );

    restoreSnapshotPayload(asPayloadDb(), payload);

    // The pre-snapshot rows are back…
    expect(
      db.prepare("SELECT COUNT(*) AS c FROM customers").get() as { c: number },
    ).toEqual({ c: 1 });
    expect(
      db.prepare("SELECT COUNT(*) AS c FROM history_entries").get() as {
        c: number;
      },
    ).toEqual({ c: 1 });
    expect(
      db.prepare("SELECT value FROM storage WHERE key = ?").get(KEY) as {
        value: string;
      },
    ).toEqual({ value: '{"name":"Fernanda Sintética"}' });
    // A pre-snapshot row that is not PII is restored too — the merge is not a
    // PII-only path.
    expect(
      db
        .prepare("SELECT value FROM storage WHERE key = ?")
        .get("open3dcalc_theme"),
    ).toEqual({ value: "system" });
    // …and the post-snapshot write survived.
    expect(
      db
        .prepare("SELECT value FROM storage WHERE key = ?")
        .get("open3dcalc_dashboard_v1"),
    ).toEqual({ value: '{"written":"after the snapshot"}' });
  });

  it("re-running the restore is idempotent (SPEC-02 §2 resume rule)", () => {
    const payload = snapshotPayload(asPayloadDb());
    db.prepare("DELETE FROM storage").run();
    db.prepare(`DELETE FROM ${PII_STAGE_TABLE}`).run();

    restoreSnapshotPayload(asPayloadDb(), payload);
    expect(() => restoreSnapshotPayload(asPayloadDb(), payload)).not.toThrow();
    expect(stageCount()).toBe(1);
    expect(
      db.prepare("SELECT COUNT(*) AS c FROM customers").get() as { c: number },
    ).toEqual({ c: 1 });
  });
});

describe("ADR-003 §2.2.2 diagnostic-backup redaction over the stage table", () => {
  it("strips the staged preimage from a redacted backup", async () => {
    process.env.OPEN3DCALC_DIAGNOSTIC = "1";
    resetDiagnosticGateForTests();
    const target = path.join(dir, "diag-redacted.sqlite3");

    const result = await createDiagnosticBackup({
      dbPath,
      targetPath: target,
      redact: true,
    });

    // customers + history_entries + pii_stage = 3 stripped rows.
    expect(result.strippedDomainRows).toBe(3);
    const out = new Database(target);
    const staged = out
      .prepare(`SELECT COUNT(*) AS c FROM ${PII_STAGE_TABLE}`)
      .get() as { c: number };
    out.close();
    expect(staged.c).toBe(0);
    // The sealed preimage is not sitting in the operator's artifact either.
    expect(fs.readFileSync(target).includes(Buffer.from(SEALED, "utf8"))).toBe(
      false,
    );
  });

  it("reports a table it could NOT strip, instead of counting it as clean", async () => {
    // `stripDomainTable`'s catch used to say "table absent" for ANY failure, so
    // a locked or trigger-refused DELETE produced a backup labelled
    // `redacted: true` with the rows still in it and nothing in the record. The
    // general failure mode is now named, and it is visible to the operator.
    process.env.OPEN3DCALC_DIAGNOSTIC = "1";
    resetDiagnosticGateForTests();
    const target = path.join(dir, "diag-refused.sqlite3");
    // Make the copy refuse exactly the stage-table DELETE.
    db.exec(`
      CREATE TRIGGER refuse_stage_strip
      BEFORE DELETE ON pii_stage
      BEGIN SELECT RAISE(ABORT, 'synthetic strip refusal'); END;
    `);
    const warn = console.warn;
    console.warn = () => {};

    try {
      const result = await createDiagnosticBackup({
        dbPath,
        targetPath: target,
        redact: true,
      });
      // Refusals are never reported as stripped rows.
      expect(result.strippedDomainRows).toBe(2);
      expect(result.stripFailures).toContain(PII_STAGE_TABLE);
      const meta = JSON.parse(
        fs.readFileSync(`${target}.meta.json`, "utf8"),
      ) as { strip_failures: string[] };
      expect(meta.strip_failures).toContain(PII_STAGE_TABLE);
    } finally {
      console.warn = warn;
    }
  });
});

describe("appData reporting path (erasureStores.appdataFilesAdapter)", () => {
  let userData: string;

  beforeEach(() => {
    userData = fs.mkdtempSync(path.join(os.tmpdir(), "o3dc-userdata-"));
  });

  afterEach(() => {
    fs.rmSync(userData, { recursive: true, force: true });
  });

  it("purges and reports a stage file if one is ever written to disk", async () => {
    // The stage table is a DATABASE table, so nothing writes a stage file today.
    // If a later wave spills one to disk, it must land in the erasure scope
    // rather than beside the journal: a file this adapter does not report is a
    // file the saga commits over.
    const stageFile = path.join(userData, "open3dcalc-pii-stage-0001.json");
    fs.writeFileSync(stageFile, SEALED);
    fs.writeFileSync(path.join(userData, "erasure-journal.json"), "{}");

    const adapter = appdataFilesAdapter(userData);
    expect(await adapter.purge()).toBe(1);
    expect(fs.existsSync(stageFile)).toBe(false);
    // The saga's own journal is still there.
    expect(fs.existsSync(path.join(userData, "erasure-journal.json"))).toBe(
      true,
    );
  });

  it("reports a stage file that purge could not remove", async () => {
    const stageFile = path.join(userData, "open3dcalc-pii-stage-0001.json");
    fs.writeFileSync(stageFile, SEALED);

    // A purge that failed for any reason must leave a reportable residue, or
    // the saga commits over it (§6).
    const adapter = appdataFilesAdapter(userData);
    expect(await adapter.rescan()).toEqual([
      "appdata: open3dcalc-pii-stage-0001.json",
    ]);
  });

  it("no longer exempts the open3dcalc-backup prefix from the rescan", async () => {
    // The recorded asymmetry is closed, not documented: purge deleted these
    // files but rescan skipped them, so a FAILED purge of an `open3dcalc-backup*`
    // file was invisible and the saga still committed. purge and rescan now
    // share one predicate, so they cannot disagree about what is in scope.
    const backup = path.join(userData, "open3dcalc-backup-1700000000000");
    fs.writeFileSync(backup, MARKER);

    const adapter = appdataFilesAdapter(userData);
    expect(await adapter.rescan()).toEqual([
      "appdata: open3dcalc-backup-1700000000000",
    ]);
  });

  it("rescan covers the same files purge targets, and no more", async () => {
    // Every file purge would delete, rescan names; and after a successful
    // purge, rescan is empty. The saga journal is in neither.
    fs.writeFileSync(path.join(userData, "open3dcalc.db"), "x");
    fs.writeFileSync(path.join(userData, "window-state.json"), "x");
    fs.writeFileSync(path.join(userData, "notes.txt"), "x");
    fs.writeFileSync(path.join(userData, "erasure-journal.json"), "{}");
    fs.mkdirSync(path.join(userData, "erasure-snapshots"));
    fs.writeFileSync(path.join(userData, "erasure-snapshots", "s1"), "x");

    const adapter = appdataFilesAdapter(userData);
    expect((await adapter.rescan()).sort()).toEqual([
      "appdata: open3dcalc.db",
      "appdata: window-state.json",
    ]);
    expect(await adapter.purge()).toBe(2);
    expect(await adapter.rescan()).toEqual([]);
    // Never the journal, never the snapshots.
    expect(fs.existsSync(path.join(userData, "erasure-journal.json"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(userData, "erasure-snapshots"))).toBe(true);
  });
});
