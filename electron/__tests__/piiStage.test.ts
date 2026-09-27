/**
 * @vitest-environment node
 *
 * Beta5 Wave 1 — the `pii_stage` preimage state machine, over REAL SQLite.
 *
 * The schema is not hand-written here: every test migrates a real temporary
 * database file with the app's own runner (`runMigrations`), so a change to
 * `db/migrations/0004_pii_stage.sql` that this module does not agree with
 * fails these tests instead of passing against a fixture that drifted.
 *
 * What is under test, and why each assertion is the one that matters:
 *
 *  - Writes are proven by RE-READING BYTES. `run().changes` is a match count,
 *    not a receipt: a statement that matched nothing and a statement that
 *    stored the wrong bytes both report one. The tests therefore read the
 *    stored blob back out of the file, and separately inject a lying client to
 *    prove the verification path is real (an unverified write must ROLL BACK,
 *    not land).
 *  - Each step owns its transaction. The rollback assertions use fault
 *    injection INSIDE the real `db.transaction(...)` wrapper, so a failed step
 *    leaves neither the destination nor a partial stage row.
 *  - No step VACUUMs. A statement recorder asserts it, rather than a comment
 *    claiming it.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  deleteSourceRow,
  discardStage,
  markStageApplied,
  readStage,
  stagePreimage,
  writeDestination,
  PiiStageVerificationError,
  type PiiStageRow,
  type StageDb,
} from "../piiStage.js";
import { runMigrations } from "../../db/database.js";

const MARKER = "Fernanda Sintética <fernanda@exemplo.teste>";
/** A sealed envelope. Real blobs are ciphertext; the shape is what matters. */
const SEALED = `enc1:envelope:${Buffer.from(MARKER, "utf8").toString("base64")}`;
const KEY = "open3dcalc_customers_v1";
const LEGACY = '{"name":"Fernanda Sintética","note":"pré-beta"}';

let dir: string;
let dbPath: string;
let db: Database.Database;

function stageRow(overrides: Partial<PiiStageRow> = {}): PiiStageRow {
  return {
    transactionId: "tx-0001",
    generation: 1,
    privacyEpoch: 2,
    schemaVersion: 1,
    envelopeVersion: 3,
    state: "staged",
    blob: SEALED,
    createdAt: 1_700_000_000_000,
    ...overrides,
  };
}

/** The blob as it is actually on disk — not as it was handed to a writer. */
function storedStageBlob(
  transactionId = "tx-0001",
  generation = 1,
): string | undefined {
  return (
    db
      .prepare(
        "SELECT blob FROM pii_stage WHERE transaction_id = ? AND generation = ?",
      )
      .get(transactionId, generation) as { blob: string } | undefined
  )?.blob;
}

function storedDestination(key = KEY): string | null {
  return (
    (
      db.prepare("SELECT value FROM storage WHERE key = ?").get(key) as
        { value: string } | undefined
    )?.value ?? null
  );
}

/**
 * A client that lies about ONE statement's result while every real statement
 * (and the real transaction wrapper) still runs. Used to prove the
 * re-read verification is load-bearing: with it, a write whose bytes cannot be
 * confirmed must leave the database exactly as it was.
 */
function clientLyingAbout(sqlFragment: string, value: unknown): StageDb {
  const real = db as unknown as StageDb;
  return {
    prepare(sql: string) {
      if (sql.includes(sqlFragment)) {
        return { get: () => value, run: () => ({}), all: () => [] };
      }
      return real.prepare(sql);
    },
    transaction: real.transaction.bind(real),
  };
}

/** Records every statement the layer issues, so "no VACUUM" is assertable. */
function recordingClient(recorded: string[]): StageDb {
  const real = db as unknown as StageDb;
  return {
    prepare(sql: string) {
      recorded.push(sql);
      return real.prepare(sql);
    },
    transaction: real.transaction.bind(real),
  };
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "o3dc-pii-stage-"));
  dbPath = path.join(dir, "live.sqlite3");
  db = new Database(dbPath);
  // The shipped migrations, not a hand-written fixture.
  runMigrations(db);
});

afterEach(() => {
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("S2 stagePreimage — proof by re-read, not by changes", () => {
  it("stores the sealed preimage and returns it as it reads back from disk", () => {
    const row = stageRow();
    const returned = stagePreimage(db as unknown as StageDb, row);

    // Proven by re-reading the bytes out of the file, and separately from the
    // return value: a writer that echoed its input back would pass the second
    // assertion and fail this one.
    expect(storedStageBlob()).toBe(SEALED);
    expect(returned).toEqual(row);
    expect(fs.readFileSync(dbPath).includes(Buffer.from(SEALED, "utf8"))).toBe(
      true,
    );
    // The legacy plaintext is NOT what landed: the stage holds the envelope.
    expect(storedStageBlob()).not.toBe(LEGACY);
  });

  it("carries the AAD components beside the ciphertext, so a resuming reader can refuse a foreign row", () => {
    stagePreimage(db as unknown as StageDb, stageRow());
    const stored = readStage(db as unknown as StageDb, "tx-0001");
    expect(stored).toMatchObject({
      privacyEpoch: 2,
      schemaVersion: 1,
      envelopeVersion: 3,
      state: "staged",
    });
  });

  it("keeps a retry in the next generation instead of overwriting a live preimage", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    stagePreimage(client, stageRow({ generation: 2, blob: `${SEALED}:retry` }));

    expect(
      db.prepare("SELECT generation FROM pii_stage ORDER BY generation").all(),
    ).toEqual([{ generation: 1 }, { generation: 2 }]);
    // The newest generation is what a resuming reader gets.
    expect(readStage(client, "tx-0001")?.generation).toBe(2);
  });

  it("rolls the write back when the stored bytes cannot be confirmed", () => {
    // The lie is in the VERIFICATION read, so the INSERT has already run when
    // the check fails. If the check were not inside the transaction, this row
    // would be sitting on disk right now with unverified contents.
    const lying = clientLyingAbout("FROM pii_stage", undefined);
    expect(() => stagePreimage(lying, stageRow())).toThrow(
      PiiStageVerificationError,
    );
    expect(storedStageBlob()).toBeUndefined();
    expect(
      (db.prepare("SELECT COUNT(*) AS c FROM pii_stage").get() as { c: number })
        .c,
    ).toBe(0);
  });

  it("rolls the write back when the stored bytes DIFFER from the sealed preimage", () => {
    const lying = clientLyingAbout("FROM pii_stage", {
      transaction_id: "tx-0001",
      generation: 1,
      privacy_epoch: 2,
      schema_version: 1,
      envelope_version: 3,
      state: "staged",
      blob: "enc1:envelope:TAMPERED",
      created_at: 1_700_000_000_000,
    });
    expect(() => stagePreimage(lying, stageRow())).toThrow(
      /did not store the bytes/,
    );
    expect(storedStageBlob()).toBeUndefined();
  });

  it("refuses to re-stage the same generation, instead of clobbering it", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    expect(() =>
      stagePreimage(client, stageRow({ blob: "enc1:other" })),
    ).toThrow();
    expect(storedStageBlob()).toBe(SEALED);
  });
});

describe("S4 writeDestination — the sealed blob lands verbatim", () => {
  it("writes the envelope as-is and proves it by re-reading the stored bytes", () => {
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);

    const returned = writeDestination(
      db as unknown as StageDb,
      KEY,
      SEALED,
      1_700_000_000_001,
    );

    expect(returned).toBe(SEALED);
    expect(storedDestination()).toBe(SEALED);
    expect(storedDestination()).not.toBe(LEGACY);
  });

  it("rolls back to the previous value when the write cannot be confirmed", () => {
    // "a transaction abort leaves neither destination nor partial state": the
    // destination keeps the value it had, because the transaction rolled back.
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);

    const lying = clientLyingAbout("SELECT value FROM storage", {
      value: "enc1:envelope:TAMPERED",
    });
    expect(() => writeDestination(lying, KEY, SEALED)).toThrow(
      PiiStageVerificationError,
    );

    expect(storedDestination()).toBe(LEGACY);
  });

  it("aborts without touching the destination when SQLite itself refuses the write", () => {
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);
    db.exec(`
      CREATE TRIGGER refuse_destination
      BEFORE INSERT ON storage WHEN NEW.key = '${KEY}'
      BEGIN SELECT RAISE(ABORT, 'synthetic destination refusal'); END;
    `);

    expect(() =>
      writeDestination(db as unknown as StageDb, KEY, SEALED),
    ).toThrow(/synthetic destination refusal/);
    expect(storedDestination()).toBe(LEGACY);
  });

  it("moves the stage row to applied in its own transaction, verified by re-read", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    const applied = markStageApplied(client, "tx-0001", 1);

    expect(applied.state).toBe("applied");
    expect(
      (
        db
          .prepare(
            "SELECT state FROM pii_stage WHERE transaction_id = ? AND generation = ?",
          )
          .get("tx-0001", 1) as { state: string }
      ).state,
    ).toBe("applied");
    // The preimage is still there: S6 has not run, so a crash here is
    // recoverable rather than a hole where the data used to be.
    expect(storedStageBlob()).toBe(SEALED);
  });
});

describe("S6 discardStage — retired by re-read, idempotently", () => {
  it("removes exactly the named generation and leaves the others", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    stagePreimage(client, stageRow({ generation: 2 }));

    expect(discardStage(client, "tx-0001", 1)).toBe(true);

    expect(storedStageBlob("tx-0001", 1)).toBeUndefined();
    expect(storedStageBlob("tx-0001", 2)).toBe(SEALED);
    expect(readStage(client, "tx-0001")?.generation).toBe(2);
  });

  it("is a no-op success on a re-drive (SPEC-02 §2 resume rule)", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    discardStage(client, "tx-0001", 1);
    expect(discardStage(client, "tx-0001", 1)).toBe(true);
    expect(readStage(client, "tx-0001")).toBeNull();
  });

  it("rolls back (i.e. keeps the row) when the delete cannot be confirmed", () => {
    const client = db as unknown as StageDb;
    stagePreimage(client, stageRow());
    const lying = clientLyingAbout("FROM pii_stage", {
      transaction_id: "tx-0001",
      generation: 1,
      privacy_epoch: 2,
      schema_version: 1,
      envelope_version: 3,
      state: "staged",
      blob: SEALED,
      created_at: 1_700_000_000_000,
    });
    expect(() => discardStage(lying, "tx-0001", 1)).toThrow(
      PiiStageVerificationError,
    );
    expect(storedStageBlob()).toBe(SEALED);
  });
});

describe("S8 deleteSourceRow — one source, one transaction", () => {
  it("deletes a plaintext source row and proves it by re-reading", () => {
    const client = db as unknown as StageDb;
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
      "open3dcalc_quotes_v1",
      LEGACY,
      1,
    );

    expect(deleteSourceRow(client, KEY)).toBe(true);
    expect(storedDestination(KEY)).toBeNull();
    // The other source is untouched — each source is its own transaction.
    expect(storedDestination("open3dcalc_quotes_v1")).toBe(LEGACY);
  });

  it("a failed source does not undo the sources already deleted", () => {
    // The independence that makes a partially-completed S8 resumable: the two
    // deletes are two transactions, so the first one stays committed.
    const client = db as unknown as StageDb;
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
      "open3dcalc_quotes_v1",
      LEGACY,
      1,
    );
    db.exec(`
      CREATE TRIGGER refuse_second_source
      BEFORE DELETE ON storage WHEN OLD.key = 'open3dcalc_quotes_v1'
      BEGIN SELECT RAISE(ABORT, 'synthetic source refusal'); END;
    `);

    expect(deleteSourceRow(client, KEY)).toBe(true);
    expect(() => deleteSourceRow(client, "open3dcalc_quotes_v1")).toThrow(
      /synthetic source refusal/,
    );

    expect(storedDestination(KEY)).toBeNull();
    expect(storedDestination("open3dcalc_quotes_v1")).toBe(LEGACY);
  });

  it("rolls back when the delete cannot be confirmed", () => {
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);
    const lying = clientLyingAbout("SELECT value FROM storage", {
      value: LEGACY,
    });
    expect(() => deleteSourceRow(lying, KEY)).toThrow(
      PiiStageVerificationError,
    );
    expect(storedDestination()).toBe(LEGACY);
  });
});

describe("the whole sequence, and what it must never do", () => {
  it("S2 -> S4 -> S6 -> S8 leaves the destination sealed and nothing behind", () => {
    const recorded: string[] = [];
    const recorder = recordingClient(recorded);
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(KEY, LEGACY, 1);
    db.prepare("INSERT INTO storage VALUES (?, ?, ?)").run(
      "open3dcalc_quotes_v1",
      LEGACY,
      1,
    );

    stagePreimage(recorder, stageRow());
    writeDestination(recorder, KEY, SEALED);
    markStageApplied(recorder, "tx-0001", 1);
    discardStage(recorder, "tx-0001", 1);
    deleteSourceRow(recorder, "open3dcalc_quotes_v1");

    expect(storedDestination(KEY)).toBe(SEALED);
    expect(storedStageBlob()).toBeUndefined();
    expect(storedDestination("open3dcalc_quotes_v1")).toBeNull();

    // Point 2: VACUUM cannot run inside a transaction and rewrites the whole
    // file, so no step of this state machine may issue it. Compaction is the
    // caller's decision, after the sequence commits.
    expect(recorded.filter((sql) => /vacuum/i.test(sql))).toEqual([]);
    expect(recorded.length).toBeGreaterThan(0);
  });
});
