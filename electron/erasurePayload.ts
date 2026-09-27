/**
 * Erasure snapshot payload capture/restore (SPEC-02 §5).
 *
 * Extracted from `erasure.ts` so the payload builder is unit-testable: that
 * module imports `electron` directly (app/safeStorage) and therefore cannot be
 * imported from a node test. Nothing here touches Electron APIs — only the
 * SQLite client — so the real implementation is exercised directly by
 * `piiDomainTables.test.ts` rather than re-implemented in the test body.
 *
 * The domain-table loop iterates `PII_DOMAIN_TABLES`, the single source of
 * truth shared with the §3 purge/§6 rescan, the §2.3 scan report and the
 * ADR-003 §2.2.2 backup redaction.
 */

import { PII_DOMAIN_TABLES } from "./piiDomainTables.js";

/** The subset of the drizzle/better-sqlite3 client the payload path needs. */
export interface PayloadDb {
  $client: {
    prepare(sql: string): {
      get(...params: unknown[]): unknown;
      all(...params: unknown[]): unknown[];
      run(...params: unknown[]): unknown;
    };
  };
}

/**
 * Serialize every PII-bearing row the saga is about to delete, so a failed run
 * can be rolled back. A table absent from this database yields an empty array
 * (idempotent: older profiles predate some tables).
 */
export function snapshotPayload(db: PayloadDb): string {
  const rows = db.$client
    .prepare("SELECT key, value FROM storage")
    .all() as Array<{ key: string; value: string }>;
  const domain: Record<string, unknown[]> = {};
  for (const table of PII_DOMAIN_TABLES) {
    try {
      domain[table] = db.$client
        .prepare(`SELECT * FROM ${table}`)
        .all() as unknown[];
    } catch {
      domain[table] = [];
    }
  }
  return JSON.stringify({ storage: rows, domain });
}

/** Restore a payload verbatim into its origin tables (SPEC-02 §5 rollback). */
export function restoreSnapshotPayload(db: PayloadDb, payload: string): void {
  const parsed = JSON.parse(payload) as {
    storage: Array<{ key: string; value: string }>;
    domain: Record<string, Array<Record<string, unknown>>>;
  };
  db.$client.prepare("DELETE FROM storage").run();
  const insertStorage = db.$client.prepare(
    "INSERT INTO storage (key, value, updated_at) VALUES (?, ?, ?)",
  );
  for (const row of parsed.storage) {
    insertStorage.run(row.key, row.value, Date.now());
  }
  for (const [table, rows] of Object.entries(parsed.domain)) {
    // Rows are restored verbatim into their origin tables (column sets are
    // unchanged — the payload was captured moments earlier).
    for (const row of rows) {
      const columns = Object.keys(row);
      if (columns.length === 0) continue;
      const placeholders = columns.map(() => "?").join(", ");
      db.$client
        .prepare(
          `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})`,
        )
        .run(...columns.map((c) => (row as Record<string, unknown>)[c]));
    }
  }
}
