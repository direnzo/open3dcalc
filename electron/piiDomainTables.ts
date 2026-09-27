/**
 * The canonical PII-bearing SQLite domain table list (SPEC-01 §keys,
 * SPEC-02 §3 row 2) — ONE source of truth for the whole Electron main process.
 *
 * `history_entries` was missing from every one of the five hardcoded lists
 * that used to exist (privacy scan report, IPC report type, erasure purge +
 * rescan, erasure snapshot payload, diagnostic-backup redaction). Its
 * `resultJson` / `snapshotJson` / `name` columns are PII-bearing, so the
 * SPEC-02 `rescan` post-condition reported "clean" while those rows survived —
 * silent plaintext residue in an already-shipped feature.
 *
 * Every one of those sites now imports this constant, so the lists can no
 * longer drift apart. Each table MUST also be declared `pii: true` on the
 * `sqlite_domain_tables` surface in `docs/privacy/SPEC-01-manifest-fixture.json`
 * (enforced by `piiDomainTables.test.ts` and
 * `privacyManifestCorrections.test.ts`).
 *
 * Adapters MUST treat a missing table as already-empty (idempotent): profiles
 * created before a table was introduced do not have it.
 */

export const PII_DOMAIN_TABLES = [
  "customers",
  "quotes",
  "quote_items",
  "history_entries",
] as const;

export type PiiDomainTable = (typeof PII_DOMAIN_TABLES)[number];

/**
 * Row counts for every PII domain table (the ADR-002 §2.3 scan report shape).
 * Derived from the constant, so adding a table is a compile error at every
 * site that builds or consumes this shape — no site can silently omit one.
 */
export type PiiDomainTableCounts = Record<PiiDomainTable, number>;
