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
 * The `pii_stage` preimage table (Beta5 Wave 1, migration 0004).
 *
 * It is NOT a `PII_DOMAIN_TABLE` and must not be added to that list: the list
 * is pinned, in both directions, to the `sqlite_domain_tables` surface declared
 * in the SPEC-01 fixture, so a new entry there is a privacy-contract change (a
 * new declared PII surface means a `policy_version` bump, which stops consent
 * receipts issued under the old policy from validating — SPEC-04). `pii_stage`
 * holds no user data and mirrors nothing; declaring it is the job of the wave
 * that updates SPEC-01, not a side effect of creating a table.
 *
 * It is PII-bearing all the same: a staged row carries the preimage being
 * re-homed, sealed. So every path that must leave no PII behind — the SPEC-02
 * §3 purge, the §6 rescan post-condition, the §5 snapshot payload, the ADR-003
 * §2.2.2 backup redaction — iterates `PII_ERASURE_TABLES` below, which is the
 * domain tables PLUS this one. That is the list a new PII-bearing table joins,
 * and the `history_entries` lesson is why it is a constant rather than a
 * per-module array: one table was invisible to five sites at once.
 *
 * KNOWN GAP, tracked: not yet declared on the `sqlite_domain_tables` surface in
 * the SPEC-01 fixture.
 */
export const PII_STAGE_TABLE = "pii_stage";

/** Every SQLite table the erasure, snapshot and backup paths must handle. */
export const PII_ERASURE_TABLES = [
  ...PII_DOMAIN_TABLES,
  PII_STAGE_TABLE,
] as const;

export type PiiErasureTable = (typeof PII_ERASURE_TABLES)[number];

/**
 * Row counts for every PII domain table (the ADR-002 §2.3 scan report shape).
 * Derived from the constant, so adding a table is a compile error at every
 * site that builds or consumes this shape — no site can silently omit one.
 *
 * The report covers the DOMAIN tables only: a `pii_stage` row is always a
 * sealed envelope, never legacy plaintext, which is what this report counts.
 * It is still erased (see `PII_ERASURE_TABLES`).
 */
export type PiiDomainTableCounts = Record<PiiDomainTable, number>;
