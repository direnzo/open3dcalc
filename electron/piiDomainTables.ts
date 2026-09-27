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
 * `privacyManifestCorrections.test.ts`, in BOTH directions: a manifest entry
 * with no constant behind it fails just as a constant with no manifest entry
 * does).
 *
 * Adapters MUST treat a missing table as already-empty (idempotent): profiles
 * created before a table was introduced do not have it.
 */

/**
 * The normalized PII-bearing USER CONTENT tables (db/schema/index.ts).
 *
 * Every row in one of these tables is plaintext at rest today, which is what
 * makes a row count on this list a legacy-plaintext signal (ADR-002 §2.3) — see
 * `PII_LEGACY_PLAINTEXT_TABLES` for the subset that claim is made about.
 */
export const PII_CONTENT_TABLES = [
  "customers",
  "quotes",
  "quote_items",
  "history_entries",
] as const;

/**
 * The `pii_stage` preimage table (Beta5 Wave 1, migration 0004).
 *
 * It is PII-bearing: a staged row carries the SEALED preimage of a user value
 * mid-re-homing. What separates it from `PII_CONTENT_TABLES` is not whether it
 * is PII but WHERE THE BYTES ARE — it is its own table rather than a `storage`
 * row because the 10 s `persistence-bridge` sweep deletes every `storage` key
 * the renderer does not have, and the startup pass decrypts a manifest-allowed
 * one straight back into the renderer as plaintext. Both fates are pinned by
 * `src/platform/desktop/overrides/__tests__/persistence-bridge.pii-stage.test.ts`
 * and the reason is recorded in `db/migrations/0004_pii_stage.sql`.
 *
 * DECLARED on the `sqlite_domain_tables` surface of the SPEC-01 fixture as of
 * `policy_version` 1.6 (it was a real PII surface the inventory did not name,
 * which is the `history_entries` defect one layer out). The declaration cost a
 * `policy_version` bump and therefore a re-consent, which was free only because
 * nothing had shipped under 1.5 — see SPEC-04 §6.
 */
export const PII_STAGE_TABLE = "pii_stage";

/**
 * Every PII-bearing table declared on the `sqlite_domain_tables` surface.
 *
 * Pinned in BOTH directions to that surface, so it is the exact set and not a
 * subset of what the manifest declares. Adding a table here is a
 * privacy-contract change, not a refactor: declare it, and bump
 * `policy_version` if it is new.
 */
export const PII_DOMAIN_TABLES = [
  ...PII_CONTENT_TABLES,
  PII_STAGE_TABLE,
] as const;

export type PiiDomainTable = (typeof PII_DOMAIN_TABLES)[number];

/**
 * Every SQLite table the erasure, snapshot and backup paths must handle.
 *
 * The same set as the declared PII domain tables — this alias is kept because
 * SPEC-02 §3/§5/§6 and ADR-003 §2.2.2 all speak in terms of ERASURE coverage,
 * which is a different question from what the startup scan counts, and naming
 * the two separately is what stops one answer being used for the other.
 */
export const PII_ERASURE_TABLES = PII_DOMAIN_TABLES;

export type PiiErasureTable = (typeof PII_ERASURE_TABLES)[number];

/**
 * The subset where ANY row is legacy-plaintext residue (ADR-002 §2.3) — the
 * tables the startup scan and its "profile is not clean" gate are allowed to
 * count.
 *
 * `pii_stage` is deliberately excluded. A stage row is always a sealed
 * envelope, never plaintext, so counting it would report every in-flight
 * migration as "legacy plaintext PII detected" — a false alarm that trains
 * operators to ignore the one log line that matters. The table is still erased,
 * still snapshotted and still redacted out of diagnostic backups; it is only
 * not evidence of a plaintext at-rest defect.
 */
export const PII_LEGACY_PLAINTEXT_TABLES = PII_CONTENT_TABLES;

/**
 * Row counts for every declared PII domain table (the ADR-002 §2.3 scan report
 * shape). Derived from the constant, so adding a table is a compile error at
 * every site that builds or consumes this shape — no site can silently omit
 * one.
 */
export type PiiDomainTableCounts = Record<PiiDomainTable, number>;
