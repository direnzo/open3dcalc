-- Open3DCalc — Migration 0004: PII stage table (Beta5 Wave 1, data layer)
--
-- Where a SEALED preimage is parked between reading a plaintext source and
-- writing its encrypted replacement. Staging it as a row in `storage` is
-- provably impossible, not merely racy:
--
--   * `persistence-bridge.deleteStaleKeys()` runs every AUTO_SAVE_INTERVAL_MS
--     (10 s) and DELETES every `storage` key absent from renderer
--     localStorage — a stage row stored there is gone within one poll.
--   * `loadFromDatabase()` materializes every manifest-allowed `storage` row
--     into renderer localStorage as PLAINTEXT, which is the exact mirror this
--     remediation removes, recreated on the next launch.
--
-- A separate table is invisible to `db:list-keys` and to that sweep, so a
-- staged preimage survives exactly as long as its own state machine says.
--
-- The blob is an ADR-001 sealed envelope ("enc1:…"), never plaintext: this
-- table holds the ENCRYPTED preimage, which is why it is treated as a PII
-- table by the erasure purge/rescan, the §5 snapshot payload and the
-- ADR-003 §2.2.2 diagnostic-backup redaction (see electron/piiDomainTables.ts
-- → PII_ERASURE_TABLES).
--
-- Columns: transaction_id + generation identify WHICH preimage of WHICH
-- attempt (a retry writes the next generation instead of overwriting a row
-- that may already have been applied); privacy_epoch / schema_version /
-- envelope_version are the AAD components the preimage is bound to, kept
-- beside the ciphertext so a resuming reader can refuse a row sealed under a
-- policy this build no longer speaks; state is `staged` (destination not yet
-- written) or `applied` (destination written and verified, stage row not yet
-- retired). There is deliberately no CHECK on `state`: the vocabulary is
-- pinned by the PiiStageState union in electron/piiStage.ts, and a CHECK could
-- not be widened later without rebuilding the table.
--
-- ONE statement, IF NOT EXISTS: `runMigrations` (db/database.ts) executes each
-- statement on its own with NO transaction and tolerates only
-- "…already exists" and "duplicate column name:". A single idempotent
-- statement means the only reachable outcome of a partial run is "already
-- applied" — the file cannot leave half a table behind.
--
-- DOWN (rollback, see db/migrate.ts):
--   DROP TABLE IF EXISTS `pii_stage`;

CREATE TABLE IF NOT EXISTS `pii_stage` (
  `transaction_id` TEXT NOT NULL,
  `generation` INTEGER NOT NULL,
  `privacy_epoch` INTEGER NOT NULL,
  `schema_version` INTEGER NOT NULL,
  `envelope_version` INTEGER NOT NULL,
  `state` TEXT NOT NULL,
  `blob` TEXT NOT NULL,
  `created_at` INTEGER NOT NULL,
  PRIMARY KEY (`transaction_id`, `generation`)
);
