-- Open3DCalc — Migration 0005: legacy ciphertext residue (Beta5 Wave 2, §3.6)
--
-- Where a RETAINED legacy at-rest blob is parked when ADR-001 §3.6 recovery
-- re-seals a value under the new bound envelope. The approved mode for this
-- programme is COPY-AND-NEVER-DELETE, so the recovery cannot consume the blob
-- it read: the old bytes are moved here first, byte for byte, and the `storage`
-- row is rewritten with the new sealed value.
--
-- Why a separate table, and why not a `storage` row — the same two provable
-- reasons as `pii_stage` (0004):
--
--   * `persistence-bridge.deleteStaleKeys()` runs every AUTO_SAVE_INTERVAL_MS
--     (10 s) and DELETES every `storage` key absent from renderer localStorage.
--     A residue row parked in `storage` is gone within one poll, which would
--     silently drop the only retained copy of a value that may not be
--     recoverable from any other source.
--   * `loadFromDatabase()` materializes every manifest-ALLOWED `storage` row
--     into renderer localStorage. A residue row is manifest-UNKNOWN, so it is
--     never materialized — but relying on that alone leaves it one manifest
--     change away from being decrypted into the renderer.
--
-- The blob is the LEGACY CIPHERTEXT, never plaintext: `enc1:safeStorage:<b64>` is
-- the OS keyring's own output and `enc1:envelope:{…}` v1.1 is an AES-256-GCM
-- envelope. Neither is readable without the keyring or the session passphrase, so
-- this table is treated as a PII table by the erasure purge/rescan, the §5
-- snapshot payload and the ADR-003 §2.2.2 diagnostic-backup redaction (see
-- electron/piiDomainTables.ts → PII_ERASURE_TABLES).
--
-- Columns:
--   * `key`                  — the storage key the legacy blob was found under.
--   * `shape`                — which legacy shape it was, so an operator reading
--                              the table can tell a keyring blob from a 1.1
--                              envelope without decoding either.
--   * `blob`                 — the legacy ciphertext, byte-identical to what was
--                              in `storage`. Never modified after insert.
--   * `recovered_at`         — when the copy was taken.
--   * `recovered_value_sha`  — SHA-256 of the PLAINTEXT the recovery re-sealed, so
--                              a later audit can prove the retained blob is the
--                              same value that is now sealed, without storing the
--                              plaintext anywhere. A digest of a value, not the
--                              value.
--
-- ONE statement, IF NOT EXISTS: `runMigrations` (db/database.ts) executes each
-- statement on its own with NO transaction and tolerates only "…already exists"
-- and "duplicate column name:". A single idempotent statement means the only
-- reachable outcome of a partial run is "already applied".
--
-- DOWN (rollback, see db/migrate.ts):
--   DROP TABLE IF EXISTS `legacy_residue`;

CREATE TABLE IF NOT EXISTS `legacy_residue` (
  `key` TEXT PRIMARY KEY NOT NULL,
  `shape` TEXT NOT NULL,
  `blob` TEXT NOT NULL,
  `recovered_value_sha` TEXT NOT NULL,
  `recovered_at` INTEGER NOT NULL
);
