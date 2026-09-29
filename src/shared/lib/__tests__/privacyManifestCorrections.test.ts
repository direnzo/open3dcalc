/**
 * Beta5 Wave 0 — SPEC-01 manifest truthfulness (privacy inventory corrections).
 *
 * The Phase-1 inventory confirmed six false or missing declarations in
 * `docs/privacy/SPEC-01-manifest-fixture.json`. These tests pin the corrected
 * classifications so they cannot drift back, and enforce the global invariant
 * that no PII key is ever `plaintext_allowed` (ADR-001 zero-plaintext path).
 *
 * Follows the existing contract-test pattern of `dataManifest.test.ts`.
 */

import { describe, it, expect } from "vitest";
import manifestFixture from "../../../../docs/privacy/SPEC-01-manifest-fixture.json";
import {
  loadManifest,
  validateManifestEntry,
  isKnownKey,
  getEntry,
  type ManifestDocument,
  type ManifestEntry,
} from "@/shared/lib/dataManifest";
import { checkKey } from "@/shared/lib/manifestGate";

const doc = manifestFixture as ManifestDocument;
const manifest = loadManifest(doc);

/** Declared sqlite domain tables, by PII flag. */
function domainTables(pii: boolean): string[] {
  return doc.keys
    .filter((k) => k.surface === "sqlite_domain_tables" && k.pii === pii)
    .map((k) => k.key)
    .sort();
}

// ---------------------------------------------------------------------------
// The fixture itself must remain schema-valid
// ---------------------------------------------------------------------------

describe("SPEC-01 fixture validity after the corrections", () => {
  it("accepts every entry", () => {
    for (const entry of doc.keys) {
      expect(() => validateManifestEntry(entry)).not.toThrow();
    }
  });

  it("rejects a duplicate key (guards the two new entries)", () => {
    const clone = getEntry(manifest, "history_entries");
    expect(clone).toBeDefined();
    expect(() =>
      loadManifest({
        ...doc,
        keys: [clone as ManifestEntry, clone as ManifestEntry],
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Gap 1 — history_entries and quote_items must be declared
// ---------------------------------------------------------------------------

describe("SPEC-01: PII-bearing domain tables are declared", () => {
  it.each(["history_entries", "quote_items"])(
    "%s is registered as a PII sqlite domain table",
    (key) => {
      expect(isKnownKey(manifest, key)).toBe(true);
      const entry = getEntry(manifest, key);
      expect(entry).toMatchObject({
        key,
        surface: "sqlite_domain_tables",
        platforms: ["electron"],
        class: "user_content",
        pii: true,
        persistence: "encrypted_at_rest",
        sync: "never",
        export: "user_export",
        erasure: "erase_on_delete_all",
        legal_basis: "consent",
        owner: "demeter",
      });
      expect(entry?.retention).toEqual({
        policy: "user_controlled",
        max_days: 0,
      });
    },
  );

  it("history_entries declares a purpose naming its PII-bearing columns", () => {
    const purpose = getEntry(manifest, "history_entries")?.purpose ?? "";
    expect(purpose).toMatch(/resultJson|result_json/i);
    expect(purpose).toMatch(/snapshotJson|snapshot_json/i);
    expect(purpose).toMatch(/name/i);
  });

  it("quote_items declares a purpose naming its PII-bearing columns", () => {
    const purpose = getEntry(manifest, "quote_items")?.purpose ?? "";
    expect(purpose).toMatch(/history_entry_id|historyEntryId/);
    expect(purpose).toMatch(/name/i);
  });

  it("every declared PII domain table is in the electron PII table list", async () => {
    const { PII_DOMAIN_TABLES } =
      await import("../../../../electron/piiDomainTables");
    const declared = domainTables(true);
    expect(declared.length).toBeGreaterThan(0);
    for (const table of declared) {
      expect([...PII_DOMAIN_TABLES]).toContain(table);
    }
    expect(declared.sort()).toEqual([...PII_DOMAIN_TABLES].sort());
  });
});

// ---------------------------------------------------------------------------
// Correction 1 — open3dcalc_dashboard_v1 is not PII
// ---------------------------------------------------------------------------

describe("SPEC-01: open3dcalc_dashboard_v1 is not PII", () => {
  it("is reclassified as non-PII plaintext local state", () => {
    expect(getEntry(manifest, "open3dcalc_dashboard_v1")).toMatchObject({
      pii: false,
      persistence: "plaintext_allowed",
      legal_basis: "not_personal_data",
      sync: "never",
    });
  });

  it("purpose no longer claims persisted aggregates", () => {
    const purpose =
      getEntry(manifest, "open3dcalc_dashboard_v1")?.purpose ?? "";
    // The aggregates are computed in memory at render time and never stored
    // under this key — the old text claimed otherwise.
    expect(purpose).not.toMatch(/aggregates over user history/i);
    expect(purpose).toMatch(/printsPerMonth|prints per month/i);
    expect(purpose).toMatch(/never persisted|computed in memory/i);
  });
});

// ---------------------------------------------------------------------------
// Correction 2 — never-written staging keys
// ---------------------------------------------------------------------------

describe("SPEC-01: keys with no writer anywhere are not declared", () => {
  it.each(["idb_reports_staging", "opfs_export_staging"])(
    "%s is absent (no writer exists in any surface)",
    (key) => {
      expect(isKnownKey(manifest, key)).toBe(false);
      expect(doc.keys.some((k) => k.key === key)).toBe(false);
    },
  );

  it("open3dcalc_erasure_snapshot STAYS declared — it has a live writer", () => {
    // REGRESSION GUARD. webSnapshotStore().write() writes this key through
    // guardedStorage (erasureSaga/webStores.ts). checkKey() only throws in dev;
    // in production it returns {allowed:false} and guardedStorage.setItem()
    // returns WITHOUT writing. Removing this declaration therefore turns a
    // working snapshot writer into a SILENT NO-OP: write() looks successful,
    // canRollback later reports "snapshot_missing", and a safety snapshot the
    // user believes exists was never persisted.
    const entry = getEntry(manifest, "open3dcalc_erasure_snapshot");
    expect(entry).toBeDefined();
    expect(entry).toMatchObject({
      surface: "localStorage",
      platforms: ["web", "pwa"],
      class: "snapshot",
      pii: true,
      persistence: "encrypted_at_rest",
      sync: "never",
      export: "never",
      legal_basis: "contract_performance",
    });
    // The purpose must distinguish "declared and writable" from "the web
    // adapter is not yet wired into a production saga".
    expect(entry?.purpose).toMatch(/writable/i);
    expect(entry?.purpose).toMatch(/not.yet.wired|not-yet-wired/i);
  });

  it("the erasure snapshot key passes the S1 gate (the real production failure)", () => {
    // This is the behaviour that actually broke: the gate must ALLOW the key.
    const decision = checkKey("open3dcalc_erasure_snapshot");
    expect(decision.allowed).toBe(true);
  });

  it("erasure_snapshots is narrowed to the electron platform", () => {
    // The desktop saga uses diskSnapshotStore under userData; the separate
    // web/pwa localStorage key is open3dcalc_erasure_snapshot above.
    expect(getEntry(manifest, "erasure_snapshots")?.platforms).toEqual([
      "electron",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Correction 3 — open3dcalc_migration_done_v2 embeds raw history
// ---------------------------------------------------------------------------

describe("SPEC-01: open3dcalc_migration_done_v2 is PII-bearing", () => {
  it("is reclassified as PII and never leaves the device", () => {
    expect(getEntry(manifest, "open3dcalc_migration_done_v2")).toMatchObject({
      pii: true,
      persistence: "encrypted_at_rest",
      sync: "never",
      export: "never",
      legal_basis: "consent",
      erasure: "erase_on_delete_all",
    });
  });

  it("is no longer classed as an onboarding flag", () => {
    // The schema forbids class onboarding_flag with pii:true; the key's value
    // is a raw history array, not a flag.
    const cls = getEntry(manifest, "open3dcalc_migration_done_v2")?.class;
    expect(cls).not.toBe("onboarding_flag");
    expect(cls).not.toBe("consent_record");
  });

  it("purpose states it is a legacy compatibility input carrying raw history", () => {
    const purpose =
      getEntry(manifest, "open3dcalc_migration_done_v2")?.purpose ?? "";
    expect(purpose).toMatch(/legacy/i);
    expect(purpose).toMatch(/history/i);
  });

  it("keeps open3dcalc_products as non-PII (explicitly out of scope)", () => {
    expect(getEntry(manifest, "open3dcalc_products")).toMatchObject({
      pii: false,
      persistence: "plaintext_allowed",
      legal_basis: "not_personal_data",
    });
  });
});

// ---------------------------------------------------------------------------
// Correction 4 — appdata_temp_staging was mis-declared
// ---------------------------------------------------------------------------

describe("SPEC-01: the appdata PII-bearing surfaces are declared truthfully", () => {
  it("appdata_temp_staging stays declared — tempStagingAdapter is a real store row", () => {
    // electron/main.ts writes .open3dcalc-import-<ts>.tmp (a whole-DB copy)
    // during db:import; erasure.ts:146 wires tempStagingAdapter as store row 10.
    const entry = getEntry(manifest, "appdata_temp_staging");
    expect(entry).toBeDefined();
    expect(entry).toMatchObject({
      surface: "temp_staging",
      platforms: ["electron"],
      pii: true,
      sync: "never",
      export: "never",
      erasure: "erase_on_delete_all",
    });
    // A whole-database copy is PII; it must never be plaintext_allowed.
    expect(entry?.persistence).not.toBe("plaintext_allowed");
    expect(entry?.purpose).toMatch(/db:import/i);
  });

  it("the diagnostic backup is a SEPARATE declaration, not the old key reused", () => {
    const backup = getEntry(manifest, "appdata_diagnostic_backup");
    const staging = getEntry(manifest, "appdata_temp_staging");
    expect(backup).toBeDefined();
    expect(backup?.key).not.toBe(staging?.key);
    expect(backup?.surface).toBe("appdata_files");
    expect(staging?.surface).toBe("temp_staging");
  });

  it("appdata_diagnostic_backup declares the real 14-day retention", () => {
    // electron/diagnosticBackup.ts keeps DIAGNOSTIC_RETENTION_DAYS = 14.
    const entry = getEntry(manifest, "appdata_diagnostic_backup");
    expect(entry?.retention).toEqual({ policy: "fixed", max_days: 14 });
  });

  it("appdata_diagnostic_backup declares a non-plaintext at-rest policy", () => {
    const entry = getEntry(manifest, "appdata_diagnostic_backup");
    expect(entry?.platforms).toEqual(["electron"]);
    expect(entry?.pii).toBe(true);
    // redact:false is a straight unredacted copy today; the manifest declares
    // the REQUIRED policy, and the purpose discloses the gap.
    expect(entry?.persistence).not.toBe("plaintext_allowed");
    expect(entry?.export).toBe("diagnostic_only");
  });

  it("purpose discloses the unredacted whole-database copy", () => {
    const purpose =
      getEntry(manifest, "appdata_diagnostic_backup")?.purpose ?? "";
    expect(purpose).toMatch(/unredacted/i);
    expect(purpose).toMatch(/copyFile/i);
    expect(purpose).toMatch(/14/i);
  });
});

// ---------------------------------------------------------------------------
// Decision 1 — the policy version was bumped because policy content changed
// ---------------------------------------------------------------------------

describe("SPEC-01: policy_version reflects the Beta5 corrections", () => {
  it("is 1.8, so receipts issued under 1.6 no longer validate", () => {
    // 1.4 -> 1.5 for the corrections pinned in this file. 1.5 -> 1.6 declares
    // `pii_stage` as a PII sqlite domain table; see piiStageDeclaration.test.ts
    // for the re-consent side of that bump. 1.6 -> 1.7 declares
    // `open3dcalc_pii_vault`; see piiVaultDeclaration.test.ts for that side.
    // 1.7 -> 1.8 declares `legacy_residue`, the retained legacy ciphertext the
    // ADR-001 §3.6 recovery copies aside; see SPEC-04 §6.
    expect(doc.policy_version).toBe("1.8");
  });
});

// ---------------------------------------------------------------------------
// Global invariant — ADR-001 zero-plaintext path
// ---------------------------------------------------------------------------

describe("SPEC-01: no PII key is ever plaintext_allowed", () => {
  it("holds across the whole fixture", () => {
    for (const entry of doc.keys) {
      if (entry.pii) {
        expect(
          entry.persistence,
          `${entry.key} is PII and must not be plaintext_allowed`,
        ).not.toBe("plaintext_allowed");
      }
    }
  });

  it("holds for the newly declared PII keys specifically", () => {
    for (const key of ["history_entries", "quote_items"]) {
      const entry = getEntry(manifest, key);
      expect(entry?.pii).toBe(true);
      expect(entry?.persistence).not.toBe("plaintext_allowed");
    }
  });

  it("reclassified non-PII keys are allowed plaintext", () => {
    for (const key of ["open3dcalc_dashboard_v1", "open3dcalc_products"]) {
      expect(getEntry(manifest, key)?.persistence).toBe("plaintext_allowed");
    }
  });
});
