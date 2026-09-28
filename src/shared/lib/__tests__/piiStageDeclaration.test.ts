/**
 * Beta5 Wave 1 close-out — `pii_stage` is a DECLARED PII surface, and
 * `policy_version` has since moved on to 1.8 (1.7 declared the PII vault, 1.8
 * declared `legacy_residue`), so the fixture version this file pins is the
 * CURRENT one and the receipts under test are steps back: the invariant under
 * test is "a bump re-consents", which holds for any bump.
 *
 * `pii_stage` was created by migration `0004_pii_stage.sql` and has been
 * PII-bearing since the moment it was written: a staged row carries the SEALED
 * preimage of a user value mid-re-homing. It was absent from the SPEC-01
 * fixture, which meant a real PII surface existed that the privacy inventory
 * did not name — the same class of defect as `history_entries` (the manifest
 * entry that was missing while five erasure sites went unreported).
 *
 * Declaring it is not a bookkeeping edit. A new declared PII surface is a
 * privacy-contract change: `policy_version` moves 1.5 → 1.6, so a SPEC-04
 * consent receipt issued under 1.5 stops validating and the user is
 * re-consented for the delta. So this file pins three things that must move
 * together:
 *
 *  1. the declaration itself, with a truthful policy per field (a PII surface
 *     that lies about retention or export is worse than an undeclared one);
 *  2. the re-consent consequence — a receipt issued under the PREVIOUS version
 *     evaluates `policy_mismatch` (NOT `tampered`: the user did nothing wrong,
 *     the policy they consented to changed) and consent is not given until they
 *     re-consent;
 *  3. the `PII_SCHEMA_VERSION` landmine this edit walks toward.
 */

import { describe, it, expect } from "vitest";
import manifestFixture from "../../../../docs/privacy/SPEC-01-manifest-fixture.json";
import {
  getEntry,
  loadManifest,
  type ManifestDocument,
} from "@/shared/lib/dataManifest";
import {
  consentErasurePlan,
  evaluateReceipt,
  issueReceipt,
  receiptDigest,
  type ConsentReceipt,
} from "@/shared/lib/consentReceipt";
import {
  PII_DOMAIN_TABLES,
  PII_ERASURE_TABLES,
  PII_LEGACY_PLAINTEXT_TABLES,
  PII_STAGE_TABLE,
} from "../../../../electron/piiDomainTables";

const doc = manifestFixture as ManifestDocument;

/** Every declared PII sqlite domain table, from the fixture. */
function declaredPiiDomainTables(): string[] {
  return doc.keys
    .filter((k) => k.surface === "sqlite_domain_tables" && k.pii)
    .map((k) => k.key)
    .sort();
}

/** A receipt from under the previous policy, with a VALID digest over it. */
async function receiptUnderPolicy(
  policyVersion: string,
  policyHash: string,
): Promise<{ receipt: ConsentReceipt; digest: string }> {
  const { receipt } = await issueReceipt(["pii_stage"], ["rehome_pii"]);
  const under = {
    ...receipt,
    policy_version: policyVersion,
    policy_hash: policyHash,
  };
  return { receipt: under, digest: await receiptDigest(under) };
}

// ---------------------------------------------------------------------------
// 1. The declaration
// ---------------------------------------------------------------------------

describe("SPEC-01: pii_stage is a declared PII sqlite domain table", () => {
  it("is registered on the sqlite_domain_tables surface as PII", () => {
    const entry = getEntry(loadManifest(doc), PII_STAGE_TABLE);
    expect(entry).toMatchObject({
      key: "pii_stage",
      surface: "sqlite_domain_tables",
      platforms: ["electron"],
      class: "user_content",
      pii: true,
      persistence: "encrypted_at_rest",
      sync: "never",
      export: "diagnostic_only",
      erasure: "erase_on_delete_all",
      legal_basis: "consent",
      owner: "demeter",
    });
    expect(entry?.retention).toEqual({ policy: "session_only", max_days: 1 });
  });

  it("declares a purpose naming what a staged row actually carries", () => {
    const purpose = getEntry(loadManifest(doc), PII_STAGE_TABLE)?.purpose ?? "";
    // The sealed preimage, and the AAD components it is bound to.
    expect(purpose).toMatch(/sealed/i);
    expect(purpose).toMatch(/preimage/i);
    expect(purpose).toMatch(/privacy_epoch/);
    // WHY it is a table and not a `storage` row — the load-bearing reason.
    expect(purpose).toMatch(/storage row|storage key/i);
    // No TTL sweeper exists; the SPEC-02 purge is the only backstop. An
    // undeclared gap is the `appdata_temp_staging` mistake, not a detail.
    expect(purpose).toMatch(/no ttl sweeper/i);
    // The raw-file-copy exposure is disclosed rather than papered over.
    expect(purpose).toMatch(/db:export/);
  });

  it("is in the withdrawal erasure plan (SPEC-04 §6.1 — legal_basis: consent)", () => {
    // A declared PII surface with `legal_basis: consent` is erased on
    // withdrawal. If the declaration lands without this, the user's consent can
    // be withdrawn and the stage row survives.
    expect(consentErasurePlan().erase).toContain(PII_STAGE_TABLE);
  });

  it("is pinned two ways to the electron constant — the list and the manifest agree", () => {
    // The Wave 0 pin is a two-way equality, so a manifest entry with no
    // constant behind it (or a constant with no manifest entry) fails here.
    expect(declaredPiiDomainTables()).toEqual([...PII_DOMAIN_TABLES].sort());
    expect([...PII_DOMAIN_TABLES]).toContain(PII_STAGE_TABLE);
  });

  it("is erased like a domain table but is NOT legacy-plaintext residue", () => {
    // Two different claims about the same table, and conflating them is a lie
    // in either direction:
    //  - erasure/snapshot/backup coverage includes it (a stage row is the
    //    user's data mid-re-homing — SPEC-02 §3 row 12);
    //  - the ADR-002 startup scan does NOT count it as legacy plaintext (a
    //    stage row is always a sealed envelope, so counting it would report
    //    every in-flight migration as plaintext residue).
    expect([...PII_ERASURE_TABLES]).toContain(PII_STAGE_TABLE);
    expect([...PII_LEGACY_PLAINTEXT_TABLES]).not.toContain(PII_STAGE_TABLE);
  });
});

// ---------------------------------------------------------------------------
// 2. The re-consent consequence — SPEC-04 §6
// ---------------------------------------------------------------------------

describe("SPEC-04: policy_version 1.8 re-consents a 1.6 receipt", () => {
  it("is 1.8, so 1.6 receipts no longer carry over", () => {
    expect(doc.policy_version).toBe("1.8");
  });

  it("a validly-digested 1.6 receipt evaluates policy_mismatch, not tampered", async () => {
    // The distinction is the whole point: `tampered` means the app cannot trust
    // the record and the user is asked to re-consent by an integrity failure.
    // `policy_mismatch` means the record is intact and the POLICY they
    // consented to changed — re-consent for the delta, old receipt kept as
    // history (SPEC-04 §6). Conflating the two would report a policy change as
    // tampering, and a tamper as a policy change.
    const { receipt, digest } = await receiptUnderPolicy(
      "1.6",
      `sha256:${"0".repeat(64)}`,
    );
    const evaluation = await evaluateReceipt({ receipt, digest });
    expect(evaluation.status).toBe("policy_mismatch");
    expect(evaluation.consentGiven).toBe(false);
    // Retained for the delta UI — the old receipt is history, not rubbish.
    expect(evaluation.receipt?.policy_version).toBe("1.6");
    expect(evaluation.currentPolicyVersion).toBe("1.8");
  });

  it("the version alone drives it, and the hash alone drives it (two-sided binding)", async () => {
    // A real 1.6 receipt would carry BOTH a 1.6 version and a different policy
    // hash. Either difference is sufficient on its own, so neither half of the
    // binding can be quietly dropped.
    const fresh = await issueReceipt(["pii_stage"], ["rehome_pii"]);
    const versionOnly = {
      receipt: { ...fresh.receipt, policy_version: "1.6" },
      digest: await receiptDigest({ ...fresh.receipt, policy_version: "1.6" }),
    };
    expect((await evaluateReceipt(versionOnly)).status).toBe("policy_mismatch");

    const hashOnly = {
      receipt: { ...fresh.receipt, policy_hash: `sha256:${"0".repeat(64)}` },
      digest: await receiptDigest({
        ...fresh.receipt,
        policy_hash: `sha256:${"0".repeat(64)}`,
      }),
    };
    expect((await evaluateReceipt(hashOnly)).status).toBe("policy_mismatch");
  });

  it("a receipt issued under 1.8 validates, so re-consent is reachable", async () => {
    // Without this, the mismatch tests above would be satisfied by a broken
    // gate that refuses every receipt: the re-consent path has to actually work.
    const { receipt, digest } = await issueReceipt(
      ["pii_stage"],
      ["rehome_pii"],
    );
    const evaluation = await evaluateReceipt({ receipt, digest });
    expect(evaluation.status).toBe("valid");
    expect(evaluation.consentGiven).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. The PII_SCHEMA_VERSION landmine (ADR-001 §3.1 slot 4, §3.3)
// ---------------------------------------------------------------------------

describe("ADR-001: PII_SCHEMA_VERSION stays truthful against the manifest", () => {
  /**
   * `electron/cryptoCapability.ts:49-64` pins the AAD's `S` to the CONSTANT
   * `PII_SCHEMA_VERSION = 1` and says so: the trusted source for `S` is the
   * per-key `version` in this manifest, but the main process cannot reach the
   * fixture, so the value is mirrored by hand and the constant is "only as
   * trusted as the review that pins it".
   *
   * Today the constant is harmless: the manifest `version` is not read by
   * anything, so bumping it changes nothing. The landmine is the day that
   * changes. When `S` becomes a per-key manifest lookup, a `version` bump on any
   * PII at-rest entry re-labels `S` for that key and every envelope already
   * sealed under the old value fails GCM authentication — the user's data is
   * still on disk and is now unreadable. This manifest edit is the first place
   * the habit starts (a new entry, a `version` field to fill in), so it is where
   * the warning is written, and this test is the tripwire.
   *
   * Tracked as ADR-001 §3.3 `TODO(hermes)`; NOT fixed here.
   */
  it("no PII at-rest entry has moved off schema version 1", () => {
    const atRest = doc.keys.filter(
      (k) => k.pii && k.persistence === "encrypted_at_rest",
    );
    // Non-vacuous: the invariant is only meaningful while the set is non-empty.
    expect(atRest.length).toBeGreaterThan(0);
    const drifted = atRest
      .filter((k) => Number(k.version.split(".")[0]) !== 1)
      .map((k) => `${k.key}@${k.version}`);
    expect(
      drifted,
      "PII_SCHEMA_VERSION is a constant, not a per-key lookup: bumping a PII key's manifest version strands every existing envelope for that key. Land `TODO(hermes)` (ADR-001 §3.3) — the per-key lookup — first.",
    ).toEqual([]);
  });

  it("pii_stage is declared at 1.0, the value the constant is pinned to", () => {
    expect(getEntry(loadManifest(doc), PII_STAGE_TABLE)?.version).toBe("1.0");
  });

  it("the pii_stage purpose carries the warning, so it cannot be dropped silently", () => {
    const purpose = getEntry(loadManifest(doc), PII_STAGE_TABLE)?.purpose ?? "";
    expect(purpose).toMatch(/do not bump/i);
    expect(purpose).toMatch(/PII_SCHEMA_VERSION/);
  });
});
