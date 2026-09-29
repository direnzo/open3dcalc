import { beforeEach, describe, expect, it } from "vitest";
import {
  MIGRATION_CONSENT_PURPOSES,
  MIGRATION_CONSENT_SCOPE,
  useConsentStore,
} from "../consentStore";
import { RECEIPT_VERSION } from "@/shared/lib/consentReceipt";

/**
 * T5.1 — the migration grant is a SEPARATE consent from the first-run one.
 *
 * These specs pin three things: the migration grant issues its own verified
 * receipt (own scope/purpose/version), it is queryable and withdrawable on its
 * own, and neither direction of the pair interferes with the other.
 */

describe("useConsentStore — migration consent (T5.1)", () => {
  beforeEach(() => {
    localStorage.clear();
    useConsentStore.setState({
      privacyBannerDismissed: false,
      consentGiven: false,
      consentDate: null,
      receipt: null,
      receiptDigest: null,
      withdrawnReceipts: [],
      migrationConsentGiven: false,
      migrationConsentDate: null,
      migrationReceipt: null,
      migrationReceiptDigest: null,
      withdrawnMigrationReceipts: [],
    });
  });

  // ── Initial state ──────────────────────────────────────────────
  it("initial state has no migration grant and requires consent", () => {
    const state = useConsentStore.getState();
    expect(state.migrationConsentGiven).toBe(false);
    expect(state.migrationConsentDate).toBeNull();
    expect(state.migrationReceipt).toBeNull();
    expect(state.migrationReceiptDigest).toBeNull();
    expect(state.withdrawnMigrationReceipts).toEqual([]);
    expect(state.needsMigrationConsent()).toBe(true);
  });

  // ── Grant ──────────────────────────────────────────────────────
  it("grantMigrationConsent() issues a verified, migration-scoped receipt", async () => {
    const before = Date.now();
    await useConsentStore.getState().grantMigrationConsent();
    const after = Date.now();
    const state = useConsentStore.getState();

    expect(state.migrationConsentGiven).toBe(true);
    expect(state.migrationConsentDate).not.toBeNull();
    expect(state.migrationConsentDate!).toBeGreaterThanOrEqual(before);
    expect(state.migrationConsentDate!).toBeLessThanOrEqual(after);
    expect(state.migrationReceipt).not.toBeNull();
    expect(state.migrationReceiptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);

    // Own scope / purpose / version — never the first-run ones.
    expect(state.migrationReceipt!.scope).toEqual(MIGRATION_CONSENT_SCOPE);
    expect(state.migrationReceipt!.purposes).toEqual(
      MIGRATION_CONSENT_PURPOSES,
    );
    expect(state.migrationReceipt!.receipt_version).toBe(RECEIPT_VERSION);
    expect(state.migrationReceipt!.legal_basis).toBe("consent");
    expect(state.migrationReceipt!.withdrawn_at).toBeNull();
  });

  it("querying via needsMigrationConsent() reflects the grant", async () => {
    expect(useConsentStore.getState().needsMigrationConsent()).toBe(true);
    await useConsentStore.getState().grantMigrationConsent();
    expect(useConsentStore.getState().needsMigrationConsent()).toBe(false);
  });

  // ── Withdrawal ─────────────────────────────────────────────────
  it("withdrawMigrationConsent() annotates and keeps the receipt as audit", async () => {
    await useConsentStore.getState().grantMigrationConsent();
    const granted = useConsentStore.getState().migrationReceipt!;
    await useConsentStore.getState().withdrawMigrationConsent();

    const state = useConsentStore.getState();
    expect(state.migrationConsentGiven).toBe(false);
    expect(state.migrationConsentDate).toBeNull();
    expect(state.migrationReceipt).toBeNull();
    expect(state.migrationReceiptDigest).toBeNull();
    expect(state.needsMigrationConsent()).toBe(true);
    expect(state.withdrawnMigrationReceipts).toHaveLength(1);
    expect(state.withdrawnMigrationReceipts[0].receipt_id).toBe(
      granted.receipt_id,
    );
    expect(state.withdrawnMigrationReceipts[0].withdrawn_at).not.toBeNull();
  });

  it("withdrawMigrationConsent() is a no-op when nothing was granted", async () => {
    await useConsentStore.getState().withdrawMigrationConsent();
    expect(useConsentStore.getState().withdrawnMigrationReceipts).toEqual([]);
  });

  // ── Non-interference ───────────────────────────────────────────
  it("granting migration consent never touches the first-run consent", async () => {
    await useConsentStore.getState().grantMigrationConsent();

    const state = useConsentStore.getState();
    expect(state.consentGiven).toBe(false);
    expect(state.consentDate).toBeNull();
    expect(state.receipt).toBeNull();
    expect(state.receiptDigest).toBeNull();
    expect(state.privacyBannerDismissed).toBe(false);
    expect(state.needsConsent()).toBe(true);
  });

  it("first-run giveConsent() never touches the migration consent", async () => {
    await useConsentStore.getState().giveConsent();

    const state = useConsentStore.getState();
    expect(state.consentGiven).toBe(true);
    expect(state.migrationConsentGiven).toBe(false);
    expect(state.migrationReceipt).toBeNull();
    expect(state.migrationReceiptDigest).toBeNull();
    expect(state.needsMigrationConsent()).toBe(true);
  });

  it("withdrawing migration consent leaves the first-run grant intact", async () => {
    await useConsentStore.getState().giveConsent();
    const firstRunReceipt = useConsentStore.getState().receipt;
    await useConsentStore.getState().grantMigrationConsent();
    await useConsentStore.getState().withdrawMigrationConsent();

    const state = useConsentStore.getState();
    expect(state.consentGiven).toBe(true);
    expect(state.receipt).toEqual(firstRunReceipt);
    expect(state.migrationConsentGiven).toBe(false);
    expect(state.migrationReceipt).toBeNull();
  });

  // ── Reset ──────────────────────────────────────────────────────
  it("resetMigrationConsent() resets only the migration grant", async () => {
    await useConsentStore.getState().giveConsent();
    await useConsentStore.getState().grantMigrationConsent();
    useConsentStore.getState().resetMigrationConsent();

    const state = useConsentStore.getState();
    expect(state.migrationConsentGiven).toBe(false);
    expect(state.migrationConsentDate).toBeNull();
    expect(state.migrationReceipt).toBeNull();
    // First-run grant is untouched.
    expect(state.consentGiven).toBe(true);
    expect(state.receipt).not.toBeNull();
  });

  // ── Persistence ────────────────────────────────────────────────
  it("persists the migration grant and never persists a passphrase", async () => {
    await useConsentStore.getState().grantMigrationConsent();

    const stored = localStorage.getItem("open3dcalc_consent_v1");
    expect(stored).not.toBeNull();
    const parsed = JSON.parse(stored!) as {
      state: {
        migrationConsentGiven: boolean;
        migrationConsentDate: number | null;
        migrationReceipt: { purposes: string[] } | null;
      };
    };
    expect(parsed.state.migrationConsentGiven).toBe(true);
    expect(parsed.state.migrationConsentDate).toBeTypeOf("number");
    expect(parsed.state.migrationReceipt?.purposes).toEqual(
      MIGRATION_CONSENT_PURPOSES,
    );
    expect(stored).not.toMatch(/passphrase/i);
  });
});
