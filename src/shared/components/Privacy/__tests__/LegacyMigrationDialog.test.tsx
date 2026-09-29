import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import type { LegacyPiiPlaintextReport } from "@/shared/lib/legacyPiiPlaintext";

/**
 * T5.2 — the legacy-migration choice dialog.
 *
 * ADR-002 §2.2.5: there is no implicit acceptance. Every exit is an explicit,
 * user-chosen action, and a refused migration must say WHY rather than look
 * like success. The delete option is destructive and is disabled unless a
 * verified key-scoped erasure exists — never a silent delete.
 */

const mockGrantMigrationConsent = vi.fn();
const mockMigrate = vi.fn();
const mockIsPiiSyncAvailable = vi.fn();
const mockDetect = vi.fn();

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock("@/shared/lib/legacyPiiPlaintext", () => ({
  detectLegacyPlaintextPii: () => mockDetect(),
}));

vi.mock("@/shared/stores/consentStore", () => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  useConsentStore: (selector?: any) => {
    const state = { grantMigrationConsent: mockGrantMigrationConsent };
    return selector ? selector(state) : state;
  },
}));

vi.mock("@/shared/lib/migration/legacyPiiRehome", () => ({
  migrateLegacyPlaintextPiiToVault: () => mockMigrate(),
}));

vi.mock("@/shared/lib/dataSync", () => ({
  isPiiSyncAvailable: () => mockIsPiiSyncAvailable(),
}));

import { LegacyMigrationDialog } from "../LegacyMigrationDialog";

const REPORT: LegacyPiiPlaintextReport = {
  present: true,
  total: 3,
  keys: [
    { key: "open3dcalc_customers_v1", present: true, count: 2 },
    { key: "open3dcalc_quotes_v1", present: true, count: 1 },
    { key: "open3dcalc_history_v2", present: false, count: 0 },
  ],
};

function renderDialog(
  overrides: Partial<React.ComponentProps<typeof LegacyMigrationDialog>> = {},
) {
  const onRequestClose = vi.fn();
  const onOpenExport = vi.fn();
  const { container } = render(
    <LegacyMigrationDialog
      open
      report={REPORT}
      onRequestClose={onRequestClose}
      onOpenExport={onOpenExport}
      {...overrides}
    />,
  );
  return { container, onRequestClose, onOpenExport };
}

beforeEach(() => {
  mockGrantMigrationConsent.mockReset();
  mockMigrate.mockReset();
  mockIsPiiSyncAvailable.mockReset();
  mockDetect.mockReset();
  mockIsPiiSyncAvailable.mockReturnValue(true);
  mockDetect.mockReturnValue(REPORT);
});

describe("LegacyMigrationDialog — structure and a11y", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <LegacyMigrationDialog
        open={false}
        report={REPORT}
        onRequestClose={vi.fn()}
        onOpenExport={vi.fn()}
      />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("exposes a labelled modal dialog disclosing how many records exist", () => {
    renderDialog();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-label", "privacy.migration.title");
    // The interpolated intro is rendered through t(); the mock returns the key.
    expect(screen.getByText("privacy.migration.intro")).toBeInTheDocument();
  });

  it("offers the five explicit choices", () => {
    renderDialog();
    for (const key of [
      "optionMigrate",
      "optionKeep",
      "optionExport",
      "optionDelete",
      "optionCancel",
    ]) {
      expect(
        screen.getByRole("button", { name: `privacy.migration.${key}` }),
      ).toBeInTheDocument();
    }
  });

  it("closes without action when cancel is chosen", () => {
    const { onRequestClose } = renderDialog();
    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionCancel" }),
    );
    expect(onRequestClose).toHaveBeenCalledTimes(1);
    expect(mockMigrate).not.toHaveBeenCalled();
  });

  it("closes on Escape", () => {
    const { onRequestClose } = renderDialog();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onRequestClose).toHaveBeenCalledTimes(1);
  });

  it("ignores non-navigation keys", () => {
    const { onRequestClose } = renderDialog();
    fireEvent.keyDown(document, { key: "a" });
    expect(onRequestClose).not.toHaveBeenCalled();
  });

  it("traps Tab, wrapping from the last control back to the first", () => {
    renderDialog();
    const first = screen.getByRole("button", {
      name: "privacy.migration.optionMigrate",
    });
    const last = screen.getByRole("button", {
      name: "privacy.migration.optionCancel",
    });

    last.focus();
    expect(document.activeElement).toBe(last);
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(first);
  });

  it("traps Shift+Tab, wrapping from the first control to the last", () => {
    renderDialog();
    const first = screen.getByRole("button", {
      name: "privacy.migration.optionMigrate",
    });
    const last = screen.getByRole("button", {
      name: "privacy.migration.optionCancel",
    });

    first.focus();
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it("defaults to live detection when no report is injected", () => {
    render(
      <LegacyMigrationDialog
        open
        onRequestClose={vi.fn()}
        onOpenExport={vi.fn()}
      />,
    );
    expect(mockDetect).toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("privacy.migration.intro")).toBeInTheDocument();
  });
});

describe("LegacyMigrationDialog — migrate", () => {
  it("grants migration consent, then re-homes, and reports success honestly", async () => {
    mockMigrate.mockResolvedValue({
      status: "migrated",
      migratedKeys: ["open3dcalc_customers_v1"],
      skippedKeys: [],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    await waitFor(() =>
      expect(mockGrantMigrationConsent).toHaveBeenCalledTimes(1),
    );
    expect(mockMigrate).toHaveBeenCalledTimes(1);
    // Consent is granted BEFORE the migration reads it.
    const consentOrder = mockGrantMigrationConsent.mock.invocationCallOrder[0];
    const migrateOrder = mockMigrate.mock.invocationCallOrder[0];
    expect(consentOrder).toBeLessThan(migrateOrder);
    expect(
      await screen.findByText("privacy.migration.resultMigrated"),
    ).toBeInTheDocument();
  });

  it("reports a locked vault as a refusal, not a success", async () => {
    mockMigrate.mockResolvedValue({
      status: "vault_unavailable",
      migratedKeys: [],
      skippedKeys: [],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    expect(
      await screen.findByText("privacy.migration.resultVaultLocked"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("privacy.migration.resultMigrated"),
    ).not.toBeInTheDocument();
  });

  it("reports an empty residue as nothing to migrate", async () => {
    mockMigrate.mockResolvedValue({
      status: "no_residue",
      migratedKeys: [],
      skippedKeys: [],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    expect(
      await screen.findByText("privacy.migration.resultNothingToMigrate"),
    ).toBeInTheDocument();
  });

  it("reports an incomplete migration without claiming success", async () => {
    mockMigrate.mockResolvedValue({
      status: "incomplete",
      migratedKeys: [],
      skippedKeys: ["open3dcalc_customers_v1"],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    expect(
      await screen.findByText("privacy.migration.resultIncomplete"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("privacy.migration.resultMigrated"),
    ).not.toBeInTheDocument();
  });

  it("treats an already-migrated vault as nothing to migrate", async () => {
    mockMigrate.mockResolvedValue({
      status: "already_migrated",
      migratedKeys: [],
      skippedKeys: [],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    expect(
      await screen.findByText("privacy.migration.resultNothingToMigrate"),
    ).toBeInTheDocument();
  });

  it("reports a consent-refused re-home as incomplete, never as success", async () => {
    mockMigrate.mockResolvedValue({
      status: "consent_required",
      migratedKeys: [],
      skippedKeys: [],
    });
    renderDialog();

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );

    expect(
      await screen.findByText("privacy.migration.resultIncomplete"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("privacy.migration.resultMigrated"),
    ).not.toBeInTheDocument();
  });
});

describe("LegacyMigrationDialog — reopen", () => {
  it("resets to a fresh question when reopened after an outcome was shown", async () => {
    mockMigrate.mockResolvedValue({
      status: "migrated",
      migratedKeys: ["open3dcalc_customers_v1"],
      skippedKeys: [],
    });
    const props = {
      report: REPORT,
      onRequestClose: vi.fn(),
      onOpenExport: vi.fn(),
    };
    const { rerender } = render(<LegacyMigrationDialog open {...props} />);

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    );
    expect(
      await screen.findByText("privacy.migration.resultMigrated"),
    ).toBeInTheDocument();

    rerender(<LegacyMigrationDialog open={false} {...props} />);
    rerender(<LegacyMigrationDialog open {...props} />);

    expect(
      screen.queryByText("privacy.migration.resultMigrated"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "privacy.migration.optionMigrate" }),
    ).toBeEnabled();
  });
});

describe("LegacyMigrationDialog — keep read-only", () => {
  it("discloses that the data stays plaintext and does not migrate", () => {
    renderDialog();
    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionKeep" }),
    );

    expect(
      screen.getByText("privacy.migration.keptReadOnly"),
    ).toBeInTheDocument();
    expect(mockMigrate).not.toHaveBeenCalled();
    expect(mockGrantMigrationConsent).not.toHaveBeenCalled();
  });
});

describe("LegacyMigrationDialog — export", () => {
  it("opens the existing export flow when the vault is available", () => {
    const { onOpenExport } = renderDialog();
    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionExport" }),
    );
    expect(onOpenExport).toHaveBeenCalledTimes(1);
  });

  it("refuses export with a message when the vault is locked", () => {
    const { onOpenExport } = renderDialog();
    mockIsPiiSyncAvailable.mockReturnValue(false);

    fireEvent.click(
      screen.getByRole("button", { name: "privacy.migration.optionExport" }),
    );

    expect(onOpenExport).not.toHaveBeenCalled();
    expect(
      screen.getByText("privacy.migration.exportBlocked"),
    ).toBeInTheDocument();
  });
});

describe("LegacyMigrationDialog — delete", () => {
  it("disables elimination and explains why, rather than deleting silently", () => {
    renderDialog();
    const remove = screen.getByRole("button", {
      name: "privacy.migration.optionDelete",
    });
    expect(remove).toBeDisabled();
    expect(
      screen.getByText("privacy.migration.deleteUnavailable"),
    ).toBeInTheDocument();
  });
});
