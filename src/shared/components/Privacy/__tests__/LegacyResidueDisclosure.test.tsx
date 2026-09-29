import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import type { LegacyPiiDisclosure } from "@/shared/lib/migration/legacyPiiDisclosure";
import { LEGACY_PII_REHOME_MARKER_KEY } from "@/shared/lib/migration/legacyPiiRehome";
import { MIGRATION_MARKER_KEY } from "@/shared/lib/migration/marker";

/**
 * T5.3 — the legacy-residue disclosure panel.
 *
 * The panel must be HONEST and VALUE-FREE: it names the residue keys and their
 * counts, states the vault access state, and states the re-home / marker state.
 * It must never render a record value nor a marker value. This suite pins the
 * accessibility contract (a labelled region) and the value-free render.
 */

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) =>
      opts ? `${key} ${JSON.stringify(opts)}` : key,
  }),
}));

import { LegacyResidueDisclosure } from "../LegacyResidueDisclosure";

const CUSTOMERS = "open3dcalc_customers_v1";
const QUOTES = "open3dcalc_quotes_v1";
const HISTORY = "open3dcalc_history_v2";

function disclosure(
  overrides: Partial<LegacyPiiDisclosure> = {},
): LegacyPiiDisclosure {
  return {
    residue: {
      present: true,
      total: 3,
      keys: [
        { key: CUSTOMERS, present: true, count: 2 },
        { key: QUOTES, present: true, count: 1 },
        { key: HISTORY, present: false, count: 0 },
      ],
    },
    vault: { status: "locked", reason: "profile_locked" },
    rehome: {
      state: "pending",
      completed: false,
      markerKey: LEGACY_PII_REHOME_MARKER_KEY,
    },
    historyMarker: { state: "absent", markerKey: MIGRATION_MARKER_KEY },
    ...overrides,
  };
}

function renderPanel(value: LegacyPiiDisclosure) {
  return render(<LegacyResidueDisclosure disclosure={value} />);
}

describe("LegacyResidueDisclosure — a11y", () => {
  it("renders a labelled region", () => {
    renderPanel(disclosure());
    expect(
      screen.getByRole("region", { name: "privacy.residue.title" }),
    ).toBeInTheDocument();
  });

  it("announces state changes politely", () => {
    renderPanel(disclosure());
    expect(
      screen.getByRole("region", { name: "privacy.residue.title" }),
    ).toHaveAttribute("aria-live", "polite");
  });
});

describe("LegacyResidueDisclosure — residue (value-free)", () => {
  it("names every present residue key with its count", () => {
    renderPanel(disclosure());
    expect(screen.getByText(/open3dcalc_customers_v1/)).toBeInTheDocument();
    expect(screen.getByText(/open3dcalc_quotes_v1/)).toBeInTheDocument();
    expect(
      screen.getByText(/privacy.residue.residueTotal/),
    ).toBeInTheDocument();
  });

  it("omits an absent key from the residue list", () => {
    renderPanel(disclosure());
    expect(screen.queryByText(/open3dcalc_history_v2/)).not.toBeInTheDocument();
  });

  it("renders the empty state when there is no residue", () => {
    renderPanel(
      disclosure({
        residue: {
          present: false,
          total: 0,
          keys: [
            { key: CUSTOMERS, present: false, count: 0 },
            { key: QUOTES, present: false, count: 0 },
            { key: HISTORY, present: false, count: 0 },
          ],
        },
      }),
    );
    expect(screen.getByText("privacy.residue.residueNone")).toBeInTheDocument();
    expect(
      screen.queryByText("privacy.residue.residueTotal"),
    ).not.toBeInTheDocument();
  });
});

describe("LegacyResidueDisclosure — vault state", () => {
  it.each([
    [{ status: "hydrated" } as const, "privacy.residue.vaultHydrated"],
    [
      { status: "locked", reason: "profile_locked" } as const,
      "privacy.residue.vaultLocked",
    ],
    [
      { status: "unavailable", reason: "indexeddb_unavailable" } as const,
      "privacy.residue.vaultUnavailable",
    ],
  ])("states the vault as %o (%#)", (vault, label) => {
    renderPanel(disclosure({ vault }));
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("shows the typed reason when the vault is unavailable", () => {
    renderPanel(
      disclosure({
        vault: { status: "unavailable", reason: "insecure_context" },
      }),
    );
    expect(
      screen.getByText(/privacy.residue.vaultUnavailableDetail/),
    ).toBeInTheDocument();
    expect(screen.getByText(/insecure_context/)).toBeInTheDocument();
  });
});

describe("LegacyResidueDisclosure — re-home / marker state", () => {
  it.each([
    ["migrated", "privacy.residue.rehomeMigrated"],
    ["pending", "privacy.residue.rehomePending"],
    ["incomplete", "privacy.residue.rehomeIncomplete"],
  ] as const)("states the re-home as %s", (state, label) => {
    renderPanel(
      disclosure({
        rehome: {
          state,
          completed: state === "migrated",
          markerKey: LEGACY_PII_REHOME_MARKER_KEY,
        },
      }),
    );
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it.each([
    ["absent", "privacy.residue.historyAbsent"],
    ["complete", "privacy.residue.historyComplete"],
    ["resumable", "privacy.residue.historyResumable"],
  ] as const)("states the history marker as %s", (state, label) => {
    renderPanel(
      disclosure({ historyMarker: { state, markerKey: MIGRATION_MARKER_KEY } }),
    );
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("exposes the marker key NAMES, never their values", () => {
    renderPanel(disclosure());
    expect(
      screen.getByText(new RegExp(LEGACY_PII_REHOME_MARKER_KEY)),
    ).toBeInTheDocument();
    expect(
      screen.getByText(new RegExp(MIGRATION_MARKER_KEY)),
    ).toBeInTheDocument();
  });
});

describe("LegacyResidueDisclosure — drift (T4.6, value-free)", () => {
  it("renders no drift warning when there is no drift", () => {
    renderPanel(disclosure());
    expect(
      screen.queryByText(/privacy\.residue\.driftHeading/),
    ).not.toBeInTheDocument();
  });

  it("renders the honest drift warning when the source changed", () => {
    renderPanel(
      disclosure({
        drift: { detected: true, sources: ["open3dcalc_history_v2"] },
      }),
    );
    expect(
      screen.getByText(/privacy\.residue\.driftHeading/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/privacy\.residue\.driftWarning/),
    ).toBeInTheDocument();
  });

  it("names the changed KEY, never a value", () => {
    renderPanel(
      disclosure({
        drift: { detected: true, sources: ["open3dcalc_products"] },
      }),
    );
    expect(screen.getByText(/open3dcalc_products/)).toBeInTheDocument();
  });
});

describe("LegacyResidueDisclosure — default derivation", () => {
  it("derives its own disclosure when none is injected", () => {
    // No throw and a labelled region: the default path installs the capability
    // snapshot and reads through the gate without a DOM-backed vault.
    render(<LegacyResidueDisclosure />);
    expect(
      screen.getByRole("region", { name: "privacy.residue.title" }),
    ).toBeInTheDocument();
  });
});
