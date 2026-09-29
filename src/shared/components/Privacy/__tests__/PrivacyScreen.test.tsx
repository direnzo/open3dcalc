import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enUS from "@/shared/i18n/locales/en-US.json";
import ptBR from "@/shared/i18n/locales/pt-BR.json";
import i18n from "@/shared/i18n/i18n";
import { useLegacyKeepReadOnlyStore } from "@/shared/stores/legacyKeepReadOnlyStore";
import { PrivacyScreen } from "../PrivacyScreen";

// ---------------------------------------------------------------------------
// D1.1 S4 — privacy screen: presents the quarantine state (metadata only)
// and the two explicit exits (migrate / eliminate — ADR-002 §2.2.3/§2.2.4).
// ---------------------------------------------------------------------------

const hoisted = vi.hoisted(() => ({
  quarantineReport: vi.fn(),
  migrateKey: vi.fn(),
  eliminateKey: vi.fn(),
  evaluateReceipt: vi.fn(),
  // `t` is the IDENTITY by default, because the specs above pin i18n KEYS and
  // a resolving `t` would rename every assertion in them. The SPEC-04 spec at
  // the bottom flips this to the real i18next instance, which is the only way
  // to see what a wrong namespace prefix does: it renders the key itself.
  tMode: "identity" as "identity" | "real",
}));

vi.mock("@/shared/lib/consentReceipt", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@/shared/lib/consentReceipt")>();
  return { ...actual, evaluateReceipt: hoisted.evaluateReceipt };
});

vi.mock("react-i18next", () => {
  const identity = (key: string, opts?: Record<string, unknown>) => {
    if (opts && "key" in opts) return `${key}:${String(opts.key)}`;
    if (opts && "count" in opts) return `${key}:${String(opts.count)}`;
    return key;
  };
  // One stable `t`, not one per render: `loadReport` is a `useCallback` over
  // `t`, so a fresh function every render would re-fire the report effect on
  // every commit and the specs above would see six loads instead of one.
  const t = (key: string, opts?: Record<string, unknown>): string =>
    hoisted.tMode === "real" ? i18n.t(key, opts) : identity(key, opts);
  return {
    useTranslation: () => ({ t }),
    // `@/shared/i18n/i18n` calls `.use(initReactI18next)` at import time and the
    // SPEC-04 spec reads real copy off that instance. `useTranslation` is
    // mocked, so the plugin has nothing left to wire up.
    initReactI18next: { type: "3rdParty", init: () => undefined },
  };
});

const baseReport = {
  scannedAt: new Date().toISOString(),
  entries: [
    { key: "open3dcalc_quotes_v1", status: "quarantined", recordCount: 3 },
    { key: "open3dcalc_settings_v2", status: "non_pii" },
  ],
  quarantinedKeys: ["open3dcalc_quotes_v1"],
};

function stubElectronApi(): void {
  vi.stubGlobal("electronAPI", {
    privacy: {
      quarantineReport: hoisted.quarantineReport,
      migrateKey: hoisted.migrateKey,
      eliminateKey: hoisted.eliminateKey,
    },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  hoisted.tMode = "identity";
  hoisted.evaluateReceipt.mockResolvedValue({
    status: "absent",
    consentGiven: false,
    currentPolicyHash: "sha256:synthetic",
    currentPolicyVersion: "2026.09",
  });
  hoisted.quarantineReport.mockResolvedValue(baseReport);
  hoisted.migrateKey.mockResolvedValue({
    key: "open3dcalc_quotes_v1",
    migrated: true,
    verified: true,
  });
  hoisted.eliminateKey.mockResolvedValue({
    key: "open3dcalc_quotes_v1",
    eliminated: true,
  });
});

describe("PrivacyScreen (D1.1 S4)", () => {
  it("renders quarantined keys with record counts and both exits", async () => {
    stubElectronApi();
    render(<PrivacyScreen />);
    await waitFor(() =>
      expect(
        screen.getAllByText(/quarantined|Quarantined/).length,
      ).toBeGreaterThan(0),
    );
    expect(
      screen.getByText(/privacy.quarantine.records:3/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "privacy.quarantine.migrate" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "privacy.quarantine.eliminate" }),
    ).toBeInTheDocument();
  });

  it("migrate calls the IPC and refreshes the report", async () => {
    stubElectronApi();
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<PrivacyScreen />);
    await waitFor(() =>
      expect(hoisted.quarantineReport).toHaveBeenCalledTimes(1),
    );
    await user.click(
      screen.getByRole("button", { name: "privacy.quarantine.migrate" }),
    );
    await waitFor(() => expect(hoisted.migrateKey).toHaveBeenCalled());
    await waitFor(() =>
      expect(hoisted.quarantineReport).toHaveBeenCalledTimes(2),
    );
  });

  it("eliminate calls the IPC with the quarantined key", async () => {
    stubElectronApi();
    const user = userEvent.setup();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<PrivacyScreen />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "privacy.quarantine.eliminate" }),
      ),
    );
    await user.click(
      screen.getByRole("button", { name: "privacy.quarantine.eliminate" }),
    );
    await waitFor(() =>
      expect(hoisted.eliminateKey).toHaveBeenCalledWith("open3dcalc_quotes_v1"),
    );
  });

  it("never renders quarantined values — metadata only", async () => {
    stubElectronApi();
    render(<PrivacyScreen />);
    await waitFor(() =>
      expect(
        screen.getAllByText(/open3dcalc_quotes_v1/).length,
      ).toBeGreaterThan(0),
    );
    expect(screen.queryByText(/Fernanda/)).not.toBeInTheDocument();
  });

  it("shows the desktop-only notice on web (no electronAPI)", () => {
    render(<PrivacyScreen />);
    expect(
      screen.getByText("privacy.quarantine.desktopOnly"),
    ).toBeInTheDocument();
    expect(hoisted.quarantineReport).not.toHaveBeenCalled();
  });

  it("discloses the legacy residue panel on web (no electronAPI)", () => {
    render(<PrivacyScreen />);
    expect(
      screen.getByRole("region", { name: "privacy.residue.title" }),
    ).toBeInTheDocument();
  });

  it("discloses the legacy residue panel on desktop too", async () => {
    stubElectronApi();
    render(<PrivacyScreen />);
    await waitFor(() =>
      expect(hoisted.quarantineReport).toHaveBeenCalledTimes(1),
    );
    expect(
      screen.getByRole("region", { name: "privacy.residue.title" }),
    ).toBeInTheDocument();
  });
});

/**
 * L-2 — the way back to the legacy-migration choice. When a keep-read-only
 * decision is stored the screen must disclose it and offer to reopen the
 * choice, because the prompt no longer asks while the residue is unchanged.
 */
describe("PrivacyScreen (L-2) — reopen the keep-read-only choice", () => {
  afterEach(() => {
    useLegacyKeepReadOnlyStore.setState({ signature: null });
  });

  it("offers a way back to the choice when a decision is stored", () => {
    useLegacyKeepReadOnlyStore.setState({
      signature: "open3dcalc_customers_v1=1",
    });
    render(<PrivacyScreen />);

    expect(
      screen.getByText("privacy.migration.keepReadOnlyTitle"),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: "privacy.migration.keepReadOnlyReopen",
      }),
    );

    expect(useLegacyKeepReadOnlyStore.getState().signature).toBeNull();
    expect(
      screen.queryByRole("button", {
        name: "privacy.migration.keepReadOnlyReopen",
      }),
    ).toBeNull();
  });

  it("renders no control when no decision is stored", () => {
    render(<PrivacyScreen />);
    expect(
      screen.queryByRole("button", {
        name: "privacy.migration.keepReadOnlyReopen",
      }),
    ).toBeNull();
  });
});

/**
 * D1.1 S8 / SPEC-04 — the consent receipt block is TRANSLATED, not keyed.
 *
 * The defect this pins is not a missing key. Every string the block needs is
 * present and fully written in both locales — under `privacy.consent_receipt.*`
 * — while the call sites asked `privacy.consent.*` for six of them, which
 * resolves to nothing and renders the raw key ("privacy.consent.absent") in
 * the user's face. `privacy.consent.*` is a DIFFERENT, real namespace: the
 * ConsentModal heading, so repointing the block there would have kept showing
 * a key. The assertion is therefore made against the real i18next resources,
 * because a key-echoing `t` (what the specs above use) cannot tell a resolved
 * string from an unresolved one.
 */
describe("PrivacyScreen (SPEC-04) — the consent receipt block resolves real copy", () => {
  const LOCALES = [
    ["pt-BR", ptBR],
    ["en-US", enUS],
  ] as const;

  afterEach(async () => {
    await i18n.changeLanguage("pt-BR");
    hoisted.tMode = "identity";
  });

  const VERSION = "2026.09";

  /**
   * Render with the real resolver in `locale` and wait for the receipt.
   *
   * The receipt is evaluated in a deferred microtask, and until it lands the
   * block shows "…" — which would make every assertion below vacuous. So the
   * wait is on the branch copy itself, not on the heading, which renders
   * before the receipt exists.
   */
  async function renderIn(
    locale: "pt-BR" | "en-US",
    branch: "absent" | "granted",
  ): Promise<{ container: HTMLElement }> {
    stubElectronApi();
    await i18n.changeLanguage(locale);
    hoisted.tMode = "real";
    const view = render(<PrivacyScreen />);
    const dict = locale === "pt-BR" ? ptBR : enUS;
    const receipt = dict.privacy.consent_receipt;
    await waitFor(() =>
      expect(
        screen.getByText(
          branch === "absent"
            ? receipt.absent
            : receipt.granted.replace("{{version}}", VERSION),
        ),
      ).toBeInTheDocument(),
    );
    return view;
  }

  it.each(LOCALES)(
    "renders the default-deny branch as translated text in %s",
    async (locale, dict) => {
      await renderIn(locale, "absent");

      const receipt = dict.privacy.consent_receipt;
      expect(
        screen.getByRole("heading", { name: receipt.title }),
      ).toBeInTheDocument();
      expect(screen.getByText(receipt.absent)).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: receipt.grant }),
      ).toBeInTheDocument();
      expect(screen.getByText(receipt.flagsNote)).toBeInTheDocument();
    },
  );

  it.each(LOCALES)(
    "renders the active-receipt branch as translated text in %s",
    async (locale, dict) => {
      hoisted.evaluateReceipt.mockResolvedValue({
        status: "valid",
        consentGiven: true,
        currentPolicyHash: "sha256:synthetic",
        currentPolicyVersion: VERSION,
      });
      const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
      const user = userEvent.setup();
      await renderIn(locale, "granted");

      const receipt = dict.privacy.consent_receipt;
      expect(
        screen.getByRole("heading", { name: receipt.title }),
      ).toBeInTheDocument();
      // Interpolated on the version, so the resolved string — not the template.
      expect(
        screen.getByText(receipt.granted.replace("{{version}}", VERSION)),
      ).toBeInTheDocument();
      const withdraw = screen.getByRole("button", { name: receipt.withdraw });
      expect(withdraw).toBeInTheDocument();

      await user.click(withdraw);
      // The withdrawal prompt is copy too, and it is the one a user is most
      // likely to read before acting on it.
      expect(confirm).toHaveBeenCalledWith(receipt.withdrawConfirm);
    },
  );

  it.each(LOCALES)(
    "leaves no unresolved privacy.consent.* key on screen in %s",
    async (locale, dict) => {
      const { container } = await renderIn(locale, "absent");

      // The six that were wrong, plus the title: none of them may survive as a
      // literal key now that the block reads `privacy.consent_receipt.*`.
      for (const key of [
        "absent",
        "flagsNote",
        "grant",
        "granted",
        "withdraw",
        "withdrawConfirm",
        "title",
      ]) {
        expect(
          container.textContent,
          `privacy.consent.${key} is rendered raw in ${locale}`,
        ).not.toContain(`privacy.consent.${key}`);
      }
      // And the block is not reading the ConsentModal namespace either.
      expect(container.textContent).not.toContain(dict.privacy.consent.title);
    },
  );
});
