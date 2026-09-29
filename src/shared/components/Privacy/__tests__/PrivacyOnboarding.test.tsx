import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";

/**
 * T5.2 — first-use privacy surface. On first run (no receipt-backed consent)
 * the ConsentModal is what the user must answer; the dismissible PrivacyBanner
 * must NOT also render, or the same notice appears twice at once. Once consent
 * exists, the banner is the surface.
 */

const consentState = { consentGiven: false };

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock("@/shared/stores/consentStore", () => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  useConsentStore: (selector?: any) => {
    const state = { consentGiven: consentState.consentGiven };
    return selector ? selector(state) : state;
  },
}));

vi.mock("@/shared/components/ui/ConsentModal", () => ({
  ConsentModal: ({ open }: { open: boolean }) =>
    open ? <div data-testid="consent-modal" /> : null,
}));

vi.mock("@/shared/components/ui/PrivacyBanner", () => ({
  PrivacyBanner: () => <div data-testid="privacy-banner" />,
}));

import { PrivacyOnboarding } from "../PrivacyOnboarding";

beforeEach(() => {
  consentState.consentGiven = false;
});

describe("PrivacyOnboarding", () => {
  it("shows the first-use consent modal instead of the banner", () => {
    render(<PrivacyOnboarding />);
    expect(screen.getByTestId("consent-modal")).toBeInTheDocument();
    expect(screen.queryByTestId("privacy-banner")).toBeNull();
  });

  it("shows the banner and not the consent modal once consent exists", () => {
    consentState.consentGiven = true;
    render(<PrivacyOnboarding />);
    expect(screen.getByTestId("privacy-banner")).toBeInTheDocument();
    expect(screen.queryByTestId("consent-modal")).toBeNull();
  });
});
