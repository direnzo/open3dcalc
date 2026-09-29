/**
 * H-4 — the visible consumer of `getLastPiiWriteRefusal()`.
 *
 * The gate records a refusal outside React; this component subscribes and shows
 * it the instant it happens, so a refused PII write is impossible to miss. The
 * specs pin: it renders nothing when idle, names the affected data area and the
 * typed reason when a real refusal exists, filters to its own store, and
 * ignores the deliberate `demo_session` non-refusal.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen } from "@testing-library/react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: Record<string, unknown>) =>
      options ? `${key} ${Object.values(options).join(" ")}` : key,
  }),
}));

import { PiiWriteRefusalNotice } from "../PiiWriteRefusalNotice";
import {
  PII_STORE_KEY,
  recordPiiWriteRefusal,
  resetPiiStoreHydrationForTests,
} from "@/shared/lib/crypto/piiStoreHydration";

describe("H-4 — PiiWriteRefusalNotice", () => {
  beforeEach(() => {
    resetPiiStoreHydrationForTests();
  });

  afterEach(() => {
    resetPiiStoreHydrationForTests();
  });

  it("renders nothing while no write has been refused", () => {
    const { container } = render(
      <PiiWriteRefusalNotice storeKey={PII_STORE_KEY.customers} />,
    );

    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows the refusal, the data area and the typed reason", () => {
    recordPiiWriteRefusal(PII_STORE_KEY.customers, "profile_locked");

    render(<PiiWriteRefusalNotice storeKey={PII_STORE_KEY.customers} />);

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("privacy.vault.writeRefusedTitle");
    // The area label is resolved through the existing customers.title key.
    expect(alert).toHaveTextContent("customers.title");
    expect(alert).toHaveTextContent("profile_locked");
  });

  it("only renders a refusal that matches its own store", () => {
    recordPiiWriteRefusal(PII_STORE_KEY.customers, "profile_locked");

    const { container } = render(
      <PiiWriteRefusalNotice storeKey={PII_STORE_KEY.quotes} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("ignores a demo_session refusal — it is not a failure", () => {
    recordPiiWriteRefusal(PII_STORE_KEY.history, "demo_session");

    const { container } = render(<PiiWriteRefusalNotice />);

    expect(container).toBeEmptyDOMElement();
  });

  it("falls back to a generic area label for an unknown store key", () => {
    recordPiiWriteRefusal("open3dcalc_unknown_store", "capability_unknown");

    render(<PiiWriteRefusalNotice />);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "privacy.vault.writeRefusedAreaUnknown",
    );
  });

  it("appears as soon as a refusal arrives after mount", () => {
    render(<PiiWriteRefusalNotice storeKey={PII_STORE_KEY.customers} />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    act(() => {
      recordPiiWriteRefusal(PII_STORE_KEY.customers, "profile_locked");
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "privacy.vault.writeRefusedTitle",
    );
  });
});
