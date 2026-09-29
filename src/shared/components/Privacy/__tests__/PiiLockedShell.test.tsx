/**
 * T3.3 — the locked shell and its minimal unlock.
 *
 * The shell is the honest face of a vault the app cannot open: it renders when
 * the environment is incapable, when the vault is locked, or when an unlock
 * FAILED — never a blank window, and never an empty customer list mistaken for
 * lost data. These specs drive the REAL gate (real Web Crypto, fake IndexedDB)
 * so the assertion is about the wiring, not about a mock of it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

import "@/shared/stores/customerStore";
import "@/shared/stores/quoteStore";
import "@/shared/stores/historyStore";

import { PiiLockedShell } from "../PiiLockedShell";
import {
  configurePiiStoreRuntime,
  getPiiStoreAccessState,
  resetPiiStoreHydrationForTests,
  unlockPiiStoresAndRehydrate,
} from "@/shared/lib/crypto/piiStoreHydration";
import {
  createPiiStore,
  lockAllPiiStores,
  resetPiiStoreRuntimeForTests,
} from "@/shared/lib/crypto/piiStore";
import {
  resetPiiStoreGateForTests,
  setDemoSuppressedForPiiGate,
} from "@/shared/lib/crypto/piiStoreCapability";
import { zeroizeSessionPassphrase } from "@/shared/lib/crypto/passphraseSession";
import { PII_STORE_ENVIRONMENT } from "@/shared/lib/crypto/__tests__/piiStoreFixtures";
import { createFakeIndexedDb } from "@/shared/test/fakeIndexedDb";

const CUSTOMERS = "open3dcalc_customers_v1";
const PASS = "senha-sintetica-acesso-4242";
const WRONG_PASS = "senha-sintetica-errada-1717";

const LOCKED_TITLE = "privacy.vault.lockedTitle";
const UNAVAILABLE_TITLE = "privacy.vault.unavailableTitle";

function passphraseInput(): HTMLInputElement {
  return screen.getByLabelText("privacy.vault.passphraseLabel");
}

describe("T3.3 — PiiLockedShell", () => {
  const user = userEvent.setup();
  let idb: ReturnType<typeof createFakeIndexedDb>;
  let container: HTMLElement;
  const options = () => ({
    indexedDb: idb.factory,
    environment: PII_STORE_ENVIRONMENT,
  });

  function renderShell(): HTMLElement {
    container = render(<PiiLockedShell />).container;
    return container;
  }

  beforeEach(() => {
    idb = createFakeIndexedDb();
    resetPiiStoreGateForTests();
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    configurePiiStoreRuntime(options());
    window.localStorage.clear();
    zeroizeSessionPassphrase();
  });

  afterEach(() => {
    resetPiiStoreGateForTests();
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    window.localStorage.clear();
    zeroizeSessionPassphrase();
  });

  it("renders a labelled region and a form for a locked, capable vault", () => {
    renderShell();

    expect(
      screen.getByRole("region", { name: "privacy.vault.ariaLabel" }),
    ).toBeInTheDocument();
    expect(screen.getByText(LOCKED_TITLE)).toBeInTheDocument();
    expect(passphraseInput()).toHaveAttribute("type", "password");
    expect(
      screen.getByRole("button", { name: "privacy.vault.unlock" }),
    ).toBeInTheDocument();
  });

  it("moves focus to the passphrase input when it appears", () => {
    renderShell();

    expect(passphraseInput()).toHaveFocus();
  });

  it("explains an incapable environment and offers no unlock form", () => {
    resetPiiStoreGateForTests();
    configurePiiStoreRuntime({
      indexedDb: idb.factory,
      environment: { ...PII_STORE_ENVIRONMENT, webCryptoAvailable: false },
    });

    renderShell();

    expect(screen.getByText(UNAVAILABLE_TITLE)).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("stays silent for an intentional demo session", () => {
    setDemoSuppressedForPiiGate(true);

    render(<PiiLockedShell />);

    expect(screen.queryByText(LOCKED_TITLE)).not.toBeInTheDocument();
    expect(screen.queryByText(UNAVAILABLE_TITLE)).not.toBeInTheDocument();
  });

  it("renders nothing when the vault is already hydrated", async () => {
    await unlockPiiStoresAndRehydrate(PASS, options());

    const { container: rendered } = render(<PiiLockedShell />);

    expect(rendered).toBeEmptyDOMElement();
  });

  it("unlocks with the passphrase typed and Enter, rehydrating the stores", async () => {
    renderShell();

    await user.type(passphraseInput(), PASS);
    await user.keyboard("{Enter}");

    await waitFor(() => expect(container).toBeEmptyDOMElement());
    expect(getPiiStoreAccessState()).toEqual({ status: "hydrated" });
    // Memory-only: the passphrase never reaches localStorage.
    expect(window.localStorage.length).toBe(0);
  });

  it("keeps the shell up and reports a failed unlock without clearing the input safely", async () => {
    // Seed a real record so a wrong passphrase fails at unlock, then lock again.
    await unlockPiiStoresAndRehydrate(PASS, options());
    await createPiiStore(CUSTOMERS, options()).write(
      '{"state":{"customers":[]},"version":1}',
    );
    lockAllPiiStores();
    resetPiiStoreRuntimeForTests();
    resetPiiStoreHydrationForTests();
    configurePiiStoreRuntime(options());

    renderShell();
    await user.type(passphraseInput(), WRONG_PASS);
    await user.keyboard("{Enter}");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("privacy.vault.unlockError");
    expect(getPiiStoreAccessState()).toEqual({
      status: "locked",
      reason: "profile_locked",
    });
    // The failed passphrase is dropped from the field, never retained.
    expect(passphraseInput()).toHaveValue("");
  });
});
