import React from "react";
import ReactDOM from "react-dom/client";
import App from "@/platform/desktop/App";
import "@/shared/i18n/i18n";
import "./index.css";
import { initPersistenceBridge } from "@/platform/desktop/overrides/persistence-bridge";
import { initTheme } from "@/platform/desktop/hooks/useTheme";
import {
  DbErrorBanner,
  StartupBridgeFailure,
} from "@/platform/desktop/components/PersistenceBridgeError/PersistenceBridgeError";

// Initialize theme BEFORE React renders to prevent flash of wrong theme.
initTheme();

// Initialize SQLite persistence bridge BEFORE React renders.
// This loads data from SQLite → localStorage so Zustand stores
// hydrate with durable data instead of stale/empty localStorage.
//
// BOTH outcomes below are terminal and neither is a blank window. The promise
// used to carry only a `.then`, so a rejection — a CryptoDeniedError on a
// quarantined PII key (ADR-002 §2.2.1), an unreadable manifest, a SQLite error
// on the first listKeys — left an empty #root with no message and no focusable
// element, and the app looked broken rather than refused. Failing closed is
// still the rule: a renderer that hydrated from stale localStorage would look
// like it worked and then lose every write. It just says so now.
initPersistenceBridge()
  .then(() => {
    ReactDOM.createRoot(document.getElementById("root")!).render(
      <React.StrictMode>
        {/* The production subscriber for the bridge's `open3dcalc:db-error`
            signal. It lives here rather than in App because the app is not
            guaranteed to mount — a bridge that works at startup and fails
            later still has to be able to say so. */}
        <DbErrorBanner />
        <App />
      </React.StrictMode>,
    );
  })
  .catch((error: unknown) => {
    ReactDOM.createRoot(document.getElementById("root")!).render(
      <React.StrictMode>
        <StartupBridgeFailure error={error} />
      </React.StrictMode>,
    );
  });
