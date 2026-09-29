/**
 * Vitest browser mode: the PII vault against a REAL browser.
 *
 * ## Why this config exists next to `vitest.config.ts`
 *
 * Every vault spec to date runs in jsdom, where `globalThis.indexedDB` does not
 * exist: the store is a test double (`src/shared/test/fakeIndexedDb.ts`) and the
 * capability sampler has to be handed `PII_STORE_ENVIRONMENT`, because jsdom
 * reports `window.isSecureContext` as `undefined`. The cryptography was already
 * real, but the two things a public beta actually depends on were unproven in
 * the runtime that ships them: the browser's own IndexedDB (transactions,
 * auto-commit, the open/upgrade handshake) and Web Crypto behind a real secure
 * origin.
 *
 * This config runs only `*.browser.test.ts` in Chromium through Playwright, with
 * NO injected environment and NO store double. `vitest.config.ts` is untouched
 * apart from excluding the same glob, so the jsdom suite keeps its own spec set
 * and neither suite can silently adopt the other's files.
 *
 * Run it with `npm run test:browser` (which passes `--config` explicitly, so the
 * default config stays the jsdom one).
 */

import { defineConfig, mergeConfig } from "vite";
import { playwright } from "@vitest/browser-playwright";
import baseConfig from "./vite.base.config";

export default defineConfig(
  mergeConfig(baseConfig, {
    test: {
      // Only the browser specs. `vitest.config.ts` excludes this same glob, so a
      // file belongs to exactly one suite.
      include: ["src/**/*.browser.test.ts"],
      browser: {
        enabled: true,
        // Explicit rather than CI-derived: a headless run must never depend on
        // `process.env.CI`, or a local `npm run test:browser` would try to open
        // a window. There is no UI in these specs, only storage and crypto.
        headless: true,
        provider: playwright(),
        instances: [{ browser: "chromium" }],
        // Vitest defaults this to `true` in a non-UI run and writes a screenshot
        // into `__screenshots__/` beside the spec. These specs assert on
        // IndexedDB and ciphertext, never on pixels, so the artifact would be a
        // picture of an empty page and an untracked directory in the tree.
        screenshotFailures: false,
      },
    },
  }),
);
