/**
 * Shared fixture for the PII vault tests.
 *
 * The vault SAMPLES its environment from the browser (`window.isSecureContext`,
 * `globalThis.crypto.subtle`, `globalThis.indexedDB`) and that sampler is
 * tested on its own in `piiStoreCapability`/store tests. Every other test
 * needs a fully capable environment, and jsdom reports `isSecureContext` as
 * `undefined` — which the gate correctly treats as a denial. Pinning the
 * capable baseline here keeps each test about the one thing it is proving.
 */

import type { PiiStoreEnvironment } from "@/shared/lib/crypto/piiStoreCapability";

/** A browser, secure context, Web Crypto present, IndexedDB reachable. */
export const PII_STORE_ENVIRONMENT: PiiStoreEnvironment = {
  browser: true,
  secureContext: true,
  webCryptoAvailable: true,
  indexedDbAvailable: true,
};
