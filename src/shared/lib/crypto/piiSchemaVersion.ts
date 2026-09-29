/**
 * The `S` component of the at-rest AAD, shared by the Electron and browser
 * storage layers — ADR-001 §2.4, §3.3.
 *
 * ## Why this is a constant, and the landmine that comes with it
 *
 * The trusted source for `S` is the per-key `version` in the shipped SPEC-01
 * manifest. `electron/cryptoCapability.ts` cannot reach that fixture (node16
 * ESM output will not execute a static JSON import) and pins the value by
 * hand, so this module holds the shared browser-side copy of that pin. It is a
 * constant, not a lookup, and a constant is only as trusted as the review that
 * pins it.
 *
 * **A manifest `version` bump on a PII at-rest entry strands every existing
 * envelope for that key the day the lookup lands**: `S` is silently
 * re-labelled, the AES-GCM tag no longer verifies, and there is no runtime
 * signal at all — the bytes are still on disk, still intact, and the read just
 * throws. The `safeStorage` branch is unaffected (it binds no AAD, ADR-001
 * §3.4), which is what makes this so easy to miss in a desktop test profile.
 *
 * Tracked as ADR-001 §3.3 `TODO(hermes)`. Land the per-key lookup FIRST, while
 * every PII at-rest entry is still at major version 1; only then allow a
 * `version` bump. Pinned by
 * `src/shared/lib/__tests__/piiVaultDeclaration.test.ts`, which fails on drift
 * in either direction.
 */

/**
 * Schema version of the protected PII value. Mirrors
 * `electron/cryptoCapability.ts`'s pinned `PII_SCHEMA_VERSION`; the two are
 * asserted equal by test because neither can import the other today.
 */
export const PII_SCHEMA_VERSION = 1;
