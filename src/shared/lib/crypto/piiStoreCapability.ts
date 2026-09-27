/**
 * Capability decision for the browser PII vault — ADR-001 §2.3, SPEC-01.
 *
 * Pure and platform-agnostic, like `capability.ts` next door: the probes are
 * injected and this module decides. It is the decision function the
 * `manifestStorage` choke point composes with the existing demo-session
 * suppression predicate, so there is exactly ONE place that answers "may PII
 * be read or written right now?".
 *
 * ## Why a separate function from `resolveCryptoCapability`
 *
 * `capability.ts` answers the ADR-001 §2.3 table: safeStorage (electron) or a
 * session passphrase (both). That table is about WHICH key protects the value.
 * The vault needs two more axes that table does not carry:
 *
 *  - a **place to write**. `encrypted_at_rest` is a promise about bytes; a
 *    browser with no IndexedDB cannot keep that promise, and a refusal to
 *    write would be a silent no-op that reads as "saved". So an absent store
 *    is its own reason, distinct from an absent key.
 *  - **the user's decision**. `consent_declined` is not a capability failure;
 *    a perfectly capable browser that the user asked not to persist PII in is
 *    denied, and conflating the two would make the UI say "unsupported"
 *    instead of "you said no".
 *
 * ## Fail-closed
 *
 * An `undefined` probe resolves to DENIED, never to "probably fine". A gate
 * that treats an unknown as allowed turns a browser gap into plaintext-by-
 * accident the moment any fallback is ever added to it.
 */

export type PiiStoreDenialReason =
  /** A demo session owns the stores: ephemeral by definition (LGPD). */
  | "demo_session"
  /** No capability probe was ever installed — nothing is known. */
  | "capability_unknown"
  /** The user declined PII persistence. */
  | "consent_declined"
  /** `window.isSecureContext` is false, or was not observable. */
  | "insecure_context"
  /** Web Crypto (`crypto.subtle`) is not reachable. */
  | "web_crypto_unavailable"
  /** No IndexedDB to write sealed records into. */
  | "indexeddb_unavailable"
  /** A passphrase-derived key is not held in memory for this store. */
  | "profile_locked";

/**
 * An install-time capability SNAPSHOT. Not a live probe: these are facts about
 * the runtime that do not change while a page is alive, and re-probing per
 * read would make a vault write depend on a `getRandomValues` round trip.
 *
 * `declined` is deliberately NOT here — consent changes at runtime and is read
 * live by the choke point, so a withdrawal takes effect immediately.
 */
export interface PiiStoreEnvironment {
  secureContext: boolean | undefined;
  webCryptoAvailable: boolean | undefined;
  indexedDbAvailable: boolean | undefined;
}

export interface PiiStoreGateInput {
  /** The existing demo-session suppression predicate. */
  demoSuppressed: boolean;
  /** Installed capability snapshot, or null if none was ever installed. */
  environment: PiiStoreEnvironment | null;
  /** Live user decision. */
  declined: boolean;
  /** Whether the store currently holds no derived key. */
  locked: boolean;
}

/**
 * The decision table, most fundamental refusal first.
 *
 * Order is load-bearing and asserted by a test: "you cannot write here at all"
 * outranks "you are locked out right now", and the locked state is last
 * because it is the only one the user can fix by unlocking. Masking an
 * insecure context behind `profile_locked` would send the user to type a
 * passphrase that could never help.
 */
export function resolvePiiStoreRefusal(
  input: PiiStoreGateInput,
): PiiStoreDenialReason | null {
  if (input.demoSuppressed) return "demo_session";
  if (input.environment === null) return "capability_unknown";
  if (input.declined) return "consent_declined";
  if (input.environment.secureContext !== true) return "insecure_context";
  if (input.environment.webCryptoAvailable !== true) {
    return "web_crypto_unavailable";
  }
  if (input.environment.indexedDbAvailable !== true) {
    return "indexeddb_unavailable";
  }
  if (input.locked) return "profile_locked";
  return null;
}
