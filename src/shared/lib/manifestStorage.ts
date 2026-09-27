/**
 * SPEC-01 gated storage wiring (D1.1 S1).
 *
 * Two narrow choke points that connect the manifest loader to the stores
 * WITHOUT changing store behavior:
 *
 * 1. `manifestStorage()` — a zustand `StateStorage` wrapper around
 *    `localStorage` that runs `checkKey(name)` before every get/set/remove.
 *    Drop-in for the default `persist` storage: same sync semantics, same
 *    JSON handling (delegated to zustand's `createJSONStorage`).
 *
 * 2. `guardedStorage` — a `localStorage`-shaped object for the handful of
 *    stores that call `localStorage` directly. Same API, gate-checked.
 *
 * Gate semantics (see manifestGate): known keys pass through untouched;
 * unknown keys throw in dev and deny-safely in production. Values are never
 * logged — only key names (TEST-MATRIX 3.2).
 */

import {
  createJSONStorage,
  type PersistStorage,
  type StateStorage,
} from "zustand/middleware";
import { checkKey } from "./manifestGate";
import {
  resolvePiiStoreRefusal,
  type PiiStoreDenialReason,
  type PiiStoreEnvironment,
} from "./crypto/piiStoreCapability";

/**
 * Ephemeral demo-data mode (onboarding Fase 0).
 *
 * While a demo session is active, the stores are still driven through their
 * REAL actions (addSpool, addEntry, setters…) but every write is intercepted
 * here so nothing ever lands in localStorage/SQLite/manifest — the mode is
 * in-memory only, so there is nothing to inventory, export or erase (LGPD:
 * dado efêmero não é dado pessoal tratado). The choke point stays single:
 * suppression is checked before the backing store is ever touched, and reads
 * keep returning the user's real persisted data.
 */
let demoPersistenceSuppressed = false;

/** Engage/release write suppression. Called only by demoModeStore. */
export function setDemoPersistenceSuppressed(value: boolean): void {
  demoPersistenceSuppressed = value;
}

/** True while a demo session owns the stores (writes are no-ops). */
export function isDemoPersistenceSuppressed(): boolean {
  return demoPersistenceSuppressed;
}

/* ------------------------------------------------------------------ */
/*  PII vault gate — the same choke point, second predicate.           */
/* ------------------------------------------------------------------ */

/**
 * Capability snapshot for the browser PII vault, or null if none was ever
 * installed. `null` is a DENIAL, not a default: the vault has to be handed an
 * environment explicitly, so a caller that forgets cannot inherit "allowed"
 * from a previous session.
 */
let piiStoreEnvironment: PiiStoreEnvironment | null = null;

/**
 * The user's live decision. Deliberately NOT part of the snapshot: a consent
 * withdrawal must take effect at the next call, not at the next snapshot.
 */
let piiPersistenceDeclined = false;

/** Install (or clear, with null) the vault's capability snapshot. */
export function setPiiStoreEnvironment(
  environment: PiiStoreEnvironment | null,
): void {
  piiStoreEnvironment = environment;
}

/** Record that the user declined PII persistence (consent withdrawn/opt-out). */
export function setPiiPersistenceDeclined(value: boolean): void {
  piiPersistenceDeclined = value;
}

/** True while the user has declined PII persistence. */
export function isPiiPersistenceDeclined(): boolean {
  return piiPersistenceDeclined;
}

/**
 * Why the PII vault must refuse, or null when it may proceed.
 *
 * This is the ONE predicate the vault consults, and it composes the
 * demo-session suppression above rather than sitting beside it. Two
 * predicates would be two choke points: a demo session would then suppress
 * localStorage writes while still sealing PII into IndexedDB, and a demo
 * session is defined as holding nothing at all (LGPD ephemeral data is not
 * personal data being processed). `locked` is passed in by the caller because
 * the held key is per-store state, not a module-level flag.
 */
export function piiStoreRefusalReason(
  locked: boolean,
): PiiStoreDenialReason | null {
  return resolvePiiStoreRefusal({
    demoSuppressed: demoPersistenceSuppressed,
    environment: piiStoreEnvironment,
    declined: piiPersistenceDeclined,
    locked,
  });
}

/** True when the vault may read or write PII right now. */
export function isPiiStoreAllowed(locked: boolean): boolean {
  return piiStoreRefusalReason(locked) === null;
}

function rawStorage(): StateStorage {
  if (typeof window === "undefined" || !window.localStorage) {
    return {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    };
  }
  return window.localStorage;
}

function gatedStateStorage(): StateStorage {
  const backing = rawStorage();
  return {
    getItem: (name) => {
      // Deny = no-op: dev throws inside checkKey; production returns
      // allowed:false and we never touch the backing store.
      if (!checkKey(name).allowed) return null;
      return backing.getItem(name);
    },
    setItem: (name, value) => {
      // Demo mode: ephemeral by design — never persist.
      if (demoPersistenceSuppressed) return;
      if (!checkKey(name).allowed) return;
      backing.setItem(name, value);
    },
    removeItem: (name) => {
      if (demoPersistenceSuppressed) return;
      if (!checkKey(name).allowed) return;
      backing.removeItem(name);
    },
  };
}

/**
 * Drop-in zustand persist storage with manifest key-checking.
 * Identical to zustand's default (`createJSONStorage(() => localStorage)`)
 * except every key is validated against SPEC-01 first.
 */
export function manifestStorage<S>(): PersistStorage<S, unknown> | undefined {
  return createJSONStorage<S>(() => gatedStateStorage());
}

/**
 * `localStorage`-shaped facade with per-key manifest checks, for stores
 * that touch `localStorage` directly. API-compatible for get/set/remove.
 * Like `rawStorage()`, an unavailable backing store degrades to no-ops
 * (reads return null) — storage failure never crashes the app.
 */
export const guardedStorage = {
  getItem(key: string): string | null {
    const backing = rawStorage();
    if (!checkKey(key).allowed) return null;
    // rawStorage() is always the synchronous window.localStorage (or the
    // no-op stub), so the Promise variant of StateStorage never occurs.
    return backing.getItem(key) as string | null;
  },
  setItem(key: string, value: string): void {
    // Demo mode: ephemeral by design — never persist.
    if (demoPersistenceSuppressed) return;
    const backing = rawStorage();
    if (!checkKey(key).allowed) return;
    backing.setItem(key, value);
  },
  removeItem(key: string): void {
    if (demoPersistenceSuppressed) return;
    const backing = rawStorage();
    if (!checkKey(key).allowed) return;
    backing.removeItem(key);
  },
};
