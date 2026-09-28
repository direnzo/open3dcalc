/**
 * Persistence Bridge — syncs localStorage ↔ SQLite via Electron IPC.
 *
 * STRATEGY:
 *   - On startup: loads SQLite data into localStorage (stores hydrate as usual)
 *   - On first run: migrates existing localStorage → SQLite
 *   - On beforeunload: saves localStorage → SQLite
 *   - Periodic auto-save (see AUTO_SAVE_INTERVAL_MS) as a safety net
 *
 * This allows all existing Zustand stores to work unchanged — they still
 * use localStorage, but the durable store is SQLite.
 *
 * IMPORTANT: This module uses `window.electronAPI.db` directly (raw string I/O)
 * rather than `dbBridge` (which adds JSON.parse/stringify). This avoids
 * double-serialization because localStorage already stores JSON strings.
 */

import { isKeyAllowed, isManifestUnavailable } from "@/shared/lib/manifestGate";
import {
  latchUnavailableClasses,
  type UnavailableEntry,
} from "@/platform/desktop/overrides/unavailableClasses";

/**
 * Re-exported so the bridge's own type is reachable from the module a consumer
 * already imports. The VALUE comes from the leaf module above; this is an
 * alias, not a second latch, so the two cannot disagree.
 */
export type { UnavailableEntry } from "@/platform/desktop/overrides/unavailableClasses";

/* ------------------------------------------------------------------ */
/*  Error tracking                                                      */
/* ------------------------------------------------------------------ */

let consecutiveDbFailures = 0;
const MAX_FAILURES_BEFORE_WARN = 5;

/**
 * True once `loadFromDatabase` has enumerated the stored key set and written
 * every readable key into localStorage.
 *
 * The stale-key sweep's premise is "a DB row with no localStorage counterpart
 * has been removed at runtime". That premise is only valid AFTER hydration: run
 * it before, and every row looks stale — which is how an unloadable manifest,
 * which hydrates nothing, became the deletion of the whole profile.
 */
let hydrationCompleted = false;

/**
 * How often the safety-net save runs.
 *
 * Declared here, once, and referred to by name everywhere below — the four
 * comments that used to restate the interval in prose all said "30 seconds"
 * while the constant had been 10 s for a while, and reading one of them is
 * what put the wrong figure into an approved plan. A number that is only ever
 * written once cannot drift from the code it describes; a number repeated in
 * four comments can, and did.
 */
const AUTO_SAVE_INTERVAL_MS = 10_000;

/* ------------------------------------------------------------------ */
/*  Manifest availability                                               */
/* ------------------------------------------------------------------ */

/**
 * The one class the surface reports when the manifest itself will not load.
 *
 * It is NOT a storage key and is not persisted anywhere: `UnavailableEntry`
 * names "a class of stored data that exists but could not be read", and when
 * the manifest is unloadable the class is every key at once. `"*"` keeps that
 * honest while still travelling through the same latch and the same banner as a
 * per-key refusal. Key NAMES and codes only (§3.2).
 */
const MANIFEST_UNAVAILABLE_KEY = "*";
const MANIFEST_UNAVAILABLE_REASON = "manifest_unavailable";

/**
 * A save that could not even be evaluated, because the manifest would not load.
 *
 * Distinct from `PersistenceSaveError`, which reports a pass that lost SOME
 * keys: here no key could be classified, so the pass is refused in full. The
 * old path reached neither error — `collectLocalStorageEntries` filtered every
 * key out at `isKeyAllowed` and the pass reported "Saved 0 keys", a silent
 * no-op indistinguishable from a profile with nothing to save.
 */
export class ManifestUnavailableError extends Error {
  readonly reason = MANIFEST_UNAVAILABLE_REASON;
  constructor() {
    super(
      `${MANIFEST_UNAVAILABLE_REASON}: the manifest could not be loaded, so no key could be classified — save refused`,
    );
    this.name = "ManifestUnavailableError";
  }
}

/**
 * Latch and announce the whole-profile class, so the banner can show it.
 *
 * Called from the manifest failure itself rather than waiting for a per-key
 * `db:load` rejection: every key is denied before any load is issued, so no
 * load ever fails and the signal would otherwise never be raised. Idempotent in
 * effect (the latch holds one entry; re-announcing is harmless).
 */
function reportManifestUnavailable(): void {
  const entry: UnavailableEntry = {
    key: MANIFEST_UNAVAILABLE_KEY,
    reason: MANIFEST_UNAVAILABLE_REASON,
    recoverable: false,
  };
  latchUnavailableClasses([entry]);
  console.warn(
    `[persistence-bridge] ${MANIFEST_UNAVAILABLE_REASON} — no key could be classified`,
  );
  if (typeof document !== "undefined") {
    const event = new CustomEvent("open3dcalc:pii-unavailable", {
      detail: { unavailable: [entry] },
    });
    // On both, for the same reason as `loadFromDatabase`: a `document`-only
    // dispatch never reaches a `window` listener (bubbles defaults to false).
    document.dispatchEvent(event);
    window.dispatchEvent(event);
  }
}

/* ------------------------------------------------------------------ */
/*  Known localStorage keys used throughout the app                    */
/*  (Keep in sync with all stores, components, and migration logic)     */
/* ------------------------------------------------------------------ */

const LOCALSTORAGE_KEYS = [
  "open3dcalc_settings_v2",
  "open3dcalc_history_v2",
  "open3dcalc_customers_v1",
  "open3dcalc_quotes_v1",
  "open3dcalc_catalog_v1",
  "open3dcalc_filaments",
  "open3dcalc_color_palette_v1",
  "open3dcalc_consent_v1",
  "open3dcalc_tutorial_v1",
  "open3dcalc_onboarded",
  "open3dcalc_dashboard_v1",
  "open3dcalc_migration_done_v2",
  "open3dcalc_sections",
  "open3dcalc_theme",
] as const;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Check whether we're running inside Electron with the IPC bridge available.
 */
function isElectron(): boolean {
  return typeof window !== "undefined" && !!window.electronAPI?.db;
}

/**
 * Return the raw IPC db API. Throws if not in Electron — call `isElectron()` first.
 */
function db() {
  // Non-null assertion safe because caller must guard with isElectron()
  return window.electronAPI!.db;
}

/**
 * Return the known and manifest-approved localStorage source values once.
 * Capturing before the asynchronous writes keeps iteration stable while the
 * IPC adapter is saving rows.
 */
function collectLocalStorageEntries(): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  const seen = new Set<string>();

  const collect = (key: string): void => {
    if (seen.has(key) || !isKeyAllowed(key)) return;
    const raw = localStorage.getItem(key);
    if (raw === null) return;
    seen.add(key);
    entries.push([key, raw]);
  };

  for (const key of LOCALSTORAGE_KEYS) collect(key);
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key?.startsWith("open3dcalc_")) collect(key);
  }
  return entries;
}

/**
 * Record one failed operation.
 *
 * The log line carries the real error; the DOM event deliberately does NOT.
 *
 * `open3dcalc:db-error` is dispatched into the renderer, where it becomes
 * user-visible text via `DbErrorBanner`, so its `detail.message` is a FIXED
 * string and stays one — no error message, no key name, no stack, nothing
 * derived from a value. Interpolating `error` into it would be the obvious
 * "improvement" and it is the PII-exposure path this file is written to keep
 * shut (§3.2 — logs carry key NAMES only, never values, and a user-facing
 * string is a wider channel than a log). The cost of the fixed string is that
 * it cannot say which key failed; that diagnosis belongs in the console line
 * above, which already has the error.
 */
function noteDbFailure(error: unknown, operation: string): void {
  console.warn(`[persistence-bridge] Failed to ${operation}:`, error);
  consecutiveDbFailures++;
  if (consecutiveDbFailures === MAX_FAILURES_BEFORE_WARN) {
    if (typeof document !== "undefined") {
      const event = new CustomEvent("open3dcalc:db-error", {
        detail: {
          message:
            "Database unavailable — data will not persist between sessions.",
        },
      });
      document.dispatchEvent(event);
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Core operations                                                     */
/* ------------------------------------------------------------------ */

/**
 * A class of stored data that exists but could not be read, and why.
 *
 * Distinct from an error, and distinct from an empty value: the app continues,
 * the rest of the profile loads, and the user is told which class is missing and
 * what to do about it. A refusal MUST NOT look like data loss — a store hydrated
 * with an empty string would both read as "you have no customers" and then
 * overwrite the very row that could not be read on the next save.
 */
/**
 * Load all persisted data from SQLite into localStorage.
 * Called once at app startup (after any migration).
 *
 * ## Per-key isolation, and why it is not optional
 *
 * This used to `await db().load(key)` inside a bare loop, so a single unreadable
 * row rejected the whole function. An ADR-001 §3.6 refusal — a pre-remediation
 * `enc1:safeStorage:` blob, a 1.1 envelope — propagated out of here, out of
 * `initPersistenceBridge`, and `main.tsx` rendered `<StartupBridgeFailure/>`
 * instead of `<App/>`. Worse, the throw happened at step 2, so the app never
 * registered its `beforeunload` handler or its auto-save interval AT ALL: the
 * profile could not be saved even for the keys that were perfectly readable. One
 * unreadable row took down the application.
 *
 * The OS keyring was the default path before the Wave 2 remediation, so such
 * rows are exactly what a normal upgrading user has. This is the most likely
 * first-run experience of the upgrade.
 *
 * So a per-value refusal is now collected and reported, and hydration continues.
 * Fail-closed is preserved on both sides: an unreadable value is never written
 * into `localStorage` (it is not decrypted, and it is not materialized as the raw
 * ciphertext either), and it is never deleted from SQLite. A STRUCTURAL failure —
 * `listKeys` itself failing, an unreadable manifest — is still terminal, because
 * then there is no key set to isolate and hydrating from stale localStorage would
 * look like success and then lose every write.
 */
async function loadFromDatabase(): Promise<void> {
  // A structural manifest failure is detected BEFORE the per-key loop: with
  // the manifest unloadable `isKeyAllowed` denies every key, so the loop below
  // would skip the whole profile and report a successful empty hydration. Latch
  // the class instead (a `db:load` is never issued, so nothing else would), and
  // leave `hydrationCompleted` false so the sweep refuses to run.
  if (isManifestUnavailable()) {
    reportManifestUnavailable();
    console.warn(
      "[persistence-bridge] Hydration skipped: manifest unavailable",
    );
    return;
  }

  const keys = await db().listKeys();
  const values: Array<[string, string]> = [];
  const unavailable: UnavailableEntry[] = [];

  for (const key of keys) {
    // SPEC-01 gate: unknown keys are never materialized locally.
    if (!isKeyAllowed(key)) continue;
    try {
      const raw = await db().load(key);
      if (raw !== null && raw !== undefined) values.push([key, raw]);
    } catch (error) {
      // One key, isolated. The reason survives the IPC boundary as the
      // main process's own code, because `db:load` is told to attach it to the
      // rejection rather than relying on Electron's string flattening — which
      // rewrites it to "Error invoking remote method 'db:load': …" and loses
      // every structured field.
      unavailable.push({
        key,
        reason: refusalCodeFromError(error),
        recoverable: RECOVERABLE_REASONS.has(refusalCodeFromError(error)),
      });
    }
  }

  // Read every row successfully before touching localStorage. A DB read error
  // must reject startup without applying a partial hydration to the renderer.
  for (const [key, raw] of values) localStorage.setItem(key, raw);

  if (unavailable.length > 0) {
    // Latched before the event, because the event is raised with no subscriber
    // mounted yet — see `unavailableClasses.ts` for why the latch is a separate
    // leaf module rather than a field of this one.
    latchUnavailableClasses(unavailable);
    // Announced, not silently skipped: a class of data the user cannot see
    // must be said out loud, or "my customers are gone" is indistinguishable
    // from "this app decided not to show you your customers".
    console.warn(
      `[persistence-bridge] ${unavailable.length} key(s) unavailable and quarantined: ` +
        unavailable.map((u) => `${u.key} (${u.reason})`).join(", "),
    );
    if (typeof document !== "undefined") {
      // On BOTH `document` and `window`. The `document`-only dispatch is what
      // made this unobservable in practice: jsdom's `CustomEvent` defaults
      // `bubbles` to false, and a non-bubbling event dispatched on `document`
      // never reaches a listener registered on `window` — which is where a
      // React component or a plain subscriber would sit. The event is announced,
      // not silently skipped, and an announcement nobody can receive is the same
      // as no announcement.
      const event = new CustomEvent("open3dcalc:pii-unavailable", {
        detail: { unavailable },
      });
      document.dispatchEvent(event);
      window.dispatchEvent(event);
    }
  }

  console.log(
    `[persistence-bridge] Loaded ${values.length}/${keys.length} keys from SQLite` +
      (unavailable.length > 0 ? ` (${unavailable.length} quarantined)` : ""),
  );

  // Only now is the sweep's premise valid: every stored key was enumerated and
  // every readable one is in localStorage. Per-key refusals do not invalidate
  // it — the refused key is still a DB row with a localStorage counterpart when
  // the app holds one, and is never deleted either way.
  hydrationCompleted = true;
}

/**
 * Refusals where the bytes are intact and only the old SHAPE is refused, so
 * ADR-001 §3.6 recovery can still be attempted. Mirrors `RECOVERABLE_REASONS`
 * in the main process; kept as its own set because the renderer must not import
 * main-process modules across the IPC boundary.
 */
const RECOVERABLE_REASONS = new Set([
  "legacy_unbound_encryption",
  "legacy_envelope_v1_1",
]);

/**
 * Recover the main process's refusal code from a rejected `db:load`.
 *
 * Electron flattens an error crossing `ipcRenderer.invoke` into a plain string
 * prefixed "Error invoking remote method 'db:load': ", so `error.reason` and
 * `error.code` do not survive. Two sources, in order of trust:
 *
 *  1. the structured fields, when the rejection is direct (a test, or a future
 *     structured-result contract); then
 *  2. the code as a substring of the flattened message, which is why
 *     `electron/main.ts` puts the code IN the message before re-throwing.
 *
 * The fallback is a generic `unreadable` rather than a guess: inventing a
 * specific reason from a mangled string is how a wrong reason reaches a user.
 */
function refusalCodeFromError(error: unknown): string {
  const structured = (error as { reason?: unknown } | null)?.reason;
  if (typeof structured === "string" && structured.length > 0) {
    return structured;
  }
  const message = String(
    (error as { message?: unknown } | null)?.message ?? error,
  );
  for (const code of [
    "legacy_unbound_encryption",
    "legacy_envelope_v1_1",
    "authentication_failed",
    "no_capability",
    "profile_data_key_unavailable",
    "locked",
    ...RECOVERABLE_REASONS,
  ]) {
    if (message.includes(code)) return code;
  }
  return "unreadable";
}

/**
 * A save pass that lost one or more keys.
 *
 * Reported as ONE error carrying every key and its own error, rather than the
 * first refusal: a single quarantined PII key explains a failed pass, and five
 * of them do not. What the caller does with it is deliberately narrow — the
 * console line it produces receives this error whole, so the aggregated
 * message (every lost key) and every per-key error underneath it are what
 * reaches the log. The `open3dcalc:db-error` signal that `noteDbFailure` also
 * raises does NOT carry it: that event's text is a fixed string, and an error
 * is not something to put in front of a user. See `noteDbFailure`.
 *
 * Key NAMES only, in the message and in the log — never a value (§3.2).
 */
export class PersistenceSaveError extends Error {
  readonly failures: ReadonlyArray<{ key: string; error: unknown }>;

  constructor(failures: ReadonlyArray<{ key: string; error: unknown }>) {
    super(
      `Failed to save ${failures.length} localStorage key(s) to SQLite: ` +
        failures.map(({ key }) => key).join(", "),
    );
    this.name = "PersistenceSaveError";
    this.failures = failures;
  }
}

/**
 * Save all localStorage data to SQLite.
 * Called on beforeunload and periodically (every 10 s).
 *
 * Moves JSON strings as-is from localStorage to SQLite.
 *
 * Per key, not per pass: a refused key is not a one-off. A quarantined PII key
 * (ADR-002 §2.2.1) is refused on EVERY write until the user migrates or
 * eliminates it, so the `await` this loop used to put in its header threw out
 * of the function on the first one and every key after it in
 * LOCALSTORAGE_KEYS went unpersisted without a word — a failure that was both
 * total and permanent. The loop continues, and the pass reports itself as a
 * whole once every key has had its turn.
 */
async function saveToDatabase(): Promise<void> {
  // "No keys are eligible" and "no key could be evaluated" are different facts.
  // Without this check the second collapses into the first: every key is
  // filtered out at `isKeyAllowed`, the loop runs zero times, and the pass
  // reports "Saved 0 keys" — a silent no-op whose writes exist only in
  // localStorage and die on restart.
  if (isManifestUnavailable()) {
    reportManifestUnavailable();
    throw new ManifestUnavailableError();
  }

  const entries = collectLocalStorageEntries();
  const failures: Array<{ key: string; error: unknown }> = [];
  for (const [key, raw] of entries) {
    try {
      await db().save(key, raw);
    } catch (error) {
      failures.push({ key, error });
    }
  }
  if (failures.length > 0) throw new PersistenceSaveError(failures);
  console.log(`[persistence-bridge] Saved ${entries.length} keys to SQLite`);
}

/**
 * Delete keys from SQLite that are no longer in localStorage.
 * Keeps the two stores in sync when keys are removed at runtime.
 */
async function deleteStaleKeys(): Promise<void> {
  // The sweep deletes a DB row when its key is absent from localStorage. Both
  // halves of that premise have to be true before it may run:
  //
  //  - the manifest must be loadable, or "the key is not in localStorage" is
  //    indistinguishable from "the key was never evaluated"; and
  //  - hydration must have completed, or localStorage was never populated and
  //    every row looks stale.
  //
  // Refusing to run is the fail-closed choice: the cost of a skipped sweep is a
  // stale row surviving one more cycle, and the cost of a wrongly-run sweep is
  // permanent deletion of a user's profile.
  if (isManifestUnavailable()) {
    console.warn(
      "[persistence-bridge] Skipping stale-key sweep: manifest unavailable",
    );
    return;
  }
  if (!hydrationCompleted) {
    console.warn(
      "[persistence-bridge] Skipping stale-key sweep: hydration not complete",
    );
    return;
  }

  try {
    const dbKeys = await db().listKeys();
    const localKeys = new Set<string>();

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) localKeys.add(key);
    }

    for (const dbKey of dbKeys) {
      if (!localKeys.has(dbKey)) {
        await db().delete(dbKey);
      }
    }
  } catch (error) {
    console.warn("[persistence-bridge] Failed to clean stale keys:", error);
  }
}

/**
 * Import localStorage data when SQLite does not yet contain every approved
 * source key. This also resumes a previous import interrupted after any
 * committed prefix of per-key writes.
 */
async function migrateIfNeeded(): Promise<void> {
  const existingKeys = new Set(await db().listKeys());
  const sourceEntries = collectLocalStorageEntries();
  const missingSourceKeys = sourceEntries.some(
    ([key]) => !existingKeys.has(key),
  );

  if (!missingSourceKeys) {
    // SQLite is authoritative only when it already contains every allowed
    // source key. A theme seed or partial write must never suppress recovery.
    console.log(
      "[persistence-bridge] SQLite contains all localStorage source keys; skipping import",
    );
    return;
  }

  // Idempotent upserts make this restart-safe after any prefix of db.save
  // writes has committed. Failure intentionally propagates to abort renderer
  // startup; localStorage is left untouched until the entire import succeeds.
  console.log(
    "[persistence-bridge] SQLite is incomplete — migrating localStorage → SQLite",
  );
  for (const [key, raw] of sourceEntries) await db().save(key, raw);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Initialize the persistence bridge.
 *
 * Must be called ONCE at app startup, BEFORE React renders,
 * so that Zustand stores hydrate with SQLite-backed data.
 *
 * Call flow:
 *   1. Migrate localStorage → SQLite if first run
 *   2. Load SQLite data → localStorage (overwrites any stale localStorage)
 *   3. Register beforeunload handler for save-on-close
 *   4. Start periodic auto-save (see AUTO_SAVE_INTERVAL_MS)
 */
export async function initPersistenceBridge(): Promise<void> {
  if (!isElectron()) {
    console.log(
      "[persistence-bridge] Not running in Electron — using localStorage only",
    );
    return;
  }

  try {
    if (isManifestUnavailable()) {
      // Neither import nor hydrate: no key can be classified. Latch the class
      // now, from the manifest failure itself, so the banner can show it — no
      // `db:load` is ever issued, so no per-key rejection could carry it. The
      // handlers below are still registered: in-session writes must be REFUSED
      // (visibly, by `saveToDatabase`) rather than silently skipped, and the
      // sweep must refuse to run.
      reportManifestUnavailable();
    } else {
      // 1. Migrate localStorage → SQLite if first run or a prior startup was
      //    interrupted. Any partial failure rejects before renderer hydration.
      await migrateIfNeeded();

      // 2. Load SQLite data into localStorage only after the complete migration.
      //    Per-value refusals are collected INSIDE this call and do not reject —
      //    see `loadFromDatabase`. Only a structural failure reaches the catch.
      await loadFromDatabase();
    }
  } catch (error) {
    noteDbFailure(error, "initialize persistence bridge");
    throw error;
  }

  // 3. Set up save-on-close via beforeunload
  //
  // NOTE: beforeunload fires when the window is about to close.
  // Electron's IPC invoke returns a Promise; we await it to flush.
  // As a safety net, the periodic save (AUTO_SAVE_INTERVAL_MS) guards against
  // data loss if beforeunload doesn't fully complete.
  window.addEventListener("beforeunload", () => {
    void saveToDatabase().catch((error: unknown) =>
      noteDbFailure(error, "save localStorage to SQLite"),
    );
  });

  // 4. Periodic auto-save on AUTO_SAVE_INTERVAL_MS (safety net)
  //    Also runs stale-key cleanup on each cycle.
  //
  //    The two are settled independently on purpose. They were one `try`, so a
  //    single refused key threw out of the block and the sweep never ran for
  //    that cycle — while a refused key is exactly the kind that keeps being
  //    refused, so the sweep was cancelled on every cycle from then on. The
  //    sweep only deletes rows whose localStorage counterpart is gone, and a
  //    write that was refused cannot change any key's membership, so the two
  //    never actually depended on each other.
  setInterval(async () => {
    await Promise.allSettled([
      saveToDatabase().catch((error: unknown) =>
        noteDbFailure(error, "save localStorage to SQLite"),
      ),
      deleteStaleKeys(),
    ]);
  }, AUTO_SAVE_INTERVAL_MS);

  console.log(
    "[persistence-bridge] Initialized — localStorage ↔ SQLite sync active",
  );
}
