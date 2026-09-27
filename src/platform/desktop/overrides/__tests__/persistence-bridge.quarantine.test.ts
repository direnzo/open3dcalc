/**
 * One refused key must not strand the rest of the save.
 *
 * `saveToDatabase()` used to `await db().save(key, raw)` straight out of the
 * loop header, so the first refusal threw out of the function and every key
 * after it went unpersisted — silently, because a quarantined PII key
 * (ADR-002 §2.2.1) is refused on EVERY write and is therefore not a one-off
 * that a later pass would clear. The same rejection also cancelled the
 * stale-key sweep for that cycle, because the interval ran the two in one
 * `try`.
 *
 * Two things this file is careful about, both of which made the specs lie
 * rather than fail:
 *
 *  - The refusal is armed only AFTER startup. The bridge's own migration pass
 *    fails closed by design, so a refusal during `initPersistenceBridge()`
 *    aborts initialisation instead of exercising the save loop.
 *  - Every spec waits for the save pass to FINISH, not to start. The loop is
 *    sequential, so any condition the first `save` satisfies (a non-empty
 *    attempt list, one failure recorded) is read mid-pass and reports a
 *    half-completed pass as a lost tail.
 *
 * The bridge is module-scoped, and `initPersistenceBridge()` registers a
 * `beforeunload` listener and an interval on every call. Those listeners close
 * over the db stub of the spec that created them, so without removing them a
 * later spec's `beforeunload` would drive every earlier spec's stub as well.
 * `vi.clearAllTimers()` handles the intervals; the listeners are removed here.
 * `consecutiveDbFailures` is also module-scoped but is deliberately left alone:
 * it only gates the one-shot `open3dcalc:db-error` dispatch, which no spec in
 * this file asserts on, so a reset seam for it would be a test-only export
 * guarding nothing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ElectronAPI } from "@/platform/desktop/types/electron";
import {
  initPersistenceBridge,
  PersistenceSaveError,
} from "../persistence-bridge";

/** A PII key: the class the ADR-002 quarantine regime refuses writes to. */
const QUARANTINED_KEY = "open3dcalc_customers_v1";
const ALSO_REFUSED_KEY = "open3dcalc_quotes_v1";
const EARLIER_KEY = "open3dcalc_settings_v2";
/** Keys the bridge writes AFTER the quarantined one. */
const LATER_KEYS = [
  "open3dcalc_history_v2",
  "open3dcalc_catalog_v1",
  "open3dcalc_filaments",
  "open3dcalc_dashboard_v1",
  "open3dcalc_theme",
];

/** Every key seeded, i.e. the whole population one save pass must attempt. */
const SEEDED = [EARLIER_KEY, QUARANTINED_KEY, ALSO_REFUSED_KEY, ...LATER_KEYS];

function denied(reason: string): Error {
  return Object.assign(new Error(`write refused: ${reason}`), {
    name: "CryptoDeniedError",
    reason,
  });
}

interface DbStub {
  /** Keys `save` was called with, in call order. */
  attempts: string[];
  remove: ReturnType<typeof vi.fn<(key: string) => Promise<void>>>;
  listKeys: ReturnType<typeof vi.fn<() => Promise<string[]>>>;
}

/**
 * An in-memory `electronAPI.db` that refuses the keys `shouldRefuse` names.
 *
 * The predicate is read on every call rather than captured, so a spec can
 * start the bridge clean and arm the refusal afterwards.
 */
function stubElectronDb(shouldRefuse: (key: string) => boolean): DbStub {
  const attempts: string[] = [];
  const remove = vi.fn<(key: string) => Promise<void>>(async () => undefined);
  const listKeys = vi.fn<() => Promise<string[]>>(async () => []);
  const db = {
    load: vi.fn<(key: string) => Promise<string | null>>(async () => null),
    save: vi.fn(async (key: string) => {
      attempts.push(key);
      if (shouldRefuse(key)) throw denied("quarantined_read_only");
    }),
    delete: remove,
    listKeys,
  };
  (
    window as unknown as { electronAPI: { db: ElectronAPI["db"] } }
  ).electronAPI = { db: db as unknown as ElectronAPI["db"] };
  return { attempts, remove, listKeys };
}

/** The first aggregate the reporter was handed, if any. */
function reportedSaveError(
  warnCalls: unknown[][],
): PersistenceSaveError | undefined {
  return warnCalls
    .map(([, error]) => error)
    .find(
      (error): error is PersistenceSaveError =>
        error instanceof PersistenceSaveError,
    );
}

describe("persistence bridge — a refused key fails the pass, not the loop", () => {
  let armed = false;
  let registered: Array<[string, EventListenerOrEventListenerObject]>;

  beforeEach(() => {
    vi.useFakeTimers();
    armed = false;
    localStorage.clear();
    for (const key of SEEDED)
      localStorage.setItem(key, JSON.stringify({ key }));

    // Every `initPersistenceBridge()` in this file adds one beforeunload
    // listener; they are torn down per spec so a later dispatch cannot reach
    // an earlier spec's stub. The spy still registers for real — swallowing
    // the call would stop the save loop from running at all, which is a
    // different failure than the one these specs are about.
    registered = [];
    const add = window.addEventListener.bind(window);
    vi.spyOn(window, "addEventListener").mockImplementation(
      (
        type: string,
        listener: EventListenerOrEventListenerObject,
        options?: boolean | AddEventListenerOptions,
      ) => {
        registered.push([type, listener]);
        add(type, listener, options);
      },
    );
  });

  afterEach(() => {
    for (const [type, listener] of registered) {
      window.removeEventListener(type, listener);
    }
    vi.restoreAllMocks();
    vi.clearAllTimers();
    vi.useRealTimers();
    delete (window as unknown as { electronAPI?: unknown }).electronAPI;
  });

  it("attempts every remaining key after a quarantined one is refused", async () => {
    const stub = stubElectronDb((key) => armed && key === QUARANTINED_KEY);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await initPersistenceBridge();
    stub.attempts.length = 0;
    armed = true;

    window.dispatchEvent(new Event("beforeunload"));
    // Completion, not start: the whole seeded population attempted means the
    // pass ran to the end of the list rather than stalling on the refusal.
    await vi.waitFor(() =>
      expect(stub.attempts).toEqual(expect.arrayContaining(SEEDED)),
    );

    // The defect: `await` in the loop header threw on the quarantined key, so
    // none of these were ever written. The refusal has to cost one key, not
    // the tail of the list.
    for (const key of LATER_KEYS) {
      expect(stub.attempts, `${key} was never attempted`).toContain(key);
    }
    expect(stub.attempts).toContain(EARLIER_KEY);
    expect(stub.attempts.filter((key) => key === QUARANTINED_KEY)).toHaveLength(
      1,
    );
    expect(warn).toHaveBeenCalled();
  });

  it("reports the failure as an aggregate naming every key it lost", async () => {
    stubElectronDb(
      (key) => armed && (key === QUARANTINED_KEY || key === ALSO_REFUSED_KEY),
    );
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    await initPersistenceBridge();
    armed = true;

    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() =>
      expect(reportedSaveError(warn.mock.calls)).toBeDefined(),
    );

    const aggregate = reportedSaveError(warn.mock.calls)!;
    // Not swallowed: the failure reaches the reporter carrying every key.
    expect(aggregate.failures.map(({ key }) => key).sort()).toEqual(
      [QUARANTINED_KEY, ALSO_REFUSED_KEY].sort(),
    );
    for (const { error } of aggregate.failures) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).name).toBe("CryptoDeniedError");
      expect((error as { reason?: string }).reason).toBe(
        "quarantined_read_only",
      );
    }
    expect(aggregate.message).toContain(QUARANTINED_KEY);
    expect(aggregate.message).toContain(ALSO_REFUSED_KEY);
  });

  it("still sweeps stale keys in a cycle whose save was refused", async () => {
    const stub = stubElectronDb((key) => armed && key === QUARANTINED_KEY);
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    await initPersistenceBridge();
    armed = true;

    // A row whose localStorage counterpart is gone. Nothing about the refused
    // key changes this key's fate, so the sweep must still run.
    const staleKey = "open3dcalc_synthetic_stale";
    stub.listKeys.mockImplementation(async () => [staleKey]);

    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => expect(stub.remove).toHaveBeenCalledWith(staleKey));

    // The defect: one `try` around both, so the rejection cancelled the sweep.
    expect(stub.remove).toHaveBeenCalledWith(staleKey);
  });

  it("leaves a clean pass reporting nothing", async () => {
    // `() => armed` here would refuse EVERY key once armed, which is the
    // opposite of what this spec claims to measure.
    const stub = stubElectronDb(() => false);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await initPersistenceBridge();
    armed = true;

    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() =>
      expect(stub.attempts).toEqual(expect.arrayContaining(SEEDED)),
    );

    expect(warn).not.toHaveBeenCalled();
  });
});
