import { useEffect, useRef, useState, type ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, RefreshCw, X } from "lucide-react";

/**
 * The two faces of a persistence bridge that could not do its job.
 *
 * The desktop entry starts the SQLite bridge and only renders `<App/>` once it
 * resolves, so stores hydrate from durable data instead of stale localStorage.
 * That ordering is the point — and it had no rejection path, so every failure
 * the bridge can raise produced a BLANK WINDOW: a `CryptoDeniedError`
 * refusal on a quarantined PII key (ADR-002 §2.2.1, `persistGate.ts`), a
 * manifest that will not load, a SQLite error on the first `listKeys`. The
 * renderer had nothing on screen, so there was nothing to read, nothing to
 * focus and no record that the app had decided not to start.
 *
 * `<StartupBridgeFailure>` is that missing rejection path. `<DbErrorBanner>`
 * is the production subscriber for `open3dcalc:db-error`, the event the bridge
 * dispatches on `document` after five consecutive failures — a signal that
 * until now had exactly one listener in the tree, and it was a test.
 *
 * Neither reads a store. The bridge can fail *because* a gated key is
 * quarantined, so anything that resolves a PII store to render this would be
 * reading the very state that caused it; both take their whole input from
 * props and from the DOM event, and nothing else.
 */

/** The event the bridge dispatches on `document` once failures pile up. */
export const DB_ERROR_EVENT = "open3dcalc:db-error";

interface BridgeErrorSurfaceProps {
  /** Names the landmark, so it is reachable and announced as a region. */
  label: string;
  title: string;
  /** Announced on arrival — this is the text a screen reader must read out. */
  message: string;
  /** Technical detail, or null when there is nothing to add. */
  detail?: string | null;
  actionLabel: string;
  onAction: () => void;
  actionIcon: ReactElement;
  /** When set, a second control that only closes the surface. */
  dismissLabel?: string;
  onDismiss?: () => void;
  /**
   * `page` fills the window — the app never mounted, so this IS the app.
   * `banner` is a persistent strip above a running app, the shape
   * `DemoModeIndicator` already uses.
   */
  variant: "page" | "banner";
}

/**
 * The shared shell of both surfaces.
 *
 * Follows `DemoModeIndicator`: a `<section aria-label>` landmark, because this
 * is a PERSISTENT state rather than a transient — it does not dismiss itself
 * on a timer, so it must not be a toast. The failure text itself is
 * `role="alert"`, which is the `Toast` pattern: drawn *and* announced.
 *
 * Deliberately in normal flow with no `z-index`. Nothing else is mounted in
 * the `page` case, and in the `banner` case this sits above a running app the
 * way the demo and update notices do — so it cannot end up in the modal tier
 * that `focusModeLayering` pins.
 *
 * Contrast: the pair is `--danger-fill` / `--danger-fill-fg`, the same
 * non-flipping ink over a solid fill `Toast` uses. The wash scanner's family
 * is exactly `accent|primary|positive|success|danger|critical|warning|info|
 * revenue|cost`, so `-fill` suffixed tokens are outside its scope — and the
 * pairing is already measured in both themes, so this is not a new claim.
 */
function BridgeErrorSurface({
  label,
  title,
  message,
  detail,
  actionLabel,
  onAction,
  actionIcon,
  dismissLabel,
  onDismiss,
  variant,
}: BridgeErrorSurfaceProps): ReactElement {
  const actionRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    // Moving focus is right on FIRST mount — nothing else has been focused,
    // so `document.body` owns it — and wrong on every later commit, where the
    // user is mid-interaction somewhere. Same rule as `DemoModeIndicator`.
    if (document.activeElement === document.body) {
      actionRef.current?.focus();
    }
  }, []);

  const filled = variant === "page";

  return (
    <section
      aria-label={label}
      className={
        filled
          ? "min-h-dvh w-full flex items-center justify-center p-6 bg-[var(--surface-canvas)]"
          : "w-full border-b border-[var(--color-danger)]/30 bg-[var(--color-danger-fill)]"
      }
    >
      <div
        className={
          filled
            ? "surface rounded-2xl p-6 sm:p-8 w-full max-w-2xl space-y-4 border-l-4 border-[var(--color-danger)]"
            : "px-4 sm:px-6 lg:px-12 py-3 flex items-center gap-3"
        }
      >
        <AlertTriangle
          className={
            filled
              ? "w-6 h-6 shrink-0 mt-1 text-[var(--color-danger)]"
              : "w-5 h-5 shrink-0 text-[var(--danger-fill-fg)]"
          }
          aria-hidden="true"
        />

        <div className="min-w-0 flex-1">
          <h1
            className={
              filled
                ? "text-lg font-bold text-[var(--color-text-primary)]"
                : "text-sm font-bold text-[var(--danger-fill-fg)]"
            }
          >
            {title}
          </h1>
          <p
            role="alert"
            className={
              filled
                ? "text-sm text-[var(--color-text-secondary)] mt-1"
                : "text-xs text-[var(--danger-fill-fg)]"
            }
          >
            {message}
          </p>
          {detail && (
            <p
              className={
                filled
                  ? "text-xs text-[var(--color-text-muted)] mt-1 font-mono break-words"
                  : "text-[11px] text-[var(--danger-fill-fg)] opacity-90"
              }
            >
              {detail}
            </p>
          )}
        </div>

        <div
          className={
            filled
              ? "flex items-center gap-3"
              : "flex items-center gap-2 shrink-0"
          }
        >
          <button
            ref={actionRef}
            type="button"
            onClick={onAction}
            className={
              filled
                ? "inline-flex items-center gap-2 min-h-[44px] px-4 py-2 rounded-xl text-sm font-semibold bg-[var(--color-danger-fill)] text-[var(--color-danger-fill-fg)] hover:bg-[var(--color-danger-fill-hover)] transition-colors focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
                : "inline-flex items-center gap-1.5 min-h-[36px] px-3 py-1.5 text-xs font-bold rounded-lg bg-[var(--danger-fill-fg)] text-[var(--danger-fill)] hover:opacity-90 transition-opacity focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            }
          >
            {actionIcon}
            {actionLabel}
          </button>
          {onDismiss && dismissLabel && (
            <button
              type="button"
              onClick={onDismiss}
              aria-label={dismissLabel}
              className={
                filled
                  ? "inline-flex items-center justify-center min-h-[44px] min-w-[44px] rounded-xl text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] transition-colors focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
                  : "shrink-0 rounded focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
              }
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

/**
 * Why the bridge refused, as a bare code — never its message.
 *
 * A `CryptoDeniedError` carries a reason code (`quarantined_read_only`,
 * `no_capability`, `write_path_disabled`, `locked`, `unknown_key`, …) and a
 * SQLite error carries a message that can name a file path on disk. Only the
 * code and the error class are shown: those identify the failure for support,
 * and they are what the bridge's own logs already carry (key NAMES only, never
 * values, §3.2).
 *
 * The reason is read from the `reason` FIELD, not out of the message. The two
 * used to be conflated — the constructor took a reason and only interpolated
 * it — and every denial then rendered as the bare class name
 * `CryptoDeniedError`, which tells support nothing about which of five
 * mutually exclusive causes they are looking at. `CryptoDeniedError.reason` is
 * a compile-time constant at every construction site, so it carries no PII.
 *
 * KNOWN LIMIT — the reason does not survive the IPC boundary, yet. The bridge
 * reaches SQLite through `ipcRenderer.invoke`, and a handler that throws is
 * serialised on its way back, so only the fields Electron's serialisation
 * preserves (`name`, `message`, `stack`) are guaranteed to arrive in the
 * renderer; a custom own property is not among them. This function therefore
 * resolves the reason only for errors raised IN the renderer, and falls back
 * to the class name for a refusal that crossed `db:save`. Closing that needs
 * the main process to hand back a structured reason of its own
 * (`electron/main.ts`), which is out of scope for this change — so the surface
 * says what it can and does not pretend the rest.
 */
function refusalReason(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const candidate = error as { reason?: unknown; name?: unknown };
    if (typeof candidate.reason === "string" && candidate.reason) {
      return candidate.reason;
    }
    if (typeof candidate.name === "string" && candidate.name)
      return candidate.name;
  }
  return typeof error === "string" && error ? error : "unknown";
}

/**
 * The whole window, for a bridge that refused to start at all.
 *
 * Rendered INSTEAD of `<App/>`, never beside it: a renderer that hydrated from
 * localStorage after a failed migration looks like it worked, and then loses
 * every write the user makes. The retry control reloads the window, which
 * re-runs the bridge — the only honest way back, since the refusal usually
 * comes from on-disk state (a quarantined row, a manifest that moved) and not
 * from anything this renderer can repair.
 */
export function StartupBridgeFailure({
  error,
}: {
  error: unknown;
}): ReactElement {
  const { t } = useTranslation();

  return (
    <BridgeErrorSurface
      variant="page"
      label={t("persistence.bridge.startupAriaLabel")}
      title={t("persistence.bridge.startupTitle")}
      message={t("persistence.bridge.startupMessage")}
      detail={t("persistence.bridge.startupDetail", {
        reason: refusalReason(error),
      })}
      actionLabel={t("persistence.bridge.retry")}
      actionIcon={<RefreshCw className="w-4 h-4" aria-hidden="true" />}
      onAction={() => window.location.reload()}
    />
  );
}

/**
 * The bridge's own `open3dcalc:db-error` signal, finally listened to.
 *
 * Fires after five consecutive failures, which is the bridge's "the user
 * should know" threshold rather than its first hiccup — a persistent strip is
 * the right shape for it, and the one control it carries is a dismissal,
 * because the app is still running and still usable; only durability is gone.
 * The message is the bridge's, verbatim, so there is one wording of the
 * failure in the product rather than two.
 */
export function DbErrorBanner(): ReactElement | null {
  const { t } = useTranslation();
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const onDbError = (event: Event): void => {
      const detail = (event as CustomEvent<{ message?: unknown }>).detail;
      setMessage(
        typeof detail?.message === "string" && detail.message
          ? detail.message
          : t("persistence.bridge.runtimeTitle"),
      );
    };
    document.addEventListener(DB_ERROR_EVENT, onDbError);
    return () => document.removeEventListener(DB_ERROR_EVENT, onDbError);
  }, [t]);

  if (message === null) return null;

  return (
    <BridgeErrorSurface
      variant="banner"
      label={t("persistence.bridge.runtimeAriaLabel")}
      title={t("persistence.bridge.runtimeTitle")}
      message={message}
      actionLabel={t("persistence.bridge.dismiss")}
      actionIcon={<X className="w-3.5 h-3.5" aria-hidden="true" />}
      onAction={() => setMessage(null)}
      dismissLabel={t("persistence.bridge.dismiss")}
      onDismiss={() => setMessage(null)}
    />
  );
}
