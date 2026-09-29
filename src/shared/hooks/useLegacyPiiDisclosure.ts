/**
 * The desktop-aware, value-free disclosure of the legacy PII residue.
 *
 * A thin React wrapper over `getLegacyPiiDisclosure` that feeds it the merged
 * reader from `useLegacyPiiRead`, so the Privacy screen's residue panel is
 * honest on desktop too (where the residue is in SQLite, not `localStorage`).
 *
 * `enabled: false` skips the derivation entirely and returns `null` — the panel
 * uses that when a caller injects its own disclosure, so an injected test value
 * never triggers a live read.
 */

import { useMemo } from "react";
import {
  getLegacyPiiDisclosure,
  type LegacyPiiDisclosure,
} from "@/shared/lib/migration/legacyPiiDisclosure";
import { installPiiStoreRuntimeEnvironment } from "@/shared/lib/crypto/piiStoreHydration";
import { useLegacyPiiRead } from "@/shared/hooks/useLegacyPiiResidue";

/** The live disclosure, or `null` when disabled. */
export function useLegacyPiiDisclosure(
  enabled = true,
): LegacyPiiDisclosure | null {
  const read = useLegacyPiiRead(enabled);
  return useMemo(() => {
    if (!enabled) return null;
    // Install the capability snapshot before the first read, or a capable
    // browser would report `capability_unknown` and read as unavailable.
    installPiiStoreRuntimeEnvironment();
    return getLegacyPiiDisclosure({ read });
  }, [enabled, read]);
}
