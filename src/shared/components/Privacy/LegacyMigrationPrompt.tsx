import { useState } from "react";
import { useConsentStore } from "@/shared/stores/consentStore";
import { detectLegacyPlaintextPii } from "@/shared/lib/legacyPiiPlaintext";
import { DataSyncModal } from "@/shared/components/ui/DataSyncModal";
import { LegacyMigrationDialog } from "./LegacyMigrationDialog";

/**
 * T5.2 — the production caller of the legacy-residue detection.
 *
 * ADR-002 §2.2: the residue must be surfaced, never silently migrated nor
 * silently deleted. The prompt appears only when there is residue AND the
 * migration consent is still pending, so it cannot nag a user who already
 * answered by granting the grant. Choosing "not now" or "keep read-only"
 * dismisses it for the session; the durable disclosure lives on the privacy
 * screen, so this prompt is a call to decide, not the only place that admits
 * the residue exists.
 */
export function LegacyMigrationPrompt() {
  const migrationConsentGiven = useConsentStore((s) => s.migrationConsentGiven);
  const [dismissed, setDismissed] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  // Re-read on every render: the residue is copy-without-delete, so it stays
  // present until the user acts, and an unlock elsewhere must be able to make
  // the prompt actionable again without a remount.
  const report = detectLegacyPlaintextPii();
  const open = report.present && !migrationConsentGiven && !dismissed;

  return (
    <>
      <LegacyMigrationDialog
        open={open && !exportOpen}
        report={report}
        onRequestClose={() => setDismissed(true)}
        onOpenExport={() => {
          setDismissed(true);
          setExportOpen(true);
        }}
      />
      <DataSyncModal
        open={exportOpen}
        onRequestClose={() => setExportOpen(false)}
      />
    </>
  );
}
