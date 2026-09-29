import { useConsentStore } from "@/shared/stores/consentStore";
import { ConsentModal } from "@/shared/components/ui/ConsentModal";
import { PrivacyBanner } from "@/shared/components/ui/PrivacyBanner";

/**
 * T5.2 — the first-use privacy surface, in one place.
 *
 * SPEC-04 §2/§6: consent is the receipt-backed grant, and a dismissed banner
 * never substitutes for it. So while no consent exists the app must ask for it
 * through the ConsentModal, and the dismissible PrivacyBanner is withheld —
 * rendering both would show the same notice twice at once. Once consent is
 * recorded the modal disappears and the passive banner remains.
 */
export function PrivacyOnboarding() {
  const consentGiven = useConsentStore((s) => s.consentGiven);
  if (!consentGiven) return <ConsentModal open />;
  return <PrivacyBanner />;
}
