import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  gatedPiiPersistStorage,
  registerPiiPersistStore,
} from "@/shared/lib/crypto/piiStoreHydration";

export interface BusinessProfile {
  name: string;
  whatsapp: string;
  email: string;
  address: string;
  cnpj: string;
  paymentTerms: string;
  deadline: string;
  notes: string;
}

interface BusinessProfileStore {
  profile: BusinessProfile;
  setProfile: (profile: BusinessProfile) => void;
  updateProfile: (changes: Partial<BusinessProfile>) => void;
  clearProfile: () => void;
}

export const EMPTY_BUSINESS_PROFILE: BusinessProfile = {
  name: "",
  whatsapp: "",
  email: "",
  address: "",
  cnpj: "",
  paymentTerms: "",
  deadline: "",
  notes: "",
};

export const BUSINESS_PROFILE_STORE_KEY =
  "open3dcalc_business_profile_v1" as const;

export const useBusinessProfileStore = create<BusinessProfileStore>()(
  persist(
    (set) => ({
      profile: EMPTY_BUSINESS_PROFILE,
      setProfile: (profile) => set({ profile: { ...profile } }),
      updateProfile: (changes) =>
        set((state) => ({ profile: { ...state.profile, ...changes } })),
      clearProfile: () => set({ profile: { ...EMPTY_BUSINESS_PROFILE } }),
    }),
    {
      name: BUSINESS_PROFILE_STORE_KEY,
      version: 1,
      storage: gatedPiiPersistStorage<BusinessProfileStore>(
        BUSINESS_PROFILE_STORE_KEY,
      ),
      skipHydration: true,
    },
  ),
);

registerPiiPersistStore(
  BUSINESS_PROFILE_STORE_KEY,
  useBusinessProfileStore.persist,
);