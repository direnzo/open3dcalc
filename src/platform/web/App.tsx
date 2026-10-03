import React from "react";
import { NavigationProvider } from "@/shared/components/AppShell/NavigationProvider";
import { PreferenceProvider } from "@/shared/contexts/PreferenceProvider";
import { StudioLayout } from "./components/studio/StudioLayout";

// The TABS contract is re-exported here for compatibility
export { TABS } from "@/shared/components/AppShell/tabs";

function App(): React.ReactElement {
  return (
    <PreferenceProvider>
      <NavigationProvider>
        <StudioLayout />
      </NavigationProvider>
    </PreferenceProvider>
  );
}

export default App;
