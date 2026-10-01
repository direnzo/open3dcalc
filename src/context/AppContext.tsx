import React, { createContext, useContext, useState, useEffect, useMemo, ReactNode } from 'react';
import { CurrencyCode } from '../types';
import { AppSection } from '../components/AppSidebar';
import { formatCurrency as formatCurrencyUtil } from '../utils/calculator';

export type CalculatorLayoutVariant = 'classic' | 'wizard' | 'bento';
export type AppTheme = 'dark' | 'midnight' | 'light';

export interface ToastMessage {
  id: number;
  message: string;
  icon?: string;
}

interface NavigationContextValue {
  currentSection: AppSection;
  setCurrentSection: (section: AppSection) => void;
  calculatorLayout: CalculatorLayoutVariant;
  setCalculatorLayout: (layout: CalculatorLayoutVariant) => void;
  isSidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  navigateTo: (section: AppSection) => void;
}

interface CurrencyContextValue {
  currency: CurrencyCode;
  setCurrency: (currency: CurrencyCode) => void;
  formatCurrency: (amount: number) => string;
  currencySymbol: string;
}

interface ThemeContextValue {
  theme: AppTheme;
  setTheme: (theme: AppTheme) => void;
  toggleTheme: () => void;
}

interface MiniDashContextValue {
  isMiniDashOpen: boolean;
  setIsMiniDashOpen: (open: boolean) => void;
  toggleMiniDash: () => void;
  isMiniDashPinned: boolean;
  setIsMiniDashPinned: (pinned: boolean) => void;
  toggleMiniDashPinned: () => void;
}

interface SimplifiedModeContextValue {
  isSimplifiedMode: boolean;
  setIsSimplifiedMode: (simplified: boolean) => void;
  toggleSimplifiedMode: () => void;
}

export type VisibleTabsState = Record<AppSection, boolean>;

export const DEFAULT_VISIBLE_TABS: VisibleTabsState = {
  pricing: true,
  dashboard: true,
  history: true,
  printers: true,
  spools: true,
  infill: false,
  clients: false
};

interface FocusModeContextValue {
  isFocusMode: boolean;
  setIsFocusMode: (focus: boolean) => void;
  toggleFocusMode: () => void;
}

interface TabVisibilityContextValue {
  visibleTabs: VisibleTabsState;
  setVisibleTabs: (tabs: VisibleTabsState) => void;
  toggleTabVisibility: (section: AppSection) => void;
  resetTabVisibility: () => void;
  isVisibilityManagerOpen: boolean;
  setIsVisibilityManagerOpen: (open: boolean) => void;
}

interface ModalsContextValue {
  isQuoteModalOpen: boolean;
  setIsQuoteModalOpen: (open: boolean) => void;
  isAICopilotOpen: boolean;
  setIsAICopilotOpen: (open: boolean) => void;
  isHistorySidebarOpen: boolean;
  setIsHistorySidebarOpen: (open: boolean) => void;
  isInfillModalOpen: boolean;
  setIsInfillModalOpen: (open: boolean) => void;
  isClientsModalOpen: boolean;
  setIsClientsModalOpen: (open: boolean) => void;
  isShortcutsHelpOpen: boolean;
  setIsShortcutsHelpOpen: (open: boolean) => void;
  toast: ToastMessage | null;
  showToast: (message: string, icon?: string) => void;
}

export interface AppContextValue extends 
  NavigationContextValue, 
  CurrencyContextValue, 
  ThemeContextValue, 
  MiniDashContextValue,
  SimplifiedModeContextValue,
  FocusModeContextValue,
  TabVisibilityContextValue,
  ModalsContextValue {}

const AppContext = createContext<AppContextValue | null>(null);

const STORAGE_KEYS = {
  CURRENCY: 'open3dcalc_pref_currency',
  THEME: 'open3dcalc_pref_theme',
  SECTION: 'open3dcalc_pref_section',
  LAYOUT: 'open3dcalc_pref_calc_layout',
  MINI_DASH_PINNED: 'open3dcalc_pref_minidash_pinned',
  SIMPLIFIED_MODE: 'open3dcalc_pref_simplified_mode',
  FOCUS_MODE: 'open3dcalc_pref_focus_mode',
  VISIBLE_TABS: 'open3dcalc_pref_visible_tabs'
};

interface AppProviderProps {
  children: ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  // Navigation State
  const [currentSection, setCurrentSection] = useState<AppSection>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.SECTION) as AppSection;
      if (saved && ['pricing', 'dashboard', 'history', 'printers', 'spools', 'infill', 'clients'].includes(saved)) {
        return saved;
      }
    } catch {
      // fallback
    }
    return 'pricing';
  });

  const [calculatorLayout, setCalculatorLayout] = useState<CalculatorLayoutVariant>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.LAYOUT) as CalculatorLayoutVariant;
      if (saved && ['classic', 'wizard', 'bento'].includes(saved)) {
        return saved;
      }
    } catch {
      // fallback
    }
    return 'bento';
  });

  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);

  // Currency State
  const [currency, setCurrencyState] = useState<CurrencyCode>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.CURRENCY) as CurrencyCode;
      if (saved && ['BRL', 'USD', 'EUR'].includes(saved)) {
        return saved;
      }
    } catch {
      // fallback
    }
    return 'BRL';
  });

  // Theme State
  const [theme, setThemeState] = useState<AppTheme>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.THEME) as AppTheme;
      if (saved && ['dark', 'midnight', 'light'].includes(saved)) {
        return saved;
      }
    } catch {
      // fallback
    }
    return 'dark';
  });

  // Mini-Dash Summary Overlay State
  const [isMiniDashOpen, setIsMiniDashOpen] = useState<boolean>(false);
  const [isMiniDashPinned, setIsMiniDashPinned] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEYS.MINI_DASH_PINNED) === 'true';
    } catch {
      return false;
    }
  });

  // Simplified / Focus Mode
  const [isSimplifiedMode, setIsSimplifiedModeState] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEYS.SIMPLIFIED_MODE) === 'true';
    } catch {
      return false;
    }
  });

  const setIsSimplifiedMode = (simplified: boolean) => {
    setIsSimplifiedModeState(simplified);
    try {
      localStorage.setItem(STORAGE_KEYS.SIMPLIFIED_MODE, String(simplified));
    } catch (e) {
      console.warn('Could not persist simplified mode', e);
    }
  };

  const toggleSimplifiedMode = () => {
    setIsSimplifiedMode(!isSimplifiedMode);
    showToast(
      !isSimplifiedMode ? 'Modo Simplificado ativado' : 'Modo Estúdio Completo ativado',
      !isSimplifiedMode ? '⚡' : '🚀'
    );
  };

  // Focus Mode State
  const [isFocusMode, setIsFocusModeState] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEYS.FOCUS_MODE) === 'true';
    } catch {
      return false;
    }
  });

  const setIsFocusMode = (focus: boolean) => {
    setIsFocusModeState(focus);
    if (focus) {
      setCurrentSection('pricing');
      setIsHistorySidebarOpen(false);
    }
    try {
      localStorage.setItem(STORAGE_KEYS.FOCUS_MODE, String(focus));
    } catch (e) {
      console.warn('Could not persist focus mode', e);
    }
  };

  const toggleFocusMode = () => {
    const next = !isFocusMode;
    setIsFocusMode(next);
    showToast(
      next ? 'Modo Foco Ativado: Distrações ocultadas' : 'Modo Foco Desativado',
      next ? '🎯' : '🔓'
    );
  };

  // Tab Visibility Manager State
  const [visibleTabs, setVisibleTabsState] = useState<VisibleTabsState>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.VISIBLE_TABS);
      if (saved) {
        return { ...DEFAULT_VISIBLE_TABS, ...JSON.parse(saved) };
      }
    } catch {
      // fallback
    }
    return DEFAULT_VISIBLE_TABS;
  });

  const setVisibleTabs = (tabs: VisibleTabsState) => {
    setVisibleTabsState(tabs);
    try {
      localStorage.setItem(STORAGE_KEYS.VISIBLE_TABS, JSON.stringify(tabs));
    } catch (e) {
      console.warn('Could not persist visible tabs', e);
    }
  };

  const toggleTabVisibility = (section: AppSection) => {
    const nextTabs = {
      ...visibleTabs,
      [section]: !visibleTabs[section]
    };
    if (!nextTabs.pricing) {
      nextTabs.pricing = true;
    }
    setVisibleTabs(nextTabs);
  };

  const resetTabVisibility = () => {
    setVisibleTabs(DEFAULT_VISIBLE_TABS);
    showToast('Visibilidade de abas restaurada ao padrão', '🔄');
  };

  const [isVisibilityManagerOpen, setIsVisibilityManagerOpen] = useState(false);

  // Modals state
  const [isQuoteModalOpen, setIsQuoteModalOpen] = useState(false);
  const [isAICopilotOpen, setIsAICopilotOpen] = useState(false);
  const [isHistorySidebarOpen, setIsHistorySidebarOpen] = useState(false);
  const [isInfillModalOpen, setIsInfillModalOpen] = useState(false);
  const [isClientsModalOpen, setIsClientsModalOpen] = useState(false);
  const [isShortcutsHelpOpen, setIsShortcutsHelpOpen] = useState(false);

  // Global Toast Feedback for hotkeys and actions
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const showToast = (message: string, icon?: string) => {
    const id = Date.now();
    setToast({ id, message, icon });
    setTimeout(() => {
      setToast(prev => (prev?.id === id ? null : prev));
    }, 2400);
  };

  // Sync section to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.SECTION, currentSection);
    } catch (e) {
      console.warn('Could not persist section', e);
    }
  }, [currentSection]);

  // Sync layout to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.LAYOUT, calculatorLayout);
    } catch (e) {
      console.warn('Could not persist layout', e);
    }
  }, [calculatorLayout]);

  // Sync currency to localStorage
  const setCurrency = (newCurrency: CurrencyCode) => {
    setCurrencyState(newCurrency);
    try {
      localStorage.setItem(STORAGE_KEYS.CURRENCY, newCurrency);
    } catch (e) {
      console.warn('Could not persist currency', e);
    }
  };

  // Sync theme to localStorage and DOM element
  const setTheme = (newTheme: AppTheme) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem(STORAGE_KEYS.THEME, newTheme);
    } catch (e) {
      console.warn('Could not persist theme', e);
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    if (theme === 'light') {
      root.classList.add('theme-light');
      root.classList.remove('theme-midnight');
    } else if (theme === 'midnight') {
      root.classList.add('theme-midnight');
      root.classList.remove('theme-light');
    } else {
      root.classList.remove('theme-light', 'theme-midnight');
    }
  }, [theme]);

  // Sync MiniDash pinned state
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.MINI_DASH_PINNED, String(isMiniDashPinned));
    } catch (e) {
      console.warn('Could not persist mini-dash pinned', e);
    }
  }, [isMiniDashPinned]);

  const toggleSidebar = () => setIsSidebarCollapsed(prev => !prev);
  const setSidebarCollapsed = (collapsed: boolean) => setIsSidebarCollapsed(collapsed);
  const navigateTo = (section: AppSection) => setCurrentSection(section);

  const toggleTheme = () => {
    const nextTheme: AppTheme = theme === 'dark' ? 'midnight' : theme === 'midnight' ? 'light' : 'dark';
    setTheme(nextTheme);
  };

  const toggleMiniDash = () => setIsMiniDashOpen(prev => !prev);
  const toggleMiniDashPinned = () => setIsMiniDashPinned(prev => !prev);

  const formatCurrency = useMemo(() => {
    return (amount: number) => formatCurrencyUtil(amount, currency);
  }, [currency]);

  const currencySymbol = useMemo(() => {
    switch (currency) {
      case 'USD': return '$';
      case 'EUR': return '€';
      case 'BRL':
      default: return 'R$';
    }
  }, [currency]);

  const value: AppContextValue = {
    // Navigation
    currentSection,
    setCurrentSection,
    calculatorLayout,
    setCalculatorLayout,
    isSidebarCollapsed,
    toggleSidebar,
    setSidebarCollapsed,
    navigateTo,
    // Currency
    currency,
    setCurrency,
    formatCurrency,
    currencySymbol,
    // Theme
    theme,
    setTheme,
    toggleTheme,
    // Mini-Dash
    isMiniDashOpen,
    setIsMiniDashOpen,
    toggleMiniDash,
    isMiniDashPinned,
    setIsMiniDashPinned,
    toggleMiniDashPinned,
    // Simplified Mode
    isSimplifiedMode,
    setIsSimplifiedMode,
    toggleSimplifiedMode,
    // Focus Mode
    isFocusMode,
    setIsFocusMode,
    toggleFocusMode,
    // Tab Visibility
    visibleTabs,
    setVisibleTabs,
    toggleTabVisibility,
    resetTabVisibility,
    isVisibilityManagerOpen,
    setIsVisibilityManagerOpen,
    // Modals & Feedback
    isQuoteModalOpen,
    setIsQuoteModalOpen,
    isAICopilotOpen,
    setIsAICopilotOpen,
    isHistorySidebarOpen,
    setIsHistorySidebarOpen,
    isInfillModalOpen,
    setIsInfillModalOpen,
    isClientsModalOpen,
    setIsClientsModalOpen,
    isShortcutsHelpOpen,
    setIsShortcutsHelpOpen,
    toast,
    showToast
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

// Ergonomic Custom Hooks
export const useAppContext = (): AppContextValue => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
};

export const useNavigation = () => {
  const { 
    currentSection, 
    setCurrentSection, 
    calculatorLayout, 
    setCalculatorLayout, 
    isSidebarCollapsed, 
    toggleSidebar, 
    setSidebarCollapsed, 
    navigateTo 
  } = useAppContext();
  return { 
    currentSection, 
    setCurrentSection, 
    calculatorLayout, 
    setCalculatorLayout, 
    isSidebarCollapsed, 
    toggleSidebar, 
    setSidebarCollapsed, 
    navigateTo 
  };
};

export const useCurrencyPreference = () => {
  const { currency, setCurrency, formatCurrency, currencySymbol } = useAppContext();
  return { currency, setCurrency, formatCurrency, currencySymbol };
};

export const useThemeSetting = () => {
  const { theme, setTheme, toggleTheme } = useAppContext();
  return { theme, setTheme, toggleTheme };
};

export const useMiniDash = () => {
  const { 
    isMiniDashOpen, 
    setIsMiniDashOpen, 
    toggleMiniDash, 
    isMiniDashPinned, 
    setIsMiniDashPinned, 
    toggleMiniDashPinned 
  } = useAppContext();
  return { 
    isMiniDashOpen, 
    setIsMiniDashOpen, 
    toggleMiniDash, 
    isMiniDashPinned, 
    setIsMiniDashPinned, 
    toggleMiniDashPinned 
  };
};

export const useSimplifiedMode = () => {
  const { isSimplifiedMode, setIsSimplifiedMode, toggleSimplifiedMode } = useAppContext();
  return { isSimplifiedMode, setIsSimplifiedMode, toggleSimplifiedMode };
};

export const useFocusMode = () => {
  const { isFocusMode, setIsFocusMode, toggleFocusMode } = useAppContext();
  return { isFocusMode, setIsFocusMode, toggleFocusMode };
};

export const useTabVisibility = () => {
  const { 
    visibleTabs, 
    setVisibleTabs, 
    toggleTabVisibility, 
    resetTabVisibility, 
    isVisibilityManagerOpen, 
    setIsVisibilityManagerOpen 
  } = useAppContext();
  return { 
    visibleTabs, 
    setVisibleTabs, 
    toggleTabVisibility, 
    resetTabVisibility, 
    isVisibilityManagerOpen, 
    setIsVisibilityManagerOpen 
  };
};
