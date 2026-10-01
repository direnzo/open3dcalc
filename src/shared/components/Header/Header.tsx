import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Box,
  Sparkles,
  Maximize2,
  Minimize2,
  Activity,
  Layers,
  LayoutGrid,
  ListOrdered,
  Calculator as CalculatorIcon,
  BarChart3,
  Clock,
  Printer,
  Spool,
  Sliders,
  Focus,
  HelpCircle,
  Plus,
  MessageCircle,
} from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useCalculatorStore } from "@/shared/stores/calculatorStore";
import { TutorialLauncher } from "@/shared/components/ui/TutorialLauncher";
import { useCurrency } from "@/shared/hooks/useCurrency";
import { ThemeToggle } from "./ThemeToggle";
import { BetaBadge } from "@/shared/components/BetaBadge/BetaBadge";
import { DemoModeButton } from "@/shared/components/DemoMode/DemoModeButton";
import { LayoutSwitcher } from "./LayoutSwitcher";
import { ContextBreadcrumb } from "./ContextBreadcrumb";
import { CurrencySelect } from "@/shared/components/UtilityBar/CurrencySelect";
import { LanguageToggle } from "@/shared/components/UtilityBar/LanguageToggle";
import { useNavigationPrefsStore } from "@/shared/stores/navigationPrefsStore";
import { useLayoutStore } from "@/shared/stores/layoutStore";
import { useHistoryStore } from "@/shared/stores/historyStore";
import { useSpoolStore } from "@/shared/stores/spoolStore";
import { AIAssistantModal } from "@/shared/components/AIAssistant/AIAssistantModal";

const PRESET_MODELS = [
  {
    name: "Suporte Articulado Dobrável",
    type: "tpu_95a",
    costPerKg: 90,
    weight: 55,
    hours: 0,
    minutes: 54,
    power: 250,
    kwh: 0.95,
    extras: 2.2,
    margin: 100,
    hourlyRate: 25,
  },
  {
    name: "Engrenagem Helicoidal Dupla",
    type: "petg",
    costPerKg: 149,
    weight: 120,
    hours: 2,
    minutes: 15,
    power: 280,
    kwh: 0.95,
    extras: 4.5,
    margin: 80,
    hourlyRate: 30,
  },
  {
    name: "Gabinete Eletrônico Modular",
    type: "abs",
    costPerKg: 130,
    weight: 85,
    hours: 1,
    minutes: 40,
    power: 320,
    kwh: 0.95,
    extras: 6.0,
    margin: 120,
    hourlyRate: 28,
  },
  {
    name: "Vaso Geométrico Voronoi",
    type: "pla_silk",
    costPerKg: 145,
    weight: 210,
    hours: 4,
    minutes: 20,
    power: 220,
    kwh: 0.95,
    extras: 1.5,
    margin: 150,
    hourlyRate: 25,
  },
];

export function Header() {
  const { t } = useTranslation();
  const { currency: currencySetting, setCurrency } = useCalculatorStore(
    useShallow((s) => ({ currency: s.currency, setCurrency: s.setCurrency })),
  );
  const { format } = useCurrency();
  const activeTab = useNavigationPrefsStore((state) => state.activeTab);
  const setActiveTab = useNavigationPrefsStore((state) => state.setActiveTab);
  const historyEntries = useHistoryStore((s) => s.entries);
  const lowStockCount = useSpoolStore((s) => s.getLowStockSpools(100).length);
  const { layoutMode, setLayoutMode } = useLayoutStore(
    useShallow((s) => ({
      layoutMode: s.layoutMode,
      setLayoutMode: s.setLayoutMode,
    })),
  );
  const calcStore = useCalculatorStore();

  const [showCopilotModal, setShowCopilotModal] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const handleOpenCopilot = () => setShowCopilotModal(true);
    window.addEventListener("open-copilot-modal", handleOpenCopilot);
    return () =>
      window.removeEventListener("open-copilot-modal", handleOpenCopilot);
  }, []);

  const [selectedModel, setSelectedModel] = useState(
    calcStore.productName || "Suporte Articulado Dobrável",
  );

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
      setIsFullscreen(true);
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
      }
      setIsFullscreen(false);
    }
  };

  const handleSelectModel = (name: string) => {
    setSelectedModel(name);
    const preset = PRESET_MODELS.find((m) => m.name === name);
    if (preset) {
      calcStore.setField("productName", preset.name);
      calcStore.setField("activeTab", "fdm");
      calcStore.setFdmMaterial("type", preset.type);
      calcStore.setFdmMaterial("costPerKg", preset.costPerKg);
      calcStore.setFdmMaterial("printWeightGrams", preset.weight);
      calcStore.setFdmPrintParams("printTimeHours", preset.hours);
      calcStore.setFdmPrintParams("printTimeMinutes", preset.minutes);
      calcStore.setFdmMachine("powerWatts", preset.power);
      calcStore.setFdmMachine("kwhCost", preset.kwh);
      calcStore.setFdmExtras("packagingCost", preset.extras);
      calcStore.setFdmLabor("hourlyRate", preset.hourlyRate);
      calcStore.setFdmSales("targetMarginPercent", preset.margin);
      calcStore.recomputeResults();
    }
  };

  const results = calcStore?.results;
  const suggestedPriceFormatted = results
    ? format(results.sellPrice)
    : "R$ 42,27";
  const costFormatted = results ? format(results.totalCost) : "R$ 18,18";

  const generateWhatsAppMessage = () => {
    const hours = calcStore?.fdmPrintParams?.printTimeHours ?? 0;
    const minutes = calcStore?.fdmPrintParams?.printTimeMinutes ?? 45;
    const name = calcStore?.productName || "Peça 3D";
    const text =
      `*Orçamento - Open3DCalc Studio*\n` +
      `Projeto: *${name}*\n` +
      `Tempo estimado: ${hours}h ${minutes}m\n` +
      `Custo de Produção: ${costFormatted}\n` +
      `*Valor Sugerido: ${suggestedPriceFormatted}*\n\n` +
      `Proposta emitida via Open3DCalc.`;
    return encodeURIComponent(text);
  };

  return (
    <>
      <header
        className="sticky top-0 z-30 border-b select-none transition-colors border-[#1e293b] bg-[#0b1120] text-slate-200"
        style={{
          background: "var(--color-bg-primary, #0b1120)",
          borderColor: "var(--color-border, #1e293b)",
        }}
      >
        {/* ── SINGLE MODERN HEADER BAR (h-[68px]) ── */}
        <div className="max-w-[1920px] mx-auto min-w-0 px-3 sm:px-6 h-[68px] min-h-[68px] flex items-center justify-between gap-3 text-xs">
          {/* Left: Brand + Breadcrumb */}
          <div className="flex items-center gap-3 min-w-0">
            {/* Logo */}
            <button
              onClick={() => setActiveTab("calculator")}
              className="flex items-center gap-2 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg group shrink-0 min-h-[44px]"
              aria-label={t("app.title")}
            >
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-white shadow-md shadow-blue-900/40">
                <Box className="w-4 h-4" strokeWidth={2.5} />
              </div>
              <span className="font-extrabold text-[15px] sm:text-[16px] text-white tracking-tight flex items-center gap-1.5">
                {t("app.title")}
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/60 font-bold">
                  v2.5
                </span>
                <BetaBadge />
              </span>
            </button>

            <span className="hidden md:inline h-4 w-px bg-slate-800 shrink-0" />

            {/* ContextBreadcrumb */}
            <ContextBreadcrumb tab={activeTab} />
          </div>

          {/* Center: Mode switcher (Clássico / Bento / Guiado) */}
          <div className="hidden lg:flex items-center gap-2">
            {activeTab === "calculator" ? (
              <div className="flex items-center gap-1.5 bg-[#070b14] border border-[#1e293b] p-1 rounded-xl">
                <span className="text-[10px] font-mono uppercase font-bold text-slate-400 px-2">
                  MODO:
                </span>
                <button
                  type="button"
                  onClick={() => setLayoutMode("classic")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                    layoutMode === "classic"
                      ? "bg-blue-600 text-white shadow-sm"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  Clássico
                </button>
                <button
                  type="button"
                  onClick={() => setLayoutMode("bento")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                    layoutMode === "bento"
                      ? "bg-blue-600 text-white shadow-sm"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                  Bento
                </button>
                <button
                  type="button"
                  onClick={() => setLayoutMode("guided")}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                    layoutMode === "guided"
                      ? "bg-blue-600 text-white shadow-sm"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                  }`}
                >
                  <ListOrdered className="w-3.5 h-3.5" />
                  Guiado
                </button>
              </div>
            ) : (
              <span className="text-xs font-medium text-slate-400 tracking-wide">
                Open3DCalc Studio
              </span>
            )}
          </div>

          {/* Right: Model Selector + WhatsApp + Copilot + Utilities */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            {/* Model Preset Selector */}
            {activeTab === "calculator" && (
              <div className="hidden xl:flex items-center gap-1.5 bg-[#090e1a] border border-[#1e293b] rounded-lg px-2.5 py-1 text-xs min-h-[36px]">
                <span className="text-slate-400 font-medium">Modelo:</span>
                <select
                  value={selectedModel}
                  onChange={(e) => handleSelectModel(e.target.value)}
                  className="bg-transparent text-white font-medium focus:outline-none cursor-pointer pr-2"
                >
                  {PRESET_MODELS.map((m) => (
                    <option
                      key={m.name}
                      value={m.name}
                      className="bg-slate-900 text-white"
                    >
                      {m.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Proposta WhatsApp button */}
            <a
              href={`https://wa.me/?text=${generateWhatsAppMessage()}`}
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/60 text-emerald-400 bg-emerald-950/20 hover:bg-emerald-900/40 text-xs font-semibold transition-colors shadow-sm min-h-[36px]"
              title="Gerar proposta rápida formatada para WhatsApp"
            >
              <MessageCircle className="w-3.5 h-3.5" />
              <span>Proposta WhatsApp</span>
            </a>

            {/* Copilot IA button */}
            <button
              type="button"
              data-testid="copilot-btn"
              onClick={() => setShowCopilotModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-blue-500/40 bg-gradient-to-r from-blue-900/40 to-indigo-900/40 hover:from-blue-900/60 hover:to-indigo-900/60 text-blue-300 text-xs font-semibold transition-colors min-h-[36px]"
              title="Abrir Copilot de Inteligência Artificial para diagnóstico da peça"
            >
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              <span>Copilot IA</span>
            </button>

            {/* Currency Select */}
            <CurrencySelect
              setting={currencySetting}
              onChange={setCurrency}
            />

            {/* Language Toggle */}
            <LanguageToggle />

            {/* Demo Mode Button */}
            <DemoModeButton />

            {/* Tutorial Launcher */}
            <TutorialLauncher />

            {/* Theme Toggle */}
            <ThemeToggle />

            {/* Fullscreen Toggle */}
            <button
              type="button"
              onClick={toggleFullscreen}
              aria-label="Alternar tela cheia"
              title="Tela cheia"
              className="hidden sm:inline-flex items-center justify-center w-8 h-8 rounded-lg border border-[#1e293b] hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              {isFullscreen ? (
                <Minimize2 className="w-3.5 h-3.5" />
              ) : (
                <Maximize2 className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* ── COPILOT IA MODAL (WITH OPTIONAL GEMINI KEY BYOK) ── */}
      <AIAssistantModal
        open={showCopilotModal}
        onClose={() => setShowCopilotModal(false)}
      />
    </>
  );
}
