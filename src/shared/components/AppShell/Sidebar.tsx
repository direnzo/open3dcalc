import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import {
  Calculator as CalculatorIcon,
  BarChart3,
  Clock,
  Printer,
  Spool,
  Grid3x3,
  Users,
  BookOpen,
  Info,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Send,
  Boxes,
} from "lucide-react";
import { BrandIcon } from "@/platform/web/BrandIcon";
import { useHistoryStore } from "@/shared/stores/historyStore";
import { useCalculatorStore } from "@/shared/stores/calculatorStore";
import { useLayoutStore } from "@/shared/stores/layoutStore";
import type { Tab } from "./tabs";

interface SidebarProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  footer?: ReactNode;
  tabletInactiveHoverClassName?: string;
}

export function TabletSidebar({
  activeTab,
  onTabChange,
  tabletInactiveHoverClassName,
}: Omit<SidebarProps, "footer">): React.ReactElement {
  const { t } = useTranslation();
  const historyCount = useHistoryStore((s) => s.entries.length);

  const navItems: Array<{ id: Tab; icon: React.ReactNode; label: string }> = [
    { id: "calculator", icon: <CalculatorIcon className="w-4 h-4" />, label: "Calculadora 3D" },
    { id: "dashboard", icon: <BarChart3 className="w-4 h-4" />, label: "Dashboard" },
    { id: "infill", icon: <Grid3x3 className="w-4 h-4" />, label: "Calc. Infill" },
    { id: "inventory", icon: <Spool className="w-4 h-4" />, label: "Carretéis & Filamentos" },
    { id: "catalog", icon: <Printer className="w-4 h-4" />, label: "Frota de Impressoras" },
    { id: "history", icon: <Clock className="w-4 h-4" />, label: "Histórico & Pedidos" },
    { id: "customers", icon: <Users className="w-4 h-4" />, label: "Clientes" },
  ];

  return (
    <aside className="hidden md:flex lg:hidden flex-col gap-1 w-16 shrink-0 px-2 py-4 sticky top-[68px] h-[calc(100dvh-68px)] overflow-y-auto border-r border-[#1e293b] bg-[#0b1120]">
      <div className="flex flex-col gap-1">
        {navItems.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onTabChange(item.id)}
            aria-current={activeTab === item.id ? "page" : undefined}
            className={`w-full flex items-center justify-center p-2.5 rounded-xl transition-all ${
              activeTab === item.id
                ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                : `text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent`
            }`}
            title={item.label}
          >
            {item.icon}
          </button>
        ))}
      </div>
    </aside>
  );
}

export function DesktopSidebar({
  activeTab,
  onTabChange,
}: SidebarProps): React.ReactElement {
  const { t } = useTranslation();
  const historyCount = useHistoryStore((s) => s.entries.length);
  const layoutMode = useLayoutStore((s) => s.layoutMode);
  const currency = useCalculatorStore((s) => s.currency);
  const setCurrency = useCalculatorStore((s) => s.setCurrency);
  const calcStore = useCalculatorStore();
  const [collapsed, setCollapsed] = useState(false);

  const modules = [
    {
      id: "calculator" as Tab,
      icon: <CalculatorIcon className="w-4 h-4" />,
      label: "Calculadora 3D",
      badge: layoutMode === "classic" ? "Clássico" : layoutMode === "bento" ? "Bento" : "Guiado",
    },
    {
      id: "dashboard" as Tab,
      icon: <BarChart3 className="w-4 h-4" />,
      label: "Dashboard",
    },
    {
      id: "infill" as Tab,
      icon: <Grid3x3 className="w-4 h-4" />,
      label: "Calc. Infill",
    },
    {
      id: "inventory" as Tab,
      icon: <Spool className="w-4 h-4" />,
      label: "Carretéis & Filamentos",
    },
    {
      id: "catalog" as Tab,
      icon: <Printer className="w-4 h-4" />,
      label: "Frota de Impressoras",
    },
    {
      id: "history" as Tab,
      icon: <Clock className="w-4 h-4" />,
      label: "Histórico & Pedidos",
      countBadge: historyCount > 0 ? historyCount : undefined,
    },
    {
      id: "customers" as Tab,
      icon: <Users className="w-4 h-4" />,
      label: "Clientes",
    },
  ];

  const handleLoadBenchy = () => {
    onTabChange("calculator");
    calcStore.setField("productName", "3DBenchy");
    calcStore.setField("activeTab", "fdm");
    calcStore.setFdmMaterial("type", "pla");
    calcStore.setFdmMaterial("costPerKg", 110);
    calcStore.setFdmMaterial("printWeightGrams", 13.5);
    calcStore.setFdmPrintParams("printTimeHours", 0);
    calcStore.setFdmPrintParams("printTimeMinutes", 42);
    calcStore.recomputeResults();
  };

  const handleShow3DViewer = () => {
    onTabChange("calculator");
    const dropzone = document.getElementById("dropzone-banner");
    if (dropzone) {
      dropzone.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  if (collapsed) {
    return (
      <aside className="hidden lg:flex flex-col gap-2 w-16 shrink-0 px-2 py-4 sticky top-[68px] h-[calc(100dvh-68px)] overflow-y-auto border-r border-[#1e293b] bg-[#0b1120]">
        <button
          onClick={() => setCollapsed(false)}
          className="p-2 text-slate-400 hover:text-white rounded-lg flex justify-center"
          title="Expandir Painel"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
        <div className="flex flex-col gap-1 mt-2">
          {modules.map((m) => (
            <button
              key={m.id}
              onClick={() => onTabChange(m.id)}
              className={`p-2.5 rounded-xl flex items-center justify-center transition-all ${
                activeTab === m.id
                  ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
              title={m.label}
            >
              {m.icon}
            </button>
          ))}
        </div>
      </aside>
    );
  }

  return (
    <aside className="hidden lg:flex flex-col justify-between w-60 xl:w-64 shrink-0 px-3 py-4 sticky top-[68px] h-[calc(100dvh-68px)] overflow-y-auto border-r border-[#1e293b] bg-[#0b1120] text-slate-300 text-xs select-none">
      <div className="space-y-6">
        {/* Section 1: MÓDULOS */}
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-500 px-3 mb-2">
            MÓDULOS
          </div>
          <div className="space-y-0.5">
            {modules.map((item) => {
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onTabChange(item.id)}
                  aria-current={active ? "page" : undefined}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-xl font-medium transition-all ${
                    active
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <span className={active ? "text-blue-400" : "text-slate-400"}>
                      {item.icon}
                    </span>
                    <span className="truncate">{item.label}</span>
                  </div>

                  {item.badge && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded font-mono bg-blue-950/80 text-blue-400 border border-blue-800/50">
                      {item.badge}
                    </span>
                  )}
                  {item.countBadge !== undefined && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded-full font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      {item.countBadge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Section 2: RECURSOS */}
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-500 px-3 mb-2">
            RECURSOS
          </div>
          <div className="space-y-0.5">
            <button
              type="button"
              onClick={() => onTabChange("wiki")}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-xl font-medium transition-all ${
                activeTab === "wiki"
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <BookOpen className="w-4 h-4" />
                <span>Documentação / Wiki</span>
              </div>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </button>

            <button
              type="button"
              onClick={() => onTabChange("changelog")}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-xl font-medium transition-all ${
                activeTab === "changelog"
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Info className="w-4 h-4" />
                <span>Notas de Versão</span>
              </div>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </button>

            <a
              href="https://github.com/ils15/open3dcalc"
              target="_blank"
              rel="noopener noreferrer"
              className="w-full flex items-center justify-between px-3 py-2 rounded-xl font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent transition-all"
            >
              <div className="flex items-center gap-2.5 truncate">
                <BrandIcon brand="github" className="w-4 h-4" />
                <span>Código no GitHub</span>
              </div>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </a>

            <a
              href="https://t.me/Impressao3DBR"
              target="_blank"
              rel="noopener noreferrer"
              className="w-full flex items-center justify-between px-3 py-2 rounded-xl font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent transition-all"
            >
              <div className="flex items-center gap-2.5 truncate">
                <BrandIcon brand="telegram" className="w-4 h-4" />
                <span>Comunidade Telegram</span>
              </div>
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </a>
          </div>
        </div>
      </div>

      {/* Bottom Area: Moeda Base, Recolher, Atalhos */}
      <div className="pt-4 border-t border-[#1e293b] space-y-3">
        {/* Moeda Base */}
        <div className="px-2 flex items-center justify-between">
          <span className="text-[11px] text-slate-400 font-medium">Moeda Base</span>
          <div className="flex items-center gap-1 font-mono text-[10px]">
            <span className="text-slate-500 font-bold mr-1">
              {currency === "BRL" ? "BRL" : currency}
            </span>
            {(["BRL", "USD", "EUR"] as const).map((curr) => {
              const active = currency === curr;
              const lbl = curr === "BRL" ? "R$" : curr === "USD" ? "$" : "€";
              return (
                <button
                  key={curr}
                  onClick={() => setCurrency(curr)}
                  className={`px-1.5 py-0.5 rounded font-bold transition-all ${
                    active ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  {lbl}
                </button>
              );
            })}
          </div>
        </div>

        {/* Recolher Painel Button */}
        <button
          type="button"
          onClick={() => setCollapsed(true)}
          className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1e293b] bg-[#090e1a] text-slate-400 hover:text-white hover:bg-slate-800 transition-colors text-[11px]"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
          <span>Recolher Painel</span>
        </button>

        {/* ATALHOS */}
        <div className="px-2 pt-1">
          <div className="text-[10px] font-mono uppercase font-bold text-slate-500 mb-1.5">
            ATALHOS
          </div>
          <div className="space-y-1 text-[11px] text-slate-400">
            <button
              type="button"
              onClick={handleLoadBenchy}
              className="flex items-center gap-1.5 hover:text-blue-400 transition-colors cursor-pointer w-full text-left"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
              Carregar Benchy
            </button>
            <button
              type="button"
              onClick={handleShow3DViewer}
              className="flex items-center gap-1.5 hover:text-blue-400 transition-colors cursor-pointer w-full text-left"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
              Exibir Visor 3D
            </button>
          </div>
        </div>
      </div>
    </aside>
  );
}
