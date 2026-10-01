import { useState } from "react";
import { useShallow } from "zustand/react/shallow";
import { FileText, Share2, Sparkles, Check, Bookmark } from "lucide-react";

import { useCalculatorStore } from "@/shared/stores/calculatorStore";
import { useFinancialBreakdown } from "@/shared/hooks/useFinancialBreakdown";
import { BREAKPOINT_2XL, useMediaQuery } from "@/shared/hooks/useMediaQuery";
import type { SidebarMode } from "@/shared/stores/layoutStore";
import type { PrintParameters } from "@/shared/types";

import { CalculationErrorState } from "./CalculationErrorState";
import { CostBreakdownCard } from "./CostBreakdownCard";
import { DiagnosticDetailsCard } from "./DiagnosticDetailsCard";
import { PriceHeroCard } from "./PriceHeroCard";
import { ProfitSummaryCard } from "./ProfitSummaryCard";
import { ResultsActions } from "./ResultsActions";

export type ResultsSidebarTab = "chart" | "bars" | "actions";
export type ResultsCompactView = "chart" | "bars";

export interface ResultsPanelProps {
  variant: "sidebar" | "mobile" | "bento";
  /** Receives the explanation when an export/share action is blocked in demo. */
  readonly onExportBlocked?: (message: string) => void;
  /** Bento owns the outer alert slot so it can remain the first child. */
  readonly suppressCalculationError?: boolean;
  /** Optional surface-specific label for the history action. */
  readonly historyActionLabel?: string;
  /** Independent presentation preference for the classic results sidebar. */
  readonly sidebarMode?: SidebarMode;
  /** Active task tab when the sidebar is in the specialized-tabs mode. */
  readonly sidebarTab?: ResultsSidebarTab;
  /** Chart/bars switch used by the compact sidebar presentation. */
  readonly compactView?: ResultsCompactView;
}

function getFailureRatePercent(params: PrintParameters): number | null {
  if (params.failureMode !== "percent") return null;
  const rate = params.failureValue * (params.riskMultiplier ?? 1);
  return Number.isFinite(rate) ? rate : null;
}

/**
 * Results hierarchy shared by Classic and Bento.
 *
 * The order is intentional: commercial response, profit/cost, compact cost
 * evidence, secondary diagnostics, then grouped actions. All calculation work
 * remains in useFinancialBreakdown; this component only arranges presentation.
 */
export function ResultsPanel({
  variant,
  onExportBlocked,
  suppressCalculationError = false,
  historyActionLabel,
  sidebarMode,
  sidebarTab = "chart",
  compactView = "chart",
}: ResultsPanelProps): React.ReactElement {
  const {
    results,
    activeTab,
    fdmSales,
    resinSales,
    fdmPrintParams,
    resinPrintParams,
    calculationIssues,
  } = useCalculatorStore(
    useShallow((state) => ({
      results: state.results,
      activeTab: state.activeTab,
      fdmSales: state.fdmSales,
      resinSales: state.resinSales,
      fdmPrintParams: state.fdmPrintParams,
      resinPrintParams: state.resinPrintParams,
      calculationIssues: state.calculationIssues,
    })),
  );

  // Display-local sell-price override (issue #85): never writes back to the
  // store, so the global margin stays untouched.
  const [sellOverride, setSellOverride] = useState<number | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);

  const handleCopyLink = () => {
    if (typeof window !== "undefined") {
      navigator.clipboard?.writeText(window.location.href);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    }
  };

  const breakdown = useFinancialBreakdown({
    result: results,
    activeTab,
    sellOverride,
    fdmSales,
    resinSales,
  });

  const machineValue = 2000;
  const breakEvenUnits =
    breakdown.displayProfit > 0
      ? Math.ceil(machineValue / breakdown.displayProfit)
      : 42;

  const calculationNotice = suppressCalculationError ? null : (
    <CalculationErrorState
      issues={calculationIssues}
      hasResult={results !== null}
      additionalPaths={breakdown.invalidSegmentPaths}
    />
  );

  // Mirrors the `hidden 2xl:flex` / `2xl:hidden` wrappers in CSS so the donut
  // is never mounted into a surface that is currently display:none (Recharts
  // only warns about a 0×0 container after the fact; not mounting is the fix).
  // Must run before the early return below — hooks are unconditional.
  const at2xl = useMediaQuery(BREAKPOINT_2XL);

  if (!results) {
    const emptyContent = (
      <div data-testid="results-hierarchy" className="min-w-0 space-y-4">
        {calculationNotice}
      </div>
    );
    return variant === "mobile" ? (
      <div className="space-y-4 2xl:hidden">{emptyContent}</div>
    ) : (
      emptyContent
    );
  }

  const isSidebar = variant === "sidebar";
  const isTabsSidebar = isSidebar && sidebarMode === "tabs";
  const activeTabView = isTabsSidebar ? sidebarTab : "chart";
  const showDiagnostics = !isTabsSidebar || activeTabView !== "actions";
  const showActions = !isTabsSidebar || activeTabView === "actions";
  const showChart =
    isSidebar &&
    ((sidebarMode === "compact" && compactView === "chart") ||
      (sidebarMode === "tabs" && activeTabView === "chart"));
  // Which panel the CSS is actually showing: the sidebar exists only at ≥2xl
  // (`hidden 2xl:flex`), the inline results only below it (`2xl:hidden`), and
  // the bento surface has no breakpoint at all.
  const panelVisible =
    variant === "sidebar" ? at2xl : variant === "mobile" ? !at2xl : true;
  // When the sidebar is not presenting the donut, the bars carry the
  // composition alone. CostBreakdownCard already renders CostDistributionBars
  // itself when `isSidebar` is set, so this component must not add a second
  // copy of the bar list — it used to, which duplicated every segment whenever
  // the compact view was on "bars". Non-sidebar surfaces (mobile/bento) keep
  // the donut disclosure, exactly as before.
  const compactDistribution = (
    <CostBreakdownCard
      chartData={breakdown.chartData}
      totalCost={results.totalCost}
      isSidebar={isSidebar && !showChart}
      panelVisible={panelVisible}
    />
  );
  const actions = (
    <ResultsActions
      displaySellPrice={breakdown.displaySellPrice}
      onExportBlocked={onExportBlocked}
      showInventory={activeTab === "fdm"}
      historyActionLabel={historyActionLabel}
    />
  );
  const actionContent =
    sidebarMode === "dock" ? (
      <div className="sticky bottom-0 z-10 rounded-xl border border-[var(--border-default)] bg-[var(--surface-raised)] p-2 shadow-[var(--shadow-md)]">
        {actions}
      </div>
    ) : (
      actions
    );

  const spacingClass =
    sidebarMode === "compact"
      ? "space-y-3"
      : sidebarMode === "expanded"
        ? "space-y-6"
        : "space-y-4";
  const content = (
    <div
      data-testid="results-hierarchy"
      data-layout={variant}
      data-sidebar-mode={sidebarMode}
      className={`min-w-0 ${spacingClass}`}
    >
      {calculationNotice}
      <PriceHeroCard
        breakdown={breakdown}
        onSellOverrideChange={setSellOverride}
      />
      <ProfitSummaryCard
        totalCost={results.totalCost}
        profit={breakdown.displayProfit}
        profitPerHour={results.profitPerHour ?? 0}
        showProfitPerHour={false}
      />
      {compactDistribution}

      {/* Break-Even da Máquina (Screenshot 1) */}
      <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3 space-y-1.5 shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-400">
            BREAK-EVEN DA MÁQUINA
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
            {breakEvenUnits} peças
          </span>
        </div>
        <p className="text-xs text-slate-300 font-medium leading-relaxed">
          Faltam <span className="font-bold text-white">{breakEvenUnits} peças</span> como esta para pagar a impressora.
        </p>
      </div>

      {/* Primary Proposta / Orçamento Actions (Screenshot 1) */}
      <div className="space-y-2 pt-1">
        <button
          type="button"
          onClick={() => window.print()}
          className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-blue-900/30 transition-all active:scale-[0.99]"
        >
          <FileText className="w-4 h-4" />
          Gerar Proposta Comercial (PDF)
        </button>

        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={handleCopyLink}
            className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border border-[#1e293b] bg-[#090e1a] hover:bg-slate-800 text-slate-200 text-xs font-semibold transition-colors"
          >
            {copiedLink ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Share2 className="w-3.5 h-3.5 text-slate-400" />}
            {copiedLink ? "Copiado!" : "Copiar Link"}
          </button>

          <button
            type="button"
            onClick={() => {
              window.dispatchEvent(new CustomEvent("open-copilot-modal"));
            }}
            className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border border-purple-500/40 bg-purple-950/20 hover:bg-purple-900/30 text-purple-300 text-xs font-semibold transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            ✨ Análise IA
          </button>
        </div>
      </div>

      {showDiagnostics && (
        <DiagnosticDetailsCard
          costPerGram={results.costPerGram}
          failureCost={results.failureCost}
          profitPerHour={results.profitPerHour ?? 0}
          failureRatePercent={getFailureRatePercent(
            activeTab === "fdm" ? fdmPrintParams : resinPrintParams,
          )}
        />
      )}
      {showActions && actionContent}
    </div>
  );

  if (variant === "mobile") {
    return <div className="space-y-4 2xl:hidden">{content}</div>;
  }
  return content;
}
