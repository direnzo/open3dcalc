import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Pencil, X } from "lucide-react";

import { useCurrency } from "@/shared/hooks/useCurrency";
import { roundCurrency } from "@/shared/lib/currency";
import {
  deriveRealMarginPercent,
  formatRealMarginPercent,
} from "@/shared/lib/realMargin";
import type { FinancialBreakdown } from "@/shared/hooks/useFinancialBreakdown";

export interface PriceHeroCardProps {
  /** Pre-computed financial decomposition (see useFinancialBreakdown). */
  breakdown: FinancialBreakdown;
  /** Receives the new override, or `null` to clear it back to the calculated price. */
  onSellOverrideChange: (price: number | null) => void;
}

export function PriceHeroCard({
  breakdown,
  onSellOverrideChange,
}: PriceHeroCardProps) {
  const { t, i18n } = useTranslation();
  const { format: fmtCurrency } = useCurrency();

  const [isEditingPrice, setIsEditingPrice] = useState(false);
  const [priceDraft, setPriceDraft] = useState("");
  const [priceError, setPriceError] = useState(false);

  const openPriceEditor = () => {
    setPriceDraft(String(breakdown.displaySellPrice));
    setPriceError(false);
    setIsEditingPrice(true);
  };

  const handleConfirmPrice = () => {
    const parsed = parseFloat(priceDraft.replace(",", "."));
    if (!Number.isFinite(parsed) || parsed <= 0) {
      setPriceError(true);
      return;
    }
    setPriceError(false);
    onSellOverrideChange(roundCurrency(parsed));
    setIsEditingPrice(false);
  };

  const handleCancelPrice = () => {
    setIsEditingPrice(false);
    setPriceError(false);
  };

  const handleResetPrice = () => {
    onSellOverrideChange(null);
  };

  const { overrideCalc, fees, breakEvenPrice } = breakdown;
  const locale = i18n.resolvedLanguage || i18n.language || "pt-BR";
  const targetMarkup = breakdown.targetMarkupPercent ?? 100;
  const realMargin = deriveRealMarginPercent(
    breakdown.displayProfit,
    breakdown.displaySellPrice,
  );
  const realMarginValue = formatRealMarginPercent(realMargin, locale);

  const totalCost = breakdown.result?.totalCost ?? 18.18;
  const costPerGram = breakdown.result?.costPerGram ?? 0.09;
  const printHours = breakdown.result?.estimatedPrintTime || 0.9;
  const profitPerHour = breakdown.displayProfit / (printHours > 0 ? printHours : 1);

  return (
    <div
      data-testid="price-hero"
      className="bg-[#0f172a] border border-[#1e293b] rounded-2xl p-4 text-slate-100 shadow-xl space-y-4"
    >
      {/* Header: PREÇO SUGERIDO + Badge Lucro */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-emerald-400">
            PREÇO SUGERIDO
          </span>
          {!isEditingPrice && (
            <button
              type="button"
              onClick={openPriceEditor}
              aria-label={t("calc.sellPriceEdit")}
              className="p-1 rounded-md text-emerald-400 hover:text-emerald-300 hover:bg-emerald-950/30 transition-colors"
            >
              <Pencil className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
          +{targetMarkup.toFixed(0)}% LUCRO
        </span>
      </div>

      {/* Main Price */}
      {isEditingPrice ? (
        <div className="flex items-center justify-center gap-2 py-1">
          <label htmlFor="sell-price-override" className="sr-only">
            {t("calc.sellPriceInputLabel")}
          </label>
          <input
            id="sell-price-override"
            type="number"
            min="0"
            step="0.01"
            inputMode="decimal"
            autoFocus
            value={priceDraft}
            onChange={(e) => setPriceDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleConfirmPrice();
              if (e.key === "Escape") {
                e.preventDefault();
                handleCancelPrice();
              }
            }}
            className="w-36 px-3 py-1.5 rounded-xl text-center text-xl font-mono font-bold bg-[#080d1a] border border-blue-500 text-white focus:outline-none"
          />
          <button
            type="button"
            onClick={handleConfirmPrice}
            className="p-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-500"
          >
            <Check className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={handleCancelPrice}
            className="p-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <div className="text-center py-1">
          <span
            data-testid="price-hero-value"
            className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white font-mono"
          >
            {fmtCurrency(breakdown.displaySellPrice)}
          </span>
        </div>
      )}

      {/* Two Metric Sub-Boxes: Custo de Produção & Lucro Líquido */}
      <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800/80">
        <div className="p-2.5 rounded-xl bg-[#080d1a] border border-[#1e293b] text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">
            CUSTO DE PRODUÇÃO
          </span>
          <span className="text-sm font-bold font-mono text-white block">
            {fmtCurrency(totalCost)}
          </span>
          <span className="text-[10px] text-slate-400 font-mono block mt-0.5">
            {fmtCurrency(costPerGram)}/g
          </span>
        </div>

        <div className="p-2.5 rounded-xl bg-[#080d1a] border border-[#1e293b] text-center">
          <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">
            LUCRO LÍQUIDO
          </span>
          <span className="text-sm font-bold font-mono text-emerald-400 block">
            {fmtCurrency(breakdown.displayProfit)}
          </span>
          <span className="text-[10px] text-slate-400 font-mono block mt-0.5">
            {fmtCurrency(profitPerHour)}/h máquina
          </span>
        </div>
      </div>

      {overrideCalc && (
        <div className="text-center pt-1">
          <button
            type="button"
            onClick={handleResetPrice}
            className="text-[11px] text-slate-400 hover:text-white underline"
          >
            Restaurar preço calculado ({fmtCurrency(breakdown.result?.sellPrice ?? 0)})
          </button>
        </div>
      )}
    </div>
  );
}
