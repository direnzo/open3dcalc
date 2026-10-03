import React from 'react';
import { 
  X, 
  Printer, 
  AlertTriangle, 
  ArrowUpRight 
} from 'lucide-react';
import { Tab } from '@/shared/components/AppShell/tabs';

interface StudioMiniDashOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  onTabChange: (tab: Tab) => void;
}

export const StudioMiniDashOverlay: React.FC<StudioMiniDashOverlayProps> = ({
  isOpen,
  onClose,
  onTabChange,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b0f19] border border-[#1e2a44] rounded-2xl w-full max-w-lg shadow-2xl p-5 flex flex-col gap-4 text-slate-100 animate-fade-up">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <h3 className="font-bold text-sm text-white">Mini-Dash & Visão Rápida da Oficina</h3>
          </div>
          <button 
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* 3 Main KPIs */}
        <div className="grid grid-cols-3 gap-2.5">
          <div className="bg-[#101726] border border-[#1e2a44] rounded-xl p-3">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">FATURAMENTO</span>
            <span className="text-sm font-extrabold text-white block mt-1">R$ 3.737,94</span>
            <span className="text-[10px] text-emerald-400 font-semibold flex items-center gap-0.5 mt-0.5">
              <ArrowUpRight className="w-2.5 h-2.5" /> 9 orçamentos
            </span>
          </div>

          <div className="bg-[#101726] border border-[#1e2a44] rounded-xl p-3">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">LUCRO LÍQUIDO</span>
            <span className="text-sm font-extrabold text-emerald-400 block mt-1">R$ 1.980,05</span>
            <span className="text-[10px] text-slate-400">Margem 53%</span>
          </div>

          <div className="bg-[#101726] border border-[#1e2a44] rounded-xl p-3">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">MÁQUINAS</span>
            <span className="text-sm font-extrabold text-blue-400 block mt-1">2 / 6</span>
            <span className="text-[10px] text-emerald-400 font-semibold">imprimindo</span>
          </div>
        </div>

        {/* Alerts & Quick Status */}
        <div className="flex flex-col gap-2">
          <span className="text-[11px] font-mono uppercase text-slate-400 font-bold">ALERTAS DO ESTÚDIO</span>
          
          <div 
            onClick={() => { onClose(); onTabChange('inventory'); }}
            className="flex items-center justify-between p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-200 cursor-pointer hover:bg-amber-500/20 transition-colors"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>2 carretéis com estoque abaixo de 150g (TPU Laranja e Resina Azul)</span>
            </div>
            <span className="text-amber-400 font-bold text-[10px] underline">Ver Estoque</span>
          </div>

          <div 
            onClick={() => { onClose(); onTabChange('catalog'); }}
            className="flex items-center justify-between p-2.5 rounded-xl bg-[#101726] border border-[#1e2a44] text-xs text-slate-300 cursor-pointer hover:bg-[#151f33] transition-colors"
          >
            <div className="flex items-center gap-2">
              <Printer className="w-4 h-4 text-indigo-400 shrink-0" />
              <span>Ender 3 V3 SE em manutenção (lubrificação do eixo Z)</span>
            </div>
            <span className="text-blue-400 font-bold text-[10px] underline">Ver Frota</span>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800">
          <button
            onClick={() => { onClose(); onTabChange('dashboard'); }}
            className="text-xs text-blue-400 hover:underline font-semibold"
          >
            Ir para Dashboard Completo →
          </button>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
