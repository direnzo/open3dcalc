import { useEffect } from 'react';

export interface ShortcutHandlers {
  onSave?: () => void;
  onNavigatePricing?: () => void;
  onNavigateDashboard?: () => void;
  onNavigateHistory?: () => void;
  onNavigatePrinters?: () => void;
  onNavigateSpools?: () => void;
  onToggleMiniDash?: () => void;
  onNewProject?: () => void;
  onOpenQuote?: () => void;
  onOpenAICopilot?: () => void;
  onToggleSimplifiedMode?: () => void;
  onToggleFocusMode?: () => void;
  onExitFocusMode?: () => void;
  onOpenShortcutsHelp?: () => void;
  onNotify?: (message: string, icon?: string) => void;
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers, enabled = true) {
  useEffect(() => {
    if (!enabled) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      const activeEl = document.activeElement;
      const isInput = 
        activeEl?.tagName === 'INPUT' || 
        activeEl?.tagName === 'TEXTAREA' || 
        activeEl?.tagName === 'SELECT' ||
        (activeEl as HTMLElement)?.isContentEditable;

      const isModifier = event.ctrlKey || event.metaKey;
      const key = event.key.toLowerCase();

      // 1. Hotkeys that ALWAYS work even inside input fields if modifier is pressed
      // Ctrl+S / Cmd+S -> Salvar cálculo no histórico
      if (isModifier && key === 's' && !event.shiftKey) {
        event.preventDefault();
        if (handlers.onSave) {
          handlers.onSave();
          handlers.onNotify?.('Cálculo salvo no histórico!', '💾');
        }
        return;
      }

      // Ctrl+P / Cmd+P -> Alternar para Calculadora 3D (Pricing)
      if (isModifier && key === 'p' && !event.shiftKey) {
        event.preventDefault();
        if (handlers.onNavigatePricing) {
          handlers.onNavigatePricing();
          handlers.onNotify?.('Calculadora 3D [Ctrl+P]', '🖩');
        }
        return;
      }

      // Ctrl+D / Cmd+D -> Alternar para Dashboard
      if (isModifier && key === 'd') {
        event.preventDefault();
        if (handlers.onNavigateDashboard) {
          handlers.onNavigateDashboard();
          handlers.onNotify?.('Dashboard Geral [Ctrl+D]', '📊');
        }
        return;
      }

      // Ctrl+H / Cmd+H -> Histórico de Pedidos
      if (isModifier && key === 'h') {
        event.preventDefault();
        if (handlers.onNavigateHistory) {
          handlers.onNavigateHistory();
          handlers.onNotify?.('Histórico & Pedidos [Ctrl+H]', '🕒');
        }
        return;
      }

      // Ctrl+Q / Cmd+Q -> Gerar Orçamento / Proposta PDF
      if (isModifier && key === 'q') {
        event.preventDefault();
        if (handlers.onOpenQuote) {
          handlers.onOpenQuote();
          handlers.onNotify?.('Proposta Comercial [Ctrl+Q]', '📄');
        }
        return;
      }

      // Ctrl+M / Cmd+M -> Alternar Mini-Dash
      if (isModifier && key === 'm') {
        event.preventDefault();
        if (handlers.onToggleMiniDash) {
          handlers.onToggleMiniDash();
        }
        return;
      }

      // Ctrl+Shift+S / Alt+S -> Alternar Modo Simplificado
      if ((isModifier && event.shiftKey && key === 's') || (event.altKey && key === 's')) {
        event.preventDefault();
        if (handlers.onToggleSimplifiedMode) {
          handlers.onToggleSimplifiedMode();
        }
        return;
      }

      // Ctrl+Shift+F / Alt+F -> Alternar Modo Foco
      if ((isModifier && event.shiftKey && key === 'f') || (event.altKey && key === 'f')) {
        event.preventDefault();
        if (handlers.onToggleFocusMode) {
          handlers.onToggleFocusMode();
        }
        return;
      }

      // Ctrl+K / Cmd+K -> Guia de Atalhos
      if (isModifier && key === 'k') {
        event.preventDefault();
        if (handlers.onOpenShortcutsHelp) {
          handlers.onOpenShortcutsHelp();
        }
        return;
      }

      // 2. Hotkeys that ONLY work when NOT actively typing in an input
      if (!isInput) {
        // '?' -> Guia de Atalhos
        if (event.key === '?' || (event.shiftKey && event.key === '/')) {
          event.preventDefault();
          if (handlers.onOpenShortcutsHelp) {
            handlers.onOpenShortcutsHelp();
          }
          return;
        }

        // 'n' (with Ctrl or standalone Alt+N) -> Novo Projeto / Limpar
        if ((isModifier && key === 'n') || (event.altKey && key === 'n')) {
          event.preventDefault();
          if (handlers.onNewProject) {
            handlers.onNewProject();
            handlers.onNotify?.('Novo Projeto Iniciado [Ctrl+N]', '✨');
          }
          return;
        }

        // 'f' / Alt+4 -> Frota de Máquinas
        if (event.altKey && key === '4') {
          event.preventDefault();
          if (handlers.onNavigatePrinters) {
            handlers.onNavigatePrinters();
            handlers.onNotify?.('Frota de Máquinas [Alt+4]', '🖨️');
          }
          return;
        }

        // 'e' / Alt+5 -> Estoque de Carretéis
        if (event.altKey && key === '5') {
          event.preventDefault();
          if (handlers.onNavigateSpools) {
            handlers.onNavigateSpools();
            handlers.onNotify?.('Estoque de Carretéis [Alt+5]', '🧵');
          }
          return;
        }

        // 'm' -> Mini Dash (sem modifier)
        if (key === 'm' && !isModifier && !event.altKey) {
          event.preventDefault();
          if (handlers.onToggleMiniDash) {
            handlers.onToggleMiniDash();
          }
          return;
        }

        // 'Escape' -> Sair do Modo Foco se ativo
        if (event.key === 'Escape') {
          if (handlers.onExitFocusMode) {
            handlers.onExitFocusMode();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handlers, enabled]);
}
