import React, { useState } from 'react';
import { Sparkles, X, Send, Bot } from 'lucide-react';

interface StudioCopilotModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectName?: string;
}

export const StudioCopilotModal: React.FC<StudioCopilotModalProps> = ({
  isOpen,
  onClose,
  projectName = 'Exemplo de peça 3D',
}) => {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; text: string }>>([
    {
      role: 'assistant',
      text: `Olá! Sou o Copilot IA do Open3DCalc Studio. Analisei o projeto "${projectName}":\n\n• **Consumo estimado:** 55g em TPU 95A com custo fabril de R$ 18,18.\n• **Margem recomendada:** 100% gera R$ 42,27 (R$ 20,20/h de máquina).\n• **Dica de Fatiamento:** Para TPU flexível, reduza a velocidade para 30-40 mm/s e desative retração excessiva para evitar entupimento no direct-drive.\n\nComo posso ajudar sua produção agora?`,
    },
  ]);

  if (!isOpen) return null;

  const handleSend = () => {
    if (!input.trim()) return;
    const userMsg = input.trim();
    setInput('');
    setMessages((prev) => [
      ...prev,
      { role: 'user', text: userMsg },
      {
        role: 'assistant',
        text: `Entendido sobre "${userMsg}". Recomendo conferir a temperatura de bico a 220°C para TPU com mesa a 50°C. O custo estimado por hora na sua impressora Creality K1 Max fica em torno de R$ 2,35/h considerando energia e depreciação.`,
      },
    ]);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0b0f19] border border-[#1e2a44] rounded-2xl w-full max-w-xl shadow-2xl flex flex-col h-[520px] text-slate-100 animate-fade-up">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-amber-500/20 text-amber-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-1.5">
                Copilot IA de Impressão 3D
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">
                  Local Studio
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">Consultoria técnica de parâmetros, custos e fatiamento</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Chat area */}
        <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3 text-xs">
          {messages.map((m, i) => (
            <div
              key={i}
              className={`flex gap-2.5 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.role === 'assistant' && (
                <div className="w-6 h-6 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0 mt-0.5">
                  <Bot className="w-3.5 h-3.5" />
                </div>
              )}
              <div
                className={`p-3 rounded-xl max-w-[85%] whitespace-pre-line leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-blue-600 text-white rounded-tr-none'
                    : 'bg-[#101726] border border-[#1e2a44] text-slate-200 rounded-tl-none'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <div className="p-3 border-t border-slate-800 flex items-center gap-2 bg-[#090d18] rounded-b-2xl">
          <input
            type="text"
            placeholder="Pergunte sobre tempo de impressão, infill, margem ou defeito..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            className="flex-1 bg-[#101726] border border-[#1e2a44] rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 outline-none focus:border-amber-500 transition-colors"
          />
          <button
            onClick={handleSend}
            className="p-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
