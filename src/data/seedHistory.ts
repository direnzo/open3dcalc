import { SavedCalculationHistoryItem, PrintCalculationData } from '../types';
import { calculatePrintCost } from '../utils/calculator';

const NOW = Date.now();
const ONE_DAY = 24 * 60 * 60 * 1000;

const SEED_PROJECTS: Array<{
  data: PrintCalculationData;
  daysAgo: number;
  status: 'orcamento' | 'aprovado' | 'em_producao' | 'concluido' | 'cancelado';
  notes?: string;
}> = [
  {
    daysAgo: 0.1, // hoje
    status: 'em_producao',
    notes: 'Cliente solicitou acabamento fosco. Prazo urgente para sexta-feira.',
    data: {
      printTechnology: 'fdm',
      complexityMode: 'detalhado',
      projectName: 'Suporte Articulado para Tablet & Monitor',
      clientName: 'Studio Design Alpha',
      clientPhone: '(11) 98234-1100',
      materialType: 'PETG',
      filamentId: 'petg-black-esun',
      filamentColor: '#1e293b',
      spoolPrice: 110.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 280,
      printerId: 'bambu-p1s',
      printerPowerWatts: 160,
      energyKwhPrice: 0.95,
      printerCost: 5490,
      printerLifespanHours: 4000,
      printerMaintenancePerHour: 0.85,
      printTimeHours: 5,
      printTimeMinutes: 30,
      laborPrepMinutes: 15,
      laborPostMinutes: 20,
      laborHourlyRate: 35.00,
      failureRatePercent: 5,
      extraCosts: [
        { id: 'ext-1', name: '4x Parafusos M4 + Porcas', cost: 6.50, category: 'ferragem' },
        { id: 'ext-2', name: 'Caixa de Envio Reforçada', cost: 4.80, category: 'embalagem' }
      ],
      profitMarginPercent: 120,
      marketplaceFeePercent: 0,
      taxPercent: 6,
      discountPercent: 0,
      quantity: 1,
      infillPercent: 35,
      infillPattern: 'gyroid',
      layerHeightMm: 0.20,
      notes: 'Peça mecânica com boa resistência térmica para suportar tablet pesado.'
    }
  },
  {
    daysAgo: 1.2, // ontem
    status: 'concluido',
    notes: 'Entregue com sucesso via Motoboy. Cliente elogiou a cor dourada.',
    data: {
      printTechnology: 'fdm',
      complexityMode: 'rapido',
      projectName: 'Lote 35x Troféus Hackathon Tech 2026',
      clientName: 'Hub de Inovação SP',
      clientPhone: '(11) 97112-9988',
      materialType: 'PLA Silk',
      filamentId: 'pla-silk-gold',
      filamentColor: '#eab308',
      spoolPrice: 130.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 42,
      printerId: 'creality-k1',
      printerPowerWatts: 240,
      energyKwhPrice: 0.95,
      printerCost: 4350,
      printerLifespanHours: 3000,
      printerMaintenancePerHour: 0.90,
      printTimeHours: 1,
      printTimeMinutes: 10,
      laborPrepMinutes: 2,
      laborPostMinutes: 3,
      laborHourlyRate: 30.00,
      failureRatePercent: 4,
      extraCosts: [
        { id: 'ext-t1', name: 'Bases em MDF cortado a laser', cost: 3.50, category: 'ferragem' }
      ],
      profitMarginPercent: 140,
      marketplaceFeePercent: 5,
      taxPercent: 6,
      discountPercent: 5,
      quantity: 35,
      infillPercent: 20,
      infillPattern: 'honeycomb',
      layerHeightMm: 0.16,
      notes: 'Troféus com acabamento sedoso sem costuras aparentes.'
    }
  },
  {
    daysAgo: 2.5,
    status: 'aprovado',
    notes: 'Orçamento aprovado por e-mail. Aguardando liberação de máquina.',
    data: {
      printTechnology: 'resin',
      complexityMode: 'completo',
      projectName: 'Miniatura Dragão Ancião RPG 12K (MSLA)',
      clientName: 'Mestre da Guilda RPG',
      clientPhone: '(21) 99887-2233',
      materialType: 'Resina Standard',
      filamentId: 'resin-elegoo-grey',
      filamentColor: '#64748b',
      spoolPrice: 180.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 140,
      printerId: 'elegoo-saturn-3',
      printerPowerWatts: 100,
      energyKwhPrice: 0.95,
      printerCost: 3600,
      printerLifespanHours: 2000,
      printerMaintenancePerHour: 1.40,
      printTimeHours: 6,
      printTimeMinutes: 45,
      laborPrepMinutes: 20,
      laborPostMinutes: 35,
      laborHourlyRate: 40.00,
      failureRatePercent: 8,
      extraCosts: [
        { id: 'ext-ipa', name: 'Álcool Isopropílico Lavagem', cost: 12.00, category: 'acabamento' },
        { id: 'ext-box', name: 'Espuma protetora anti-impacto', cost: 8.50, category: 'embalagem' }
      ],
      profitMarginPercent: 150,
      marketplaceFeePercent: 0,
      taxPercent: 6,
      discountPercent: 0,
      quantity: 1,
      infillPercent: 100,
      infillPattern: 'concentric',
      layerHeightMm: 0.05,
      notes: 'Miniatura oca com furos de drenagem e cura UV posterior.'
    }
  },
  {
    daysAgo: 4.1,
    status: 'concluido',
    notes: 'Pagamento total recebido via Pix.',
    data: {
      printTechnology: 'fdm',
      complexityMode: 'detalhado',
      projectName: 'Engrenagem Bi-Helicoidal para Prensa',
      clientName: 'Metalúrgica Precision',
      clientPhone: '(19) 98110-4455',
      materialType: 'Nylon (PA)',
      filamentId: 'nylon-pa-cf',
      filamentColor: '#0f172a',
      spoolPrice: 280.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 310,
      printerId: 'prusa-mk4',
      printerPowerWatts: 150,
      energyKwhPrice: 0.95,
      printerCost: 6800,
      printerLifespanHours: 6000,
      printerMaintenancePerHour: 0.70,
      printTimeHours: 8,
      printTimeMinutes: 20,
      laborPrepMinutes: 20,
      laborPostMinutes: 15,
      laborHourlyRate: 45.00,
      failureRatePercent: 6,
      extraCosts: [
        { id: 'ext-heat', name: 'Recozimento Térmico em Estufa', cost: 18.00, category: 'acabamento' }
      ],
      profitMarginPercent: 130,
      marketplaceFeePercent: 0,
      taxPercent: 6,
      discountPercent: 0,
      quantity: 1,
      infillPercent: 80,
      infillPattern: 'gyroid',
      layerHeightMm: 0.15,
      notes: 'Peça técnica em substituição a componente metálico importado que quebrou.'
    }
  },
  {
    daysAgo: 6.8,
    status: 'orcamento',
    notes: 'Enviado link da proposta. Cliente analisando viabilidade.',
    data: {
      printTechnology: 'fdm',
      complexityMode: 'rapido',
      projectName: 'Gabinete Modular Mini PC Raspberry Pi 5',
      clientName: 'Eduardo Maker Labs',
      clientPhone: '(31) 99123-7766',
      materialType: 'ABS',
      filamentId: 'abs-black-voolt',
      filamentColor: '#334155',
      spoolPrice: 95.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 165,
      printerId: 'creality-k1',
      printerPowerWatts: 240,
      energyKwhPrice: 0.95,
      printerCost: 4350,
      printerLifespanHours: 3000,
      printerMaintenancePerHour: 0.90,
      printTimeHours: 3,
      printTimeMinutes: 15,
      laborPrepMinutes: 10,
      laborPostMinutes: 10,
      laborHourlyRate: 30.00,
      failureRatePercent: 5,
      extraCosts: [
        { id: 'ext-insert', name: '4x Insertos de Latão M3', cost: 4.00, category: 'ferragem' }
      ],
      profitMarginPercent: 110,
      marketplaceFeePercent: 12,
      taxPercent: 4,
      discountPercent: 0,
      quantity: 2,
      infillPercent: 30,
      infillPattern: 'grid',
      layerHeightMm: 0.20,
      notes: 'Gabinete com furação para cooler 40mm e saídas I/O.'
    }
  },
  {
    daysAgo: 9.3,
    status: 'concluido',
    notes: 'Lote corporativo de chaveiros entregue para brinde de feira.',
    data: {
      printTechnology: 'fdm',
      complexityMode: 'rapido',
      projectName: 'Lote 60x Chaveiros Cortadores de Sachê',
      clientName: 'Agência Criativa Pontual',
      clientPhone: '(41) 98844-3322',
      materialType: 'PLA',
      filamentId: 'pla-teal-3dlab',
      filamentColor: '#0ea5e9',
      spoolPrice: 90.00,
      spoolWeightGrams: 1000,
      printWeightGrams: 14,
      printerId: 'bambu-a1-mini',
      printerPowerWatts: 110,
      energyKwhPrice: 0.95,
      printerCost: 2450,
      printerLifespanHours: 3500,
      printerMaintenancePerHour: 0.50,
      printTimeHours: 0,
      printTimeMinutes: 22,
      laborPrepMinutes: 1,
      laborPostMinutes: 2,
      laborHourlyRate: 25.00,
      failureRatePercent: 3,
      extraCosts: [
        { id: 'ext-ring', name: 'Argolas de metal c/ corrente', cost: 0.60, category: 'ferragem' }
      ],
      profitMarginPercent: 160,
      marketplaceFeePercent: 0,
      taxPercent: 4,
      discountPercent: 10,
      quantity: 60,
      infillPercent: 40,
      infillPattern: 'triangles',
      layerHeightMm: 0.20,
      notes: 'Brindes com corte preciso e logotipo em relevo bicolor.'
    }
  }
];

export function getInitialSeedHistory(): SavedCalculationHistoryItem[] {
  return SEED_PROJECTS.map((proj, idx) => {
    const timestamp = NOW - Math.round(proj.daysAgo * ONE_DAY);
    const result = calculatePrintCost(proj.data);
    return {
      id: `seed-calc-${idx + 1}-${Date.now().toString(36)}`,
      timestamp,
      data: proj.data,
      result,
      status: proj.status,
      notes: proj.notes,
      isFavorite: idx < 2
    };
  });
}
