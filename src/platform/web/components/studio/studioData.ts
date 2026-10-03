export interface StudioPrinter {
  id: string;
  name: string;
  brand: string;
  technology: 'fdm' | 'resin';
  volume: string;
  powerWatts: number;
  depreciationPerHour: number;
  maintenancePerHour: number;
  hoursLogged: number;
  maxHours: number;
  status: 'imprimindo' | 'disponivel' | 'manutencao';
  activeInCalculation?: boolean;
}

export interface StudioSpool {
  id: string;
  name: string;
  colorName: string;
  colorHex: string;
  brand: string;
  type: string;
  pricePerKg: number;
  remainingWeight: number;
  totalWeight: number;
  status: 'em_estoque' | 'a_caminho';
  isLowStock?: boolean;
}

export const INITIAL_PRINTERS: StudioPrinter[] = [
  {
    id: 'bambu-p1s',
    name: 'Bambu Lab P1S Combo (AMS)',
    brand: 'Bambu Lab',
    technology: 'fdm',
    volume: '256×256×256 mm',
    powerWatts: 160,
    depreciationPerHour: 1.37,
    maintenancePerHour: 0.85,
    hoursLogged: 1240,
    maxHours: 4000,
    status: 'imprimindo',
    activeInCalculation: false,
  },
  {
    id: 'bambu-a1-mini',
    name: 'Bambu Lab A1 Mini',
    brand: 'Bambu Lab',
    technology: 'fdm',
    volume: '180×180×180 mm',
    powerWatts: 110,
    depreciationPerHour: 0.70,
    maintenancePerHour: 0.50,
    hoursLogged: 620,
    maxHours: 3500,
    status: 'disponivel',
    activeInCalculation: false,
  },
  {
    id: 'creality-k1',
    name: 'Creality K1 Max High-Speed',
    brand: 'Creality',
    technology: 'fdm',
    volume: '300×300×300 mm',
    powerWatts: 240,
    depreciationPerHour: 1.45,
    maintenancePerHour: 0.90,
    hoursLogged: 1890,
    maxHours: 3000,
    status: 'imprimindo',
    activeInCalculation: true,
  },
  {
    id: 'ender-3-v3',
    name: 'Creality Ender 3 V3 SE',
    brand: 'Creality',
    technology: 'fdm',
    volume: '220×220×250 mm',
    powerWatts: 140,
    depreciationPerHour: 0.78,
    maintenancePerHour: 0.60,
    hoursLogged: 1980,
    maxHours: 2000,
    status: 'manutencao',
    activeInCalculation: false,
  },
  {
    id: 'prusa-mk4',
    name: 'Original Prusa MK4',
    brand: 'Prusa Research',
    technology: 'fdm',
    volume: '250×210×220 mm',
    powerWatts: 150,
    depreciationPerHour: 1.13,
    maintenancePerHour: 0.70,
    hoursLogged: 2410,
    maxHours: 6000,
    status: 'disponivel',
    activeInCalculation: false,
  },
  {
    id: 'elegoo-saturn-3',
    name: 'Elegoo Saturn 3 Ultra 12K (MSLA)',
    brand: 'Elegoo',
    technology: 'resin',
    volume: '218×122×260 mm',
    powerWatts: 100,
    depreciationPerHour: 1.80,
    maintenancePerHour: 1.40,
    hoursLogged: 480,
    maxHours: 2000,
    status: 'disponivel',
    activeInCalculation: false,
  },
];

export const INITIAL_SPOOLS: StudioSpool[] = [
  {
    id: 'spool-tpu-orange',
    name: 'Laranja',
    colorName: 'Laranja',
    colorHex: '#f97316',
    brand: 'Anycubic',
    type: 'TPU',
    pricePerKg: 159.0,
    remainingWeight: 90,
    totalWeight: 1000,
    status: 'em_estoque',
    isLowStock: true,
  },
  {
    id: 'spool-resin-blue',
    name: 'Azul Translúcido',
    colorName: 'Azul Translúcido',
    colorHex: '#38bdf8',
    brand: 'Anycubic',
    type: 'Resina Standard',
    pricePerKg: 189.0,
    remainingWeight: 140,
    totalWeight: 1000,
    status: 'em_estoque',
    isLowStock: true,
  },
  {
    id: 'spool-petg-white',
    name: 'Branco',
    colorName: 'Branco',
    colorHex: '#f8fafc',
    brand: 'Prusament',
    type: 'PETG',
    pricePerKg: 149.0,
    remainingWeight: 420,
    totalWeight: 1000,
    status: 'em_estoque',
    isLowStock: false,
  },
  {
    id: 'spool-abs-grey',
    name: 'Cinza',
    colorName: 'Cinza',
    colorHex: '#64748b',
    brand: 'Polymaker',
    type: 'ABS',
    pricePerKg: 130.0,
    remainingWeight: 950,
    totalWeight: 1000,
    status: 'em_estoque',
    isLowStock: false,
  },
  {
    id: 'spool-silk-gold',
    name: 'Dourado',
    colorName: 'Dourado',
    colorHex: '#eab308',
    brand: 'Bambu Lab',
    type: 'PLA Silk',
    pricePerKg: 145.0,
    remainingWeight: 1000,
    totalWeight: 1000,
    status: 'a_caminho',
    isLowStock: false,
  },
  {
    id: 'spool-pla-black',
    name: 'Preto',
    colorName: 'Preto',
    colorHex: '#18181b',
    brand: 'Bambu Lab',
    type: 'PLA',
    pricePerKg: 110.0,
    remainingWeight: 780,
    totalWeight: 1000,
    status: 'em_estoque',
    isLowStock: false,
  },
];
