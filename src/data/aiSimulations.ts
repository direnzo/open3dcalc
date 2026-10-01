// Preset simulations for instant testing without API delay
export interface SimulationItem {
  id: string;
  title: string;
  subtitle: string;
  iconType: 'advisor' | 'pitch' | 'photo';
  advisorResult: {
    riskLevel: 'Baixo' | 'Médio' | 'Alto';
    riskExplanation: string;
    suggestedFailureRate: number;
    materialRecommendation: string;
    pricingVerdict: string;
    practicalTips: string[];
  };
  pitchResult: {
    whatsappMessage: string;
    highlights: string[];
    careInstructions: string;
  };
  photoResult: {
    detectedObject: string;
    estimatedDimensions: string;
    estimatedWeightGrams: number;
    estimatedPrintHours: number;
    recommendedMaterial: 'PLA' | 'PETG' | 'ABS' | 'TPU' | 'Resina Standard';
    supportNeeds: 'Nenhum' | 'Pouco' | 'Médio' | 'Intenso';
    reasoning: string;
    suggestedFillPercentage: number;
    sampleImageUrl: string;
  };
}

export const AI_SIMULATIONS: SimulationItem[] = [
  {
    id: 'sim-vaso-geometrico',
    title: 'Vaso Espiral Geométrico (140g - PLA)',
    subtitle: 'Decoração contemporânea com paredes finas no modo vaso',
    iconType: 'advisor',
    advisorResult: {
      riskLevel: 'Médio',
      riskExplanation: 'Peças altas com base estreita têm risco de tombamento ou descolamento na mesa após a 4ª hora de impressão.',
      suggestedFailureRate: 10,
      materialRecommendation: 'PLA Silk ou PLA Marble são excelentes para disfarçar linhas de camada e dar toque de cerâmica sem pós-processamento.',
      pricingVerdict: 'Margem de 110% perfeitamente alinhada com o nicho de decoração de interiores em marketplaces (Shopee / Elo7).',
      practicalTips: [
        'Ative uma borda (Brim) de pelo menos 6mm para garantir aderência na base.',
        'Reduza a velocidade de aceleração para evitar efeito de ondulação (ghosting) nas faces curvas.'
      ]
    },
    pitchResult: {
      whatsappMessage: `Olá Carlos, tudo bem? 👋\n\nAqui está a proposta para a produção do seu *Vaso Espiral Geométrico* sob medida!\n\n✨ *Especificações do Projeto:*\n• *Material:* PLA Premium (acabamento sedoso fosco)\n• *Tempo de Fabricação:* ~7 horas de impressão com precisão milimétrica\n• *Valor Total:* *R$ 68,50*\n\nEsse modelo fica incrível na sala ou escritório! Conseguimos iniciar a produção hoje e entregar em 24h a 48h. Posso já colocar na fila de impressão?`,
      highlights: [
        'Acabamento estético impecável sem marcas grosseiras de camada',
        'Fabricação sob demanda com material biodegradável e ecológico',
        'Entrega ágil com embalagem acolchoada anti-impacto'
      ],
      careInstructions: 'Evite expor diretamente à água quente acima de 55°C para não deformar o PLA.'
    },
    photoResult: {
      detectedObject: 'Vaso Facetado Espiral para Decoração',
      estimatedDimensions: '11 x 11 x 20 cm',
      estimatedWeightGrams: 140,
      estimatedPrintHours: 6.8,
      recommendedMaterial: 'PLA',
      supportNeeds: 'Nenhum',
      reasoning: 'Geometria com ângulos auto-portantes (< 45°), eliminando necessidade de suportes e desperdício de material.',
      suggestedFillPercentage: 15,
      sampleImageUrl: 'https://images.unsplash.com/photo-1578749556568-bc2c40e68b61?auto=format&fit=crop&w=400&q=80'
    }
  },
  {
    id: 'sim-suporte-gopro',
    title: 'Suporte de Ação para Guidão de Moto (PETG / ASA)',
    subtitle: 'Peça técnica para suportar vibrações, chuva e calor',
    iconType: 'advisor',
    advisorResult: {
      riskLevel: 'Baixo',
      riskExplanation: 'Peça pequena e compacta, excelente área de contato com a mesa de impressão, risco de falha mínimo.',
      suggestedFailureRate: 5,
      materialRecommendation: 'PLA não é recomendado aqui por deformar ao sol (temperatura de transição vítrea de 60°C). Use PETG ou ASA para resistência mecânica e proteção UV.',
      pricingVerdict: 'Peças técnicas e funcionais toleram margens superiores (140% a 180%) pelo valor percebido de engenharia e durabilidade.',
      practicalTips: [
        'Aumente o número de paredes (perímetros) para 4 ou 5 em vez de apenas aumentar o infill.',
        'Use padrão Gyroid para resistência multidirecional contra impactos de vibração.'
      ]
    },
    pitchResult: {
      whatsappMessage: `Fala Roberto, tudo certo? 🏍️\n\nFiz o cálculo detalhado do seu *Suporte Reforçado de Câmera de Ação*:\n\n🔩 *Ficha Técnica:*\n• *Material:* PETG Industrial de Alta Densidade (resistente a sol, chuva e impactos de estrada)\n• *Construção:* 5 paredes sólidas com preenchimento Giroide ultra-resistente\n• *Investimento:* *R$ 49,00*\n\nEssa peça aguenta o tranco com segurança para sua câmera. Podemos mandar rodar na máquina agora?`,
      highlights: [
        'Resistente a raios UV e calor de até 80°C sem empenar',
        'Estrutura projetada para absorver microvibrações do guidão',
        'Acompanha parafuso M5 em aço inoxidável'
      ],
      careInstructions: 'Peça totalmente lavável e resistente a graxa ou poeira.'
    },
    photoResult: {
      detectedObject: 'Suporte Articulado de Guidão com Encaixe GoPro',
      estimatedDimensions: '7 x 4.5 x 5 cm',
      estimatedWeightGrams: 48,
      estimatedPrintHours: 2.3,
      recommendedMaterial: 'PETG',
      supportNeeds: 'Pouco',
      reasoning: 'Necessita de suporte apenas sob o olhal do parafuso transversal de fixação.',
      suggestedFillPercentage: 40,
      sampleImageUrl: 'https://images.unsplash.com/photo-1512496015851-a90fb38ba796?auto=format&fit=crop&w=400&q=80'
    }
  },
  {
    id: 'sim-estatueta-dragon',
    title: 'Estatueta Colecionável RPG / Dragão (Resina UV)',
    subtitle: 'Rico em detalhes finos, chifres, asas e texturas de escama',
    iconType: 'advisor',
    advisorResult: {
      riskLevel: 'Alto',
      riskExplanation: 'Múltiplas ilhas suspensas e detalhes menores que 0.4mm. Exige suportes manuais de contato leve e orientação em 45 graus.',
      suggestedFailureRate: 15,
      materialRecommendation: 'Recomenda-se Resina Tough ou Resina Standard 8K com exposição calibrada. Se for em FDM, use bico de 0.2mm e camada de 0.08mm.',
      pricingVerdict: 'Item colecionável de alto valor agregado. Clientes de RPG pagam facilmente acima de R$ 90 a R$ 140 por impressões bem pós-curadas e limpas.',
      practicalTips: [
        'Esvazie o modelo (hollow) com parede de 2mm e adicione 2 furos de drenagem para economizar resina.',
        'Faça lavagem dupla com Álcool Isopropílico antes da cura UV final para não esbranquiçar os sulcos.'
      ]
    },
    pitchResult: {
      whatsappMessage: `E aí Lucas, beleza? 🐉\n\nProntinho o orçamento da miniatura *Lorde Dragão RPG*:\n\n🎲 *Qualidade Colecionável:*\n• *Tecnologia:* Resina 8K de Ultra Definição (camada de 0.03mm)\n• *Acabamento:* Peça lavada, descorada e polida pronta para pintura com tinta acrílica\n• *Valor do Modelo:* *R$ 115,00*\n\nOs detalhes das asas e dentes ficaram absurdos! Fechando agora, entrego na sexta-feira para sua mesa de RPG! Bora?`,
      highlights: [
        'Resolução de nível industrial com zero linhas perceptíveis a olho nu',
        'Peça curada com precisão para não quebrar no manuseio',
        'Base ponderada com equilíbrio perfeito para o tabuleiro'
      ],
      careInstructions: 'Não deixe cair de superfícies altas e guarde em local seco e abrigado de luz solar direta contínua.'
    },
    photoResult: {
      detectedObject: 'Miniatura Colecionável Fantasia / RPG',
      estimatedDimensions: '9 x 8 x 12 cm',
      estimatedWeightGrams: 85,
      estimatedPrintHours: 4.5,
      recommendedMaterial: 'Resina Standard',
      supportNeeds: 'Intenso',
      reasoning: 'Extremidades pontiagudas, asas suspensas e dentes finos demandam suportes arborescentes de ponta fina.',
      suggestedFillPercentage: 100,
      sampleImageUrl: 'https://images.unsplash.com/photo-1563089145-599997674d42?auto=format&fit=crop&w=400&q=80'
    }
  }
];
