import { useFilamentInventory } from "@/shared/stores/filamentInventory";
import { useHistoryStore } from "@/shared/stores/historyStore";
import { useCustomerStore } from "@/shared/stores/customerStore";
import { useQuoteStore } from "@/shared/stores/quoteStore";
import { useProductInventory } from "@/shared/stores/productInventory";
import { useCalculatorStore } from "@/shared/stores/calculatorStore";
import { useLayoutStore } from "@/shared/stores/layoutStore";
import {
  DEMO_SPOOLS,
  DEMO_CUSTOMERS,
  DEMO_QUOTES,
  DEMO_PRODUCTS,
  buildDemoHistoryEntries,
} from "./demoDataset";

/**
 * Initializes the workshop with the default studio dataset from the
 * screenshots if the store has no existing records.
 */
export function seedDefaultStudioDataIfEmpty(): void {
  try {
    const historyStore = useHistoryStore.getState();
    const filamentStore = useFilamentInventory.getState();

    if (historyStore.entries.length === 0 && filamentStore.spools.length === 0) {
      // 1. Spools
      for (const spool of DEMO_SPOOLS) {
        filamentStore.addSpool({
          brand: spool.brand,
          material: spool.material,
          color: spool.color,
          colorHex: spool.colorHex,
          weightGrams: spool.weightGrams,
          originalWeightGrams: spool.originalWeightGrams,
          costPerKg: spool.costPerKg,
          diameterMm: spool.diameterMm,
          status: spool.status,
          purchaseStore: spool.purchaseStore,
        });
      }

      // 2. History entries
      const entries = buildDemoHistoryEntries();
      for (const entry of entries) {
        historyStore.addEntry(entry);
      }

      // 3. Customers
      const customerStore = useCustomerStore.getState();
      const customerIds: string[] = [];
      for (const customer of DEMO_CUSTOMERS) {
        const id = customerStore.addCustomer(customer);
        customerIds.push(id);
      }

      // 4. Products
      const productStore = useProductInventory.getState();
      for (const product of DEMO_PRODUCTS) {
        productStore.addProduct(product);
      }

      // 5. Quotes
      const quoteStore = useQuoteStore.getState();
      DEMO_QUOTES.forEach((quote, i) => {
        const custId = customerIds[i % customerIds.length];
        const cust = DEMO_CUSTOMERS[i % DEMO_CUSTOMERS.length];
        quoteStore.addQuote({
          ...quote,
          customerId: custId,
          customerSnapshot: {
            name: cust.name,
            company: cust.company || undefined,
            email: cust.email || undefined,
            phone: cust.phone || undefined,
          },
        });
      });

      // 6. Set initial calculator preset: "Suporte Articulado Dobrável" (TPU 95A Laranja, 55g, 54m)
      const calcStore = useCalculatorStore.getState();
      calcStore.setField("productName", "Suporte Articulado Dobrável");
      calcStore.setField("activeTab", "fdm");
      calcStore.setFdmMaterial("type", "tpu_95a");
      calcStore.setFdmMaterial("costPerKg", 90);
      calcStore.setFdmMaterial("printWeightGrams", 55);
      calcStore.setFdmMaterial("spoolWeightGrams", 1000);
      calcStore.setFdmPrintParams("printTimeHours", 0);
      calcStore.setFdmPrintParams("printTimeMinutes", 54);
      calcStore.setFdmMachine("powerWatts", 250);
      calcStore.setFdmMachine("kwhCost", 0.95);
      calcStore.setFdmExtras("packagingCost", 2.2);
      calcStore.setFdmExtras("hardwareCost", 0);
      calcStore.setFdmFinishing("paintingCost", 0);
      calcStore.setFdmLabor("hourlyRate", 25);
      calcStore.setFdmSales("targetMarginPercent", 100);
      calcStore.recomputeResults();

      // 7. Set default layout mode to Bento (Modern Studio Dashboard)
      const layoutStore = useLayoutStore.getState();
      layoutStore.setLayoutMode("bento");
    }
  } catch (err) {
    console.warn("[seedDefaultStudioDataIfEmpty] Error seeding data:", err);
  }
}
