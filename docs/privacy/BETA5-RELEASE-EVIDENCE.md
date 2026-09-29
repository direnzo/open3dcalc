# Beta 5 — Pacote de evidências de release e disclosure

Documento de liberação do canal **beta web**. Reúne a identificação exata do artefato, o escopo
entregue (waves 0–5), as evidências dos gates, as revisões da Themis e a **disclosure obrigatória**
que deve acompanhar as release notes. Onde um dado não foi medido, está escrito **não medido** —
nenhum número é estimado.

Status atual: ✅ **PUBLICADO** (web-only) — implementação mergeada, gates verdes, Themis aprovada no
exact-SHA, disclosure publicada, tag/deploy executados e validação live concluída.

---

## 1. Identificação

| Campo                         | Valor                                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Produto                       | Open3DCalc                                                                                                               |
| Alvo                          | `v2.0.0-beta.5` (canal **beta WEB**)                                                                                     |
| Status                        | ✅ **PUBLICADO** (web-only)                                                                                              |
| Branch de remediação          | `fix/beta5-privacy-remediation` (mergeada via **squash**)                                                                |
| Head revisado (SHA histórico) | `a7d8aaff6ef0f1cb696f2f1f0a7ba4ce31f802f5` (exact-SHA aprovado pela Themis)                                              |
| PR                            | #236 (**squash-mergeado** em `main`)                                                                                     |
| Commit de merge (squash)      | `1b7b88518290348f28c6f70876c059a7d9a774e1`                                                                               |
| Base original do PR           | `main` @ `faa51d2e982ac5672fbcf4e107373c9187244211`                                                                      |
| `main` no corte da tag        | `a34c50ba84e3549dcd19de91adf041fc5f10f656`                                                                               |
| Tag anotada                   | `v2.0.0-beta.5` (obj `c480f85ccbe3c74e211b93615ef603ddcc306a51`) → commit `a34c50b`                                      |
| Release                       | [`v2.0.0-beta.5`](https://github.com/ils15/open3dcalc/releases/tag/v2.0.0-beta.5) (prerelease, **sem assets**, web-only) |
| Live                          | `https://ils15.github.io/open3dcalc/beta/` — **HTTP 200**                                                                |
| `releases/latest`             | `v1.14.0` (estável intacta)                                                                                              |
| `package.json`                | `2.0.0-beta.5`                                                                                                           |

> **SHA de release (registro histórico).** O gate final da Themis aprovou o **exact-SHA** `a7d8aaf` na
> branch de remediação. O PR #236 foi **squash-mergeado** em `main` como `1b7b885`, de modo que o
> conteúdo aprovado está contido nesse merge. O corte da tag ocorreu depois, em `main` @ `a34c50b`
> (commit tagueado): a tag anotada `v2.0.0-beta.5` aponta para esse commit. Os SHAs acima são
> imutáveis — não houve reescrita de história.

> **Branch de resíduos W4** (`fix/beta5-privacy-w4-residuals`, **pós-beta.5**): fecha os follow-ups
> W4.4/T4.4, T4.6, L-1 e L-2 e reconcilia a tabela do §6 (ver também a disclosure do §5).
> Permanecem **abertos** como follow-ups rastreáveis: **T4.5**, **W6** (harness real de browser) e o
> **re-home desktop/IPC**.

> A versão em `package.json` é a linha `2.0.0-beta.5`: o **bump é feito pelo workflow `beta.yml`**
> no momento do corte da tag (`npm version` + commit + tag anotada). O repositório não bumpa a
> versão manualmente.

---

## 2. Escopo entregue (waves 0–5)

Trabalho de remediação de privacidade do beta, fechado como PR #236:

1. **Vault de PII criptografado no browser** — IndexedDB `open3dcalc_pii_vault`, cada registro um
   envelope AES-256-GCM selado com contrato de dados vinculados (AAD) equivalente ao desktop, sob
   chave derivada de passphrase que existe **somente em memória** (não exportável, descartada ao
   travar). Não há caminho de texto puro.
2. **Remoção do mirror de PII plaintext do persistence-bridge** — as superfícies de PII deixam de
   ser espelhadas em claro no `localStorage`/bridge de persistência.
3. **Locked shell + hydration gate** — a aplicação não hidrata os stores de PII antes do
   desbloqueio; o fluxo distingue explicitamente **criar** passphrase de **desbloquear**
   (passphrase memory-only).
4. **Sync vault-aware** — a sincronização passa a consultar o vault e **nunca grava PII em
   texto puro**.
5. **Re-home do PII plaintext legado para o vault** — consent-gated, verify-before-complete,
   **copy-without-delete**, idempotente (re-home copia e verifica; nada é apagado).
6. **UX de escolha de migração** — 5 opções explícitas (`migrate`, `keep`, `export`, `delete`,
   `cancel`), sem aceitação implícita nem destruição silenciosa; a opção `delete` está
   **desabilitada** (não existe erasure key-scoped verificada para essas chaves ainda).
7. **Disclosure value-free de resíduo/marker** — o app informa a presença de resíduo plaintext
   legado e do marker de migração sem vazar valores ou contagens sensíveis.
8. **Fix de ordenação de escrita do vault (last-writer-wins real)** — `piiStore.write()` passou a
   selar **dentro** da fila por chave, garantindo que a ordem de commit siga a ordem de chamada
   (ver §3, fix de correção).

---

## 3. Evidência de gates

### 3.1 CI — run `36572669898` @ `a7d8aaf`

| Job             | Resultado                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| `checks`        | ✅ success                                                                                              |
| `test`          | ✅ success — **273 arquivos / 3854 testes**                                                             |
| `build-desktop` | ✅ success                                                                                              |
| `build-web`     | ⏭️ skipped — **tag-gated por design** (o build web do canal beta só roda via `beta-deploy.yml`, na tag) |

> Runs anteriores nesta branch (superados por este run no SHA final): `36568013313` @ `6b1d186`
> (`checks`/`test`/`build-desktop` ✅, `test` **272 arquivos / 3847 testes**, `build-web` skipped) e
> `36569073666` @ `5a431a5`.

### 3.2 Gates locais

| Gate                                                            | Resultado                                                                  |
| --------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `test:run`                                                      | ✅ **273 arquivos / 3854 testes** — exit 0 em **2 execuções consecutivas** |
| `coverage`                                                      | **statements 82.18 / branches 77.14 / functions 78.33 / lines 83**         |
| `typecheck` (`tsc --noEmit -p tsconfig.app.json`)               | ✅ exit 0                                                                  |
| `typecheck:electron` (`tsc -p electron/tsconfig.json --noEmit`) | ✅ exit 0                                                                  |
| `lint` (ESLint `eslint .`)                                      | ✅ exit 0                                                                  |
| `build:all` (desktop + web)                                     | ✅ exit 0                                                                  |

> Cobertura: os quatro agregados foram medidos nesta branch. Limiares globais do Vitest e o
> critério de aceitação de 60% da Beta 5 são objeto do gate final da Themis (§4).

### 3.3 Fix de correção verificado (ordenação de escrita do vault)

- **Causa raiz:** `piiStore.write()` **selava o valor antes de enfileirar**, de modo que a ordem de
  commit seguia a ordem de conclusão do WebCrypto, não a ordem das chamadas. Duas escritas
  encadeadas são operações criptográficas independentes e podem resolver fora de ordem; um valor
  anterior (por exemplo o estado vazio inicial de uma action) podia ser enfileirado e commitado
  **depois** do mais novo e vencer — last-writer-wins invertido.
- **Correção:** o selo passou a ocorrer **dentro da fila por chave** (conteúdo squash-mergeado em
  `main` como `1b7b885`), de modo que a fila fixa a **ordem** além da contagem;
  `rehydratePiiStores()`/`unlockPiiStoresAndRehydrate()` passaram a aguardar `whenPiiWritesSettled()`
  antes de ler.
- **Verificação de falsificabilidade:** a Themis **reverteu o fix em clone isolado** e o teste de
  regressão determinístico de last-writer-wins **falhou (FAIL)** — o teste morde de fato. Com o fix
  presente, passa.

---

## 4. Revisões

| Revisão                       | Commit revisado | Veredito             | Achados                                    | Situação                                                                                              |
| ----------------------------- | --------------- | -------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| Themis W3                     | `a0a698a`       | **CHANGES_REQUIRED** | HIGH-1, HIGH-2, HIGH-3                     | ✅ resolvidos                                                                                         |
| Themis full-branch            | `bdf5d99`       | **CHANGES_REQUIRED** | H-4                                        | ✅ fix inicial em `6b1d186`; fechamento completo em `a7d8aaf` (conteúdo squash-mergeado em `1b7b885`) |
| Themis gate final (exact-SHA) | `a7d8aaf`       | **APPROVED**         | H-4 e seu resíduo no caminho do calculador | ✅ fechado (`CalculatorHistoryWriteGate.test.tsx`, falsificabilidade verificada)                      |

**Aprovado:** a Themis aprovou o **exact-SHA final** `a7d8aaf` (gate final). Esse SHA é o registro
histórico da branch de remediação: o PR #236 foi **squash-mergeado** em `main` como `1b7b885`, e o
conteúdo aprovado está contido nesse merge. Todos os itens humanos do gate (§7) foram cumpridos.

---

## 5. Disclosure obrigatória (B2) — texto para release notes

> **Beta 5 — privacidade e seus dados no canal WEB**
>
> - **Perfis WEB legados.** Para ver clientes, orçamentos e histórico antigos, é preciso definir uma
>   **passphrase** e escolher a migração. **NADA é apagado**: o re-home copia e verifica, sem
>   deletar os dados legados.
> - **Resíduo plaintext legado e marker.** O resíduo em texto puro herdado **permanece** (sem
>   exclusão automática) até uma eliminação explícita e é divulgado no app. O código atual **nunca
>   grava** o marker legado `open3dcalc_migration_done_v2`; ele só é lido para consumir/limpar um valor
>   que uma versão antiga deixou. Enquanto esse valor existir, ele é **resíduo em texto puro** — o
>   manifest declara `persistence: "encrypted_at_rest"` como a política para escritas **novas** (que
>   não ocorrem) e a divergência está divulgada no purpose do manifest e no painel de resíduo do app.
>   Uma migração nova registra progresso **sem valores** em `open3dcalc_migration_progress_v2`.
> - **DESKTOP indisponível nesta versão.** O re-home de PII no desktop **não está disponível** nesta
>   versão — esta release é **web-only**. **Não publique artefato desktop.**
> - **Vault travado não salva PII nova.** Enquanto o vault estiver **locked**, novas entradas de PII
>   **não são salvas**; a UI avisa isso explicitamente.
> - **Harness real de browser (W6) não construído nesta iteração.** Trata-se de um **resíduo
>   conhecido desta iteração de beta** (ver §6).

---

## 6. Resíduos / limitações conhecidas e follow-ups rastreáveis

| Item                                   | Descrição                                                                                                                                                                                                                                                              | Situação nesta branch (`fix/beta5-privacy-w4-residuals`)                                                                                   |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **W4.4 / T4.4**                        | Política do marker `open3dcalc_migration_done_v2` (quando/quando não permanece)                                                                                                                                                                                        | ✅ Implementado — o marker novo é value-free (`open3dcalc_migration_progress_v2`)                                                          |
| **W4.4 / T4.4 (divergência manifest)** | O manifest declara `persistence: "encrypted_at_rest"` para o marker `open3dcalc_migration_done_v2`, que hoje é **plaintext** — divergência a explicitar no texto de disclosure                                                                                         | ✅ Divulgada — purpose do manifest + painel de resíduo no app (§5)                                                                         |
| **T4.5**                               | Cleanup condicional do resíduo apenas quando `COUNT > 0`                                                                                                                                                                                                               | Follow-up (não implementado nesta branch)                                                                                                  |
| **T4.6**                               | Drift indicator (sinalizar divergência entre vault e resíduo legado)                                                                                                                                                                                                   | ✅ Implementado — `open3dcalc_migration_fingerprint_v1` (value-free)                                                                       |
| **W6**                                 | Harness real de browser + matriz de testes packaged (não construído nesta iteração; **não medido** além do exposto)                                                                                                                                                    | Resíduo conhecido                                                                                                                          |
| **W6 — CI do harness de browser**      | `npm run test:browser` roda no job `test-browser` do `ci-cd.yml`, mas **não é required check** e **não está no caminho do `beta-deploy.yml`** (o deploy beta só roda `build:web`). Um job vermelho não bloqueia merge nem publicação — hoje é **evidência, não gate**. | Follow-up rastreável                                                                                                                       |
| **Re-home desktop / IPC**              | Re-home de PII no desktop via IPC — o `persistence-bridge` deixa de hidratar as três chaves migradas, então o resíduo fica retido em SQLite e invisível ao renderer                                                                                                    | ✅ Implementado — IPC read-only `privacy:legacy-rows` + re-home + UX + testes (branch `feat/beta5-desktop-rehome`); caminho web inalterado |
| **L-1**                                | `PII_SYNC_KEYS` é **export morto** (`src/shared/lib/dataSync.ts`)                                                                                                                                                                                                      | ✅ Implementado — export removido                                                                                                          |
| **L-2**                                | Re-prompt após `keep` (manter read-only) não ocorre nesta versão                                                                                                                                                                                                       | ✅ Implementado — `open3dcalc_legacy_keep_readonly_v1` + reabertura no app                                                                 |

> A coluna **Situação** substitui o antigo rótulo `Tipo`: os itens que esta branch resolve estão
> marcados como implementados/divulgados; `T4.5` e W6 seguem como follow-ups rastreáveis.

### 6.1 Re-home desktop (implementado nesta branch)

> **Implementado.** O caminho desktop do re-home deixou de ser um follow-up. O `persistence-bridge`
> nunca hidrata as três chaves de PII migradas (`PII_BRIDGE_KEYS`), então um perfil legado destrava
> com stores **vazios** enquanto os registros permanecem em plaintext em `storage` — retido, porém
> invisível ao renderer. A correção fecha o mesmo defeito do caminho web, com outra fonte:
>
> - **IPC read-only** `privacy:legacy-rows` (`electron/legacyRows.ts`): lê exatamente as três chaves
>   declaradas, devolve o valor cru apenas para linhas `legacy_plaintext`, reporta `already_encrypted`
>   (envelope `enc1:`, sem valor) e `absent` — nunca INSERT/UPDATE/DELETE, nunca valores em log.
> - **Re-home** (`legacyPiiRehome.ts` + `desktopLegacyRows.ts`): uma única implementação. O contrato
>   é idêntico — consent-gated, fail-closed em vault travado, copy-without-delete,
>   verify-before-complete, idempotente. `fetchLegacy` só é consultado quando o `read` síncrono não
>   encontra resíduo.
> - **UX desktop-aware** (`useLegacyPiiResidue` / `useLegacyPiiDisclosure`): os hooks fazem merge das
>   linhas SQLite sobre `localStorage`, então o prompt e o painel de resíduo voltam a ser honestos no
>   desktop.
> - **Caminho web inalterado:** sem `window.electronAPI` a leitura IPC resolve para `null` (no-op) e o
>   caminho `localStorage` segue exatamente como estava — nenhum comportamento web muda.

---

## 7. Release gate checklist

| #   | Gate                                                                                                                              | Status                                                                                                             |
| --- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| 1   | Implementação merged                                                                                                              | ✅ **squash-merge** `1b7b885` em `main`                                                                            |
| 2   | Seis gates verdes (CI `checks`, `test`, `build-desktop`; local `test:run`, `typecheck`/`typecheck:electron`, `lint`, `build:all`) | ✅                                                                                                                 |
| 3   | Themis aprovada no **exact-SHA** (`a7d8aaf`)                                                                                      | ✅                                                                                                                 |
| 4   | Disclosure publicada (§5 nas release notes)                                                                                       | ✅                                                                                                                 |
| 5   | Tag/deploy autorizado por humano                                                                                                  | ✅ autorização dada pelo usuário e **executada**                                                                   |
| 6   | Corte da tag + deploy executados                                                                                                  | ✅ `beta.yml` run `36576102531` · `beta-deploy.yml` run `36576133040` · `pages-build-deployment` run `36576237752` |
| 7   | Validação live                                                                                                                    | ✅ `beta/` HTTP 200; bundle `./assets/index.web-BhAASmC6.js` contém `2.0.0-beta.5`                                 |

> **Autorização humana.** A autorização para cortar a tag e publicar o deploy foi dada pelo **usuário**
> e **executada** pelos workflows listados (itens 5–6). O `beta-deploy.yml` foi auto-disparado pela tag
> via PAT. `releases/latest` permanece `v1.14.0` — a estável segue intacta.

---

## 8. Tag/deploy — registro do que foi executado

> **Executado.** A autorização humana foi dada pelo usuário e os passos abaixo foram aplicados:
> `beta.yml` run `36576102531` (corte, ✅) e `beta-deploy.yml` run `36576133040` (deploy, ✅,
> auto-disparado pela tag via PAT). Mantidos como registro reproduzível do processo.

1. **Cortar a beta** — _Actions → Beta channel → Run workflow_:
   - `version = 2.0.0`
   - `ref = main`
     O `beta.yml` (`workflow_dispatch`) calcula `v2.0.0-beta.5`, bumpa `package.json` +
     `package-lock.json`, cria a **tag anotada imutável** `v2.0.0-beta.5` e empurra commit + tag com o
     PAT `BETA_RELEASE_TOKEN`.
2. **Deploy automático** — a tag dispara `beta-deploy.yml`, que builda a web com
   `VITE_BETA_CHANNEL=true`, publica em `gh-pages/beta/` (`keep_files: true`) e cria/refresha a
   **prerelease** `v2.0.0-beta.5`. **Electron não é buildado** no canal beta.
3. **Validação live:**
   - `https://ils15.github.io/open3dcalc/beta/` → **HTTP 200** e bundle contendo a versão **beta.5**.
   - Prerelease `v2.0.0-beta.5` presente no GitHub Releases.
4. As tags beta são **imutáveis**: nunca reescreva/delete uma tag já publicada — corte `beta.6` para
   ajustar qualquer coisa. O `beta-deploy.yml` é idempotente em re-execução para a mesma tag.

> ⚠️ **web-only:** não publicar artefato desktop nesta versão (re-home desktop/IPC indisponível —
> §5 e §6).
