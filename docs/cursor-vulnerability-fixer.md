# Guia: comando «Verify issues Dependabot» (V3 — Automation & Zero Trust)

Guia mestre para análise e correção de vulnerabilidades (**Dependabot** / audit local). Orienta o **Cursor** (via Action ou Chat) na direção de **audit o mais limpo possível**, com **pnpm**, **npm** ou **yarn**.

---

## 1. Princípios de execução (AppSec)

- **Tolerância zero (meta de audit):** tratar **Critical**, **High**, **Moderate** e **Low** conforme política do time; meta operacional típica é **audit sem falhas** após correções.
- **Least change:** priorizar **bump** com versão patcheada oficial. **Overrides / resolutions** só quando o bump direto ou do pai não resolve sem risco desproporcional.
- **Versões fixas:** sem `^`, `~` ou ranges em dependências diretas e em pins de override (formato exato por política do repo — ver [`README.md`](../README.md)).
- **Detecção do gerenciador:** usar lockfile (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`) antes de sugerir comandos ou blocos no `package.json`.

---

## 2. Árvore de decisão de remediação

Para cada vulnerabilidade, ordem sugerida:

1. **Step 0 — Grafo:** validar caminho com `pnpm why`, `npm ls <pkg>` ou equivalente Yarn antes de mudar manifest.
2. **Bump direto:** pacote declarado em `dependencies` / `devDependencies` → atualizar para versão fixa segura (advisory / npm view / grafo).
3. **Bump do pai:** se atualizar um pacote pai (mesma linha major compatível) puxar transitiva segura, preferir atualizar o pai em vez de override isolado.
4. **Override / resolution:** transitiva profunda ou conflito de majors no pai → propor bloco **`pnpm.overrides`**, **`overrides` (npm)** ou **`resolutions` (yarn)** com versões fixas e caminho quando necessário (`pai>filho`, etc.).

---

## 3. Sintaxe por gerenciador (fragmentos para o `package.json`)

Trechos ilustrativos; fundir ao JSON existente sem apagar scripts ou chaves obrigatórias do projeto.

### Cenário A — pnpm

```json
{
  "pnpm": {
    "overrides": {
      "pacote-vulneravel": "1.2.3",
      "pai-direto>pacote-filho": "2.0.1"
    }
  }
}
```

### Cenário B — npm (v7+)

```json
{
  "overrides": {
    "pacote-vulneravel": "1.2.3",
    "pai-direto": {
      "pacote-filho": "2.0.1"
    }
  }
}
```

### Cenário C — Yarn (classic: `resolutions`)

```json
{
  "resolutions": {
    "**/pacote-vulneravel": "1.2.3",
    "pai-direto/pacote-filho": "2.0.1"
  }
}
```

_Yarn Berry pode usar `package.json` → `resolutions` ou políticas no `.yarnrc.yml`; alinhar à convenção do repositório._

---

## 4. Fluxo na Action (`cursor-security-fix`)

| Etapa | O que ocorre |
| --- | --- |
| **Diagnóstico** | Lista alertas Dependabot (REST/GraphQL), cruza com versões patcheadas quando existirem. |
| **Aplicação automática** | Bumps **diretos** (save-exact); **transitivo raso** com `add` na raiz; se o grafo (via `npm ls --json` / fallback) tiver **> 2 níveis** ou **salto major** na versão resolvida → o script grava **overrides** / **resolutions** no `package.json` conforme o gerenciador. Conflito de linhas entre patches da API continua fora do auto-fix. |
| **Step 6 — legado** | Revisar `overrides` / `resolutions` já existentes; remover entrada a entrada e revalidar com install + audit para ver se o grafo já resolve sem pin. |

Manter o `package.json` legível: ordem de chaves e scripts preservados quando possível.

---

## 5. Comandos de referência por gerenciador

| Ação | pnpm | npm | Yarn (Berry como exemplo) |
| --- | --- | --- | --- |
| Audit | `pnpm audit` | `npm audit` | `yarn npm audit` |
| Grafo | `pnpm why <pkg>` | `npm ls <pkg> --all` | `yarn npm why <pkg>` |
| Install | `pnpm install` | `npm install` | `yarn install` |
| Add fixo | `pnpm add -E <pkg>@<versão>` | `npm install <pkg>@<versão> --save-exact` | `yarn add <pkg>@<versão> --exact` |

_Yarn Classic pode usar `yarn why` e `yarn audit` onde aplicável._

---

## 6. Responsabilidades

| Ator | Entrega |
| --- | --- |
| **Action / script** | Este guia (`@docs/verify-issues-dependabot.md`), contexto de alertas e, na automação atual, bumps + PR único consolidado quando aplicável. |
| **Cursor (chat)** | Estratégia bump vs override, edição sugerida do `package.json`, checklist de testes de impacto. |
| **Action / script** | Rodar audit/install localmente conforme gerenciador, validar CI e remover overrides legados no Step 6 quando fizer sentido. |

**Instrução ao modelo:** atuar como engenheiro de AppSec conservador em mudanças de grafo: preferir bump documentado; usar overrides quando o grafo exigir pin transitivo e documentar risco na descrição do PR ou na conversa.
