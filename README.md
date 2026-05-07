# Cursor Vulnerability Fixer

> Remediação proativa de vulnerabilidades com Self-Healing PRs via Cursor Agent.

Workflow reutilizável (`workflow_call`) que lê os alertas abertos do Dependabot, passa o contexto completo para um agente Cursor via SDK e deixa a IA aplicar as correções — bump direto ou override conforme o grafo — abrindo um único PR consolidado.

---

## Fluxo

```
Caller workflow (schedule / dispatch)
  └─ cursor-vulnerability-fixer.yml  (workflow_call)
       ├─ Checkout do repositório alvo
       ├─ Checkout nomad-actions (scripts + docs)
       ├─ Detecta gerenciador de pacotes (package-manager.cjs)
       ├─ scripts/cursor-vuln-fixer/index.js
       │    ├─ GitHub API → alertas Dependabot abertos filtrados por severidade
       │    ├─ buildPrompt()
       │    │    └─ docs/cursor-vulnerability-fixer.md + alertas + gerenciador
       │    └─ Agent.prompt()  ← @cursor/sdk · cloud runtime · autoCreatePR
       └─ PR aberto automaticamente pelo agente na branch security/dependabot-remediation
```

---

## O que este projeto resolve

- **Análise real por IA:** O Cursor Agent recebe o guia de remediação (`docs/cursor-vulnerability-fixer.md`), a lista de alertas com severidade e versão patcheada, e decide a estratégia mais adequada por pacote.
- **Consolidação em um PR:** Todos os alertas são tratados numa única branch, eliminando o ruído de PRs individuais do Dependabot.
- **Versões exatas:** O agente é instruído a nunca usar `^` ou `~` — todas as versões são fixas por política.
- **Multi-gerenciador:** Detecção automática de `pnpm`, `npm` ou `yarn` via lockfile.
- **Filtro de severidade:** Parâmetro `severity-filter` controla quais alertas processar (`all` ou `critical-high`).

---

## Estratégia de remediação

O guia completo está em [`docs/cursor-vulnerability-fixer.md`](docs/cursor-vulnerability-fixer.md). Em resumo:

| Cenário | Ação |
| :--- | :--- |
| Dependência direta | Bump com versão fixa (`add --save-exact`) |
| Transitiva rasa | Bump do pacote pai |
| Transitiva profunda / conflito de major | `pnpm.overrides` / `overrides` / `resolutions` com versão exata |

---

## Configuração e Setup

### 1. Secrets obrigatórios

| Secret | Descrição |
| :--- | :--- |
| `CURSOR_TOKEN` | API key do Cursor, obtida em [cursor.com/dashboard/cloud-agents](https://cursor.com/dashboard/cloud-agents). |
| `SRE_SCRIPTS` | PAT com acesso ao repositório `nomad-bank/nomad-actions` (checkout dos scripts). |

### 2. Inputs do workflow

| Input | Descrição | Default |
| :--- | :--- | :--- |
| `severity-filter` | `"all"` (CRITICAL, HIGH, MODERATE, LOW) ou `"critical-high"` | `all` |
| `package-manager` | `npm`, `yarn` ou `pnpm`. Detectado automaticamente se omitido. | — |
| `runner` | Runner a utilizar. | `ubuntu-latest` |

### 3. Permissões necessárias no repositório alvo

- `security-events: read` — leitura dos alertas Dependabot
- `contents: read` — checkout do código

O PR é criado pelo agente Cursor via cloud runtime com as permissões do `CURSOR_TOKEN`.

---

## Como funciona o Workflow

1. **Detecção:** Busca alertas `state=open` paginados via GitHub API (cursor-based, `Link` header).
2. **Filtro:** Aplica `severity-filter`; encerra sem erro se não houver alertas no filtro.
3. **Prompt:** Monta contexto com o guia de remediação, lista de alertas e gerenciador detectado.
4. **Agente:** `Agent.prompt` (Cursor SDK, cloud runtime) edita `package.json`, executa install e abre PR.
5. **PR:** Consolidado na branch `security/dependabot-remediation` com descrição gerada pelo agente.

---

## Triagem manual no Cursor

Para análise manual no chat, use `@docs/cursor-vulnerability-fixer.md`. A regra `.cursor/rules/security-automation.mdc` orienta o modelo sobre as políticas do repositório.

---

## Licença

Conforme o repositório pai.
