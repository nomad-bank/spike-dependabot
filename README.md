# Security Fixer Automation

> Remediação proativa de vulnerabilidades com Self-Healing PRs via Cursor Agent.

Este repositório implementa um modelo **Automated-Proactive** de remediação de segurança. O fluxo lê os alertas abertos do Dependabot, passa o contexto completo para um agente Cursor via SDK e deixa a IA aplicar as correções diretamente — bump direto ou override, conforme a análise do grafo — consolidando tudo em um único PR.

---

## Fluxo

```
GitHub Actions (schedule / dispatch)
  └─ cursor-fixer.js
       ├─ gh api → lê alertas Dependabot abertos (npm)
       ├─ npm ls → grafo por pacote
       ├─ <package-manager> audit → log completo
       ├─ buildRemediationPrompt()
       │    └─ docs/verify-issues-dependabot.md + alertas + package.json atual
       ├─ callCursorAgent()  ← @cursor/sdk · Agent.prompt · local runtime
       │    └─ Agente edita package.json e roda install
       └─ git commit + push → branch security/dependabot-remediation
```

---

## O que este projeto resolve

- **Análise real por IA:** O Cursor Agent recebe o guia de remediação (`docs/verify-issues-dependabot.md`), o grafo de dependências e o audit log completo, e decide a estratégia mais adequada para cada pacote.
- **Consolidação em um PR:** Todos os alertas são tratados numa única branch fixa (`security/dependabot-remediation`), eliminando o ruído de PRs individuais do Dependabot.
- **Versões exatas:** O agente é instruído a nunca usar `^` ou `~` — todas as versões são fixas por política do repositório.
- **Multi-gerenciador:** Detecção automática de `pnpm` (lockfile `pnpm-lock.yaml`) ou `npm`.

---

## Estratégia de remediação

O guia completo está em [`docs/verify-issues-dependabot.md`](docs/verify-issues-dependabot.md). Em resumo:

| Cenário | Ação |
| :--- | :--- |
| Dependência direta | Bump com versão fixa (`add --save-exact`) |
| Transitiva rasa | Bump do pacote pai ou pin na raiz |
| Transitiva profunda / conflito de major | `pnpm.overrides` / `overrides` com versão exata |

---

## Configuração e Setup

### 1. Personal Access Token (PAT)

Configure um **Fine-grained PAT** com as seguintes permissões:

- `Dependabot alerts`: Read-only
- `Contents`: Write
- `Pull requests`: Write

### 2. Secrets do repositório

No GitHub, vá em *Settings > Secrets and variables > Actions*:

| Secret | Descrição |
| :--- | :--- |
| `GH_DEPENDABOT_ALERTS_TOKEN` | PAT com acesso aos alertas Dependabot (obrigatório). |
| `CURSOR_TOKEN` | API key do Cursor (`cursor_...`), obtida em [cursor.com/dashboard/cloud-agents](https://cursor.com/dashboard/cloud-agents). |

### 3. Variável de repositório (opcional)

| Variável | Descrição | Default |
| :--- | :--- | :--- |
| `SECURITY_PACKAGE_ROOT` | Caminho relativo ao `package.json` alvo. | `.` |

---

## Integração com Cursor AI

O agente recebe o contexto montado por `buildRemediationPrompt()`:

1. Conteúdo completo de `docs/verify-issues-dependabot.md` como guia de decisão.
2. Lista de alertas abertos com severidade, versão atual e versão patcheada.
3. Grafo `npm ls --json` por pacote vulnerável.
4. Saída completa do `audit --json`.
5. Conteúdo atual do `package.json`.

Para triagem manual no chat do Cursor, use `@docs/verify-issues-dependabot.md`. A regra `.cursor/rules/security-automation.mdc` orienta o modelo sobre as políticas do repositório.

---

## Como funciona o Workflow

1. **Detecção:** Busca alertas `state=open` com ecossistema `npm` via `gh api`.
2. **Contexto:** Coleta grafo e audit de todos os pacotes antes de invocar o agente.
3. **Agente:** `Agent.prompt` (Cursor SDK, runtime local, `cwd` apontado para o repositório).
4. **Aplicação:** O agente edita `package.json` e executa o install conforme a estratégia.
5. **Commit:** Apenas se houver mudanças detectadas pelo `git diff`, cria o commit e faz push para `security/dependabot-remediation`.

---

## Licença

Conforme o repositório pai.
