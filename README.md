# Cursor Vulnerability Fixer

> Remediação proativa de vulnerabilidades com PR único via Cursor Agent (SDK) em CI.

O workflow lê alertas Dependabot (REST, paginação por cursor), monta o prompt com o guia `docs/cursor-vulnerability-fixer.md`, conteúdo dos **manifests afetados** (`manifest_path` por alerta) e aciona o agente em **runtime local** no checkout do Actions. Depois: `audit`, commit na branch `security/dependabot-remediation` e PR com corpo gerado (`pr-body.md`).

---

## Fluxo

```
cursor-vulnerability-fixer.yml  (cron diário / workflow_dispatch / workflow_call)
  ├─ checkout + branch security/dependabot-remediation
  ├─ scripts/cursor-vuln-fixer/index.js
  │    ├─ API Dependabot (GH_DEPENDABOT_ALERTS_TOKEN) + paginação Link/after
  │    ├─ filtro npm + agrupamento por manifest_path + snapshot dos package.json
  │    └─ Agent.prompt · local cwd · modelo cursor-auto
  ├─ pnpm|npm|yarn audit (se houver alertas)
  ├─ commit + push
  └─ gh pr create / gh pr edit (--body-file pr-body.md)
```

---

## Secrets e permissões

| Secret | Uso |
| :--- | :--- |
| `CURSOR_TOKEN` | API key Cursor (Cloud Agents / dashboard). |
| `GH_DEPENDABOT_ALERTS_TOKEN` | PAT com leitura de alertas Dependabot (fine-grained: Dependabot alerts Read + SSO na org se aplicável). |

No repositório: **Settings → Actions → General → Workflow permissions** → habilite **Allow GitHub Actions to create and approve pull requests** (senão `gh pr create` falha).

---

## Disparo

- **Agendado:** `cron` no YAML (ajuste o horário UTC conforme necessidade).
- **Manual:** Actions → *Cursor Vulnerability Fixer* → Run workflow → `severity-filter`.
- **Reutilizável:** outro repo pode chamar `uses: <org>/<repo>/.github/workflows/cursor-vulnerability-fixer.yml@<ref>` e passar `secrets: inherit` / `CURSOR_TOKEN`.

---

## Comportamento sem gasto de tokens

Se não houver alertas **npm** no filtro, o script grava `has_alerts=false` e os steps de audit, commit e PR são ignorados.

---

## Triagem manual no Cursor

Use `@docs/cursor-vulnerability-fixer.md`. Regra: `.cursor/rules/security-automation.mdc`.

---

## Licença

Conforme o repositório pai.
