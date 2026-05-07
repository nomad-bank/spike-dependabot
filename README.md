# Cursor Vulnerability Fixer

> Remediação proativa de vulnerabilidades com PR único via Cursor Agent (SDK) em CI.

O workflow lê alertas Dependabot (REST, paginação por cursor). Na API do GitHub, **npm, Yarn e pnpm** aparecem como `ecosystem: npm` para pacotes do registry. O script detecta o cliente pelo lockfile (`pnpm-lock.yaml` → pnpm, `yarn.lock` → yarn, senão npm) ou pela env `PACKAGE_MANAGER`, injeta saída de **`pnpm|npm|yarn audit --json`** no prompt e aciona o agente em **runtime local**. Depois: audit no CI, commit na branch `security/dependabot-remediation` e PR (`pr-body.md`).

---

## Fluxo

```
cursor-vulnerability-fixer.yml  (cron diário / workflow_dispatch / workflow_call)
  ├─ checkout + branch security/dependabot-remediation
  ├─ scripts/cursor-vuln-fixer/index.js
  │    ├─ API Dependabot (GH_DEPENDABOT_ALERTS_TOKEN) + paginação Link/after
  │    ├─ filtro ecosystem npm (registry; vale para npm, pnpm e yarn) + audit JSON no prompt
  │    └─ Agent.prompt · local cwd
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
