import { readFileSync, writeFileSync } from 'fs';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { Agent, CursorAgentError } from '@cursor/sdk';

const SEVERITY_MAP = {
  'critical-high': ['critical', 'high'],
  all: ['critical', 'high', 'moderate', 'low'],
};

const {
  CURSOR_API_KEY,
  GITHUB_TOKEN,
  GH_DEPENDABOT_ALERTS_TOKEN,
  GITHUB_REPOSITORY,
  GITHUB_WORKSPACE,
  GITHUB_OUTPUT,
  SEVERITY_FILTER = 'all',
  PACKAGE_MANAGER,
  NOMAD_ACTIONS_PATH,
} = process.env;

const dependabotToken = GH_DEPENDABOT_ALERTS_TOKEN ?? GITHUB_TOKEN;

const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_API_VERSION = '2026-03-10';

const severities = SEVERITY_MAP[SEVERITY_FILTER] ?? SEVERITY_MAP.all;
const [owner, repo] = GITHUB_REPOSITORY.split('/');

function buildGithubHeaders(token) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'cursor-vuln-fixer',
  };
}

function extractAfterParamFromLinkHeader(linkHeader) {
  if (!linkHeader) return null;
  const next = String(linkHeader)
    .split(',')
    .map((s) => s.trim())
    .find((p) => /;\s*rel="next"\s*$/.test(p));
  if (!next) return null;
  const match = next.match(/<([^>]+)>/);
  if (!match) return null;
  try {
    return new URL(match[1]).searchParams.get('after');
  } catch {
    return null;
  }
}

async function fetchDependabotAlerts() {
  const aggregated = [];
  let afterParam = null;

  for (;;) {
    const url = new URL(`${GITHUB_API_BASE}/repos/${owner}/${repo}/dependabot/alerts`);
    url.searchParams.set('state', 'open');
    url.searchParams.set('severity', severities.join(','));
    url.searchParams.set('per_page', '100');
    if (afterParam) url.searchParams.set('after', afterParam);

    const response = await fetch(url, { headers: buildGithubHeaders(dependabotToken) });
    const text = await response.text();
    const json = text ? JSON.parse(text) : null;

    if (!response.ok) {
      let detail = text.slice(0, 500);
      if (json?.message) {
        detail = json.message;
        if (json.documentation_url) detail += ` ${json.documentation_url}`;
      }
      if (response.status === 401 || response.status === 403) {
        throw new Error(
          `Dependabot alerts API HTTP ${response.status}: ${detail}. Verifique as permissões do token (PAT classic: repo ou security_events; fine-grained: Dependabot alerts Read; SSO de org se aplicável).`,
        );
      }
      throw new Error(`Dependabot alerts API HTTP ${response.status}: ${detail}`);
    }

    if (!Array.isArray(json) || json.length === 0) break;
    aggregated.push(...json);
    const nextAfter = extractAfterParamFromLinkHeader(response.headers.get('link'));
    if (!nextAfter) break;
    afterParam = nextAfter;
  }

  return aggregated;
}

function formatAlerts(alerts) {
  return alerts
    .filter((a) => a.dependency?.package?.ecosystem === 'npm')
    .map((a) => {
      const manifestPath = a.dependency.manifest_path || 'package.json';
      return {
        pkg: a.dependency.package.name,
        ecosystem: a.dependency.package.ecosystem,
        severity: a.security_advisory.severity,
        summary: a.security_advisory.summary,
        fixedIn: a.security_vulnerability?.first_patched_version?.identifier ?? 'sem patch disponível',
        manifestPath,
        cve: a.security_advisory.cve_id ?? a.security_advisory.ghsa_id,
        alertNumber: a.number,
      };
    });
}

function runAudit(repoCwd, packageManager) {
  const isYarnBerry = existsSync(join(repoCwd, '.yarnrc.yml'));
  const cmd =
    packageManager === 'pnpm' ? 'pnpm audit --json' :
    packageManager === 'yarn' ? (isYarnBerry ? 'yarn npm audit --json' : 'yarn audit --json') :
    'npm audit --json';

  try {
    return execSync(cmd, { cwd: repoCwd, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || '{}';
  }
}

function buildPrompt(formattedAlerts, guideDoc, auditJson) {
  const alertLines = formattedAlerts
    .map(({ alertNumber, pkg, ecosystem, severity, summary, fixedIn, cve, manifestPath }) =>
      `- [#${alertNumber}] \`${pkg}\` (${ecosystem}) [${severity.toUpperCase()}] — ${summary} — corrigir em \`${fixedIn}\` — ${cve ?? 'sem CVE'} — manifest Dependabot: \`${manifestPath}\``,
    )
    .join('\n');

  return `${guideDoc}

---

## Contexto: alertas Dependabot (npm)

Gerenciador detectado: **${PACKAGE_MANAGER}**
Repositório: **${owner}/${repo}**
Total de alertas npm: **${formattedAlerts.length}**

${alertLines}

---

## Saída do audit (fonte primária para identificar os manifests corretos)

O audit abaixo reflete o estado real das dependências instaladas neste checkout. **Use-o como fonte primária** para identificar em qual \`package.json\` aplicar cada correção — o campo \`manifest_path\` do Dependabot acima é apenas referência secundária.

\`\`\`json
${auditJson}
\`\`\`

---

## Sua tarefa

1. Analise o audit para localizar o(s) \`package.json\` onde cada pacote vulnerável é declarado.
2. Se necessário, rode \`${PACKAGE_MANAGER} why <pacote>\` para entender o grafo antes de editar.
3. Aplique a estratégia do guia (bump direto → bump do pai → override/resolution) **no manifest correto**.
4. Execute \`${PACKAGE_MANAGER} install\` na raiz do workspace após as edições.
`;
}

function buildPrBody(formattedAlerts) {
  const severityOrder = { critical: 0, high: 1, moderate: 2, low: 3 };
  const sorted = [...formattedAlerts].sort(
    (a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9),
  );

  const rows = sorted
    .map(({ alertNumber, pkg, severity, fixedIn, cve, manifestPath }) =>
      `| [#${alertNumber}](https://github.com/${owner}/${repo}/security/dependabot/${alertNumber}) | \`${pkg}\` | ${severity.toUpperCase()} | \`${fixedIn}\` | ${cve ?? '—'} | \`${manifestPath}\` |`,
    )
    .join('\n');

  return `## Remediação automática de vulnerabilidades Dependabot

Agente Cursor aplicou correções para **${formattedAlerts.length} alerta(s)** (filtro: \`${SEVERITY_FILTER}\`) em \`${PACKAGE_MANAGER}\`.

### Alertas resolvidos

| Alerta | Pacote | Severidade | Versão corrigida | CVE/GHSA | Manifest |
| ------ | ------ | ---------- | ---------------- | -------- | -------- |
${rows}

### Estratégia aplicada

O agente seguiu a árvore de decisão do guia de remediação:
1. **Bump direto** — para dependências declaradas explicitamente
2. **Bump do pacote pai** — quando o pacote vulnerável é transitivo via um pai atualizável
3. **Override/resolution** — para transitivas profundas ou conflitos de major

> Gerado automaticamente por [cursor-vuln-fixer](./scripts/cursor-vuln-fixer/index.js).
`;
}

async function main() {
  console.log(`Buscando alertas Dependabot (filtro: ${SEVERITY_FILTER})...`);

  const alerts = await fetchDependabotAlerts();
  const formattedAlerts = formatAlerts(alerts);

  if (formattedAlerts.length === 0) {
    console.log(
      'Nenhum alerta Dependabot npm aberto para o filtro de severidade selecionado (ou só ecossistemas não-npm). Nada a fazer.',
    );
    if (GITHUB_OUTPUT) writeFileSync(GITHUB_OUTPUT, 'has_alerts=false\n', { flag: 'a' });
    process.exit(0);
  }

  if (GITHUB_OUTPUT) writeFileSync(GITHUB_OUTPUT, 'has_alerts=true\n', { flag: 'a' });
  console.log(`${formattedAlerts.length} alerta(s) npm encontrado(s). Acionando agente Cursor...`);

  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const nomadActionsPath = NOMAD_ACTIONS_PATH ?? join(scriptDir, '../..');
  const repoCwd = GITHUB_WORKSPACE ?? process.cwd();
  const guideDoc = readFileSync(
    join(nomadActionsPath, 'docs/cursor-vulnerability-fixer.md'),
    'utf8',
  );

  const prBodyPath = join(repoCwd, 'pr-body.md');
  writeFileSync(prBodyPath, buildPrBody(formattedAlerts), 'utf8');

  console.log('Rodando audit local para mapear grafo de dependências...');
  const auditJson = runAudit(repoCwd, PACKAGE_MANAGER);

  const prompt = buildPrompt(formattedAlerts, guideDoc, auditJson);

  try {
    const result = await Agent.prompt(prompt, {
      apiKey: CURSOR_API_KEY,
      model: { id: 'default' },
      local: { cwd: repoCwd },
    });

    if (result.status !== 'finished') {
      console.error(`Agente encerrou com status: ${result.status}`);
      process.exit(2);
    }

    console.log(`Agente finalizado com sucesso. Run ID: ${result.id}`);
  } catch (err) {
    if (err instanceof CursorAgentError) {
      console.error(`Falha ao iniciar o agente Cursor: ${err.message} (retry: ${err.isRetryable})`);
      process.exit(1);
    }
    throw err;
  }
}

main();
