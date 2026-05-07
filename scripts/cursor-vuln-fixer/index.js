import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
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
  GITHUB_DEFAULT_BRANCH = 'main',
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
    .map(s => s.trim())
    .find(p => /;\s*rel="next"\s*$/.test(p));
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

function buildPrompt(alerts, guideDoc) {
  const alertLines = alerts
    .map((a) => {
      const pkg = a.dependency.package.name;
      const ecosystem = a.dependency.package.ecosystem;
      const severity = a.security_advisory.severity;
      const summary = a.security_advisory.summary;
      const fixedIn =
        a.security_vulnerability?.first_patched_version?.identifier ?? 'sem patch disponível';
      const manifestPath = a.dependency.manifest_path;
      return `- ${pkg} (${ecosystem}) [${severity.toUpperCase()}] — ${summary}. Corrigido em: ${fixedIn}. Manifest: ${manifestPath}`;
    })
    .join('\n');

  return `${guideDoc}

---

## Contexto: alertas Dependabot abertos neste repositório

Gerenciador de pacotes: **${PACKAGE_MANAGER}**
Repositório: **${owner}/${repo}**

Alertas a corrigir (${alerts.length} no total):
${alertLines}

Aplique a estratégia de remediação do guia acima para corrigir todos os alertas listados. Siga a árvore de decisão em ordem (bump direto → bump do pai → override/resolution). Após aplicar as alterações, execute \`${PACKAGE_MANAGER} install\` para garantir que o lockfile está consistente. Não altere scripts, dependências não relacionadas ou formatação fora das entradas modificadas.`;
}

async function main() {
  console.log(`Buscando alertas Dependabot (filtro: ${SEVERITY_FILTER})...`);

  const alerts = await fetchDependabotAlerts();

  if (alerts.length === 0) {
    console.log('Nenhum alerta Dependabot aberto encontrado para o filtro de severidade selecionado. Nada a fazer.');
    process.exit(0);
  }

  console.log(`${alerts.length} alerta(s) encontrado(s). Acionando agente Cursor...`);

  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const nomadActionsPath = NOMAD_ACTIONS_PATH ?? join(scriptDir, '../..');
  const guideDoc = readFileSync(
    join(nomadActionsPath, 'docs/cursor-vulnerability-fixer.md'),
    'utf8'
  );

  const prompt = buildPrompt(alerts, guideDoc);

  try {
    const result = await Agent.prompt(prompt, {
      apiKey: CURSOR_API_KEY,
      model: { id: 'composer-2' },
      cloud: {
        repos: [{ url: `https://github.com/${GITHUB_REPOSITORY}`, startingRef: GITHUB_DEFAULT_BRANCH }],
        autoCreatePR: true,
        skipReviewerRequest: true,
      },
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
