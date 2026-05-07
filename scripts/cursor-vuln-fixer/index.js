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
  GITHUB_REPOSITORY,
  SEVERITY_FILTER = 'all',
  PACKAGE_MANAGER,
  NOMAD_ACTIONS_PATH,
} = process.env;

const severities = SEVERITY_MAP[SEVERITY_FILTER] ?? SEVERITY_MAP.all;
const [owner, repo] = GITHUB_REPOSITORY.split('/');

async function fetchDependabotAlerts() {
  const params = new URLSearchParams({
    state: 'open',
    severity: severities.join(','),
    per_page: '100',
  });

  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/dependabot/alerts?${params}`,
    {
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    }
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Erro na API do GitHub ${response.status}: ${body}`);
  }

  return response.json();
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
        repos: [{ url: `https://github.com/${GITHUB_REPOSITORY}` }],
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
