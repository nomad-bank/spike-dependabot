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
  PR_BODY_PATH,
  SEVERITY_FILTER: SEVERITY_FILTER_RAW,
  PACKAGE_MANAGER,
  NOMAD_ACTIONS_PATH,
} = process.env;

const SEVERITY_FILTER = (SEVERITY_FILTER_RAW ?? 'all').trim() || 'all';

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
    .find((p) => /;\s*rel\s*=\s*"?next"?/i.test(p));
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
    if (SEVERITY_FILTER !== 'all' && severities.length > 0) {
      url.searchParams.set('severity', severities.join(','));
    }
    url.searchParams.set('per_page', '100');
    if (afterParam) url.searchParams.set('after', afterParam);

    const response = await fetch(url, { headers: buildGithubHeaders(dependabotToken) });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Resposta Dependabot não é JSON válido (HTTP ${response.status}): ${text.slice(0, 300)}`);
    }

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
    if (json.length >= 100 && !nextAfter) {
      console.warn(
        'Paginação: página com 100 itens mas sem rel=next no Link — possível perda de alertas. Verifique cabeçalho Link da API.',
      );
    }
    if (!nextAfter) break;
    afterParam = nextAfter;
  }

  return aggregated;
}

function normalizeEcosystem(raw) {
  return String(raw ?? '').trim().toLowerCase();
}

function detectPackageManager(repoCwd) {
  if (existsSync(join(repoCwd, 'pnpm-lock.yaml'))) return 'pnpm';
  if (existsSync(join(repoCwd, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

function graphInspectCommand(repoCwd, pm) {
  const yarnBerry = existsSync(join(repoCwd, '.yarnrc.yml'));
  if (pm === 'pnpm') return '`pnpm why <pacote>` (monorepo: `pnpm why -r <pacote>` ou a partir da pasta do pacote)';
  if (pm === 'yarn') return yarnBerry ? '`yarn npm why <pacote>`' : '`yarn why <pacote>`';
  return '`npm ls <pacote> --all`';
}

function rootLockfileHint(pm) {
  if (pm === 'pnpm') return '`pnpm-lock.yaml` na raiz do repositório';
  if (pm === 'yarn') return '`yarn.lock` (e cache Berry se aplicável) na raiz';
  return '`package-lock.json` na raiz';
}

function formatAlerts(alerts) {
  return alerts
    .filter((a) => normalizeEcosystem(a.dependency?.package?.ecosystem) === 'npm')
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

function buildPrompt(formattedAlerts, guideDoc, auditJson, repoCwd, packageManager) {
  const graphCmd = graphInspectCommand(repoCwd, packageManager);
  const alertLines = formattedAlerts
    .map(({ alertNumber, pkg, ecosystem, severity, summary, fixedIn, cve, manifestPath }) =>
      `- [#${alertNumber}] \`${pkg}\` (${ecosystem}) [${severity.toUpperCase()}] — ${summary} — corrigir em \`${fixedIn}\` — ${cve ?? 'sem CVE'} — manifest Dependabot: \`${manifestPath}\``,
    )
    .join('\n');

  const lockHint = rootLockfileHint(packageManager);

  return `${guideDoc}

---

## Raiz do projeto (obrigatório)

- Diretório de trabalho do agente: \`${repoCwd}\`
- Após corrigir manifests, rode **sempre** \`${packageManager} install\` **nesta raiz** para regenerar o lockfile correto: ${lockHint}.
- O diretório \`scripts/cursor-vuln-fixer/\` contém só o **código deste automation**; no CI o SDK é instalado **fora do repo**. **Não** concentre bumps, \`pnpm.overrides\` ou alterações de lock só nesse subdiretório salvo se um alerta tiver \`manifest_path\` explicitamente apontando para um arquivo dentro dele. O produto quase sempre está na raiz ou em pacotes do monorepo (\`packages/\`, \`apps/\`, etc.), não no script de CI.

---

## Contexto: alertas Dependabot (pacotes do registry npm)

Na API do GitHub, **npm, Yarn e pnpm** usam o mesmo valor \`ecosystem: npm\` para dependências do registry npm. O cliente detectado neste run (**${packageManager}**) define qual CLI usar (\`install\`, \`audit\`, grafo).

Repositório: **${owner}/${repo}**
Total de alertas deste ecossistema: **${formattedAlerts.length}**

${alertLines}

---

## Saída do audit (fonte primária para identificar os manifests corretos)

O audit abaixo reflete o estado real das dependências instaladas neste checkout conforme **${packageManager}**. **Use-o como fonte primária** para identificar em qual \`package.json\` aplicar cada correção — o campo \`manifest_path\` do Dependabot acima é referência secundária.

\`\`\`json
${auditJson}
\`\`\`

---

## Sua tarefa

1. Analise o audit para localizar o(s) \`package.json\` onde cada pacote vulnerável entra no grafo.
2. Se precisar do caminho de dependências, use ${graphCmd}.
3. Aplique a estratégia do guia (bump direto → bump do pai → override ou \`resolutions\`) **no manifest correto** para este gerenciador (**${packageManager}**).
4. Execute \`${packageManager} install\` na raiz do workspace após as edições.
`;
}

function buildPrBody(formattedAlerts, packageManager) {
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

Agente Cursor aplicou correções para **${formattedAlerts.length} alerta(s)** (filtro: \`${SEVERITY_FILTER}\`) com gerenciador **${packageManager}** (pacotes registry npm / compatível npm · pnpm · yarn).

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

  const ecosystemsInApi = [...new Set(alerts.map((a) => a.dependency?.package?.ecosystem).filter(Boolean))];
  console.log(
    `API Dependabot: ${alerts.length} alerta(s) aberto(s); após filtro registry npm (npm/pnpm/yarn): ${formattedAlerts.length}. Ecossistemas na resposta: ${ecosystemsInApi.length ? ecosystemsInApi.join(', ') : '(nenhum ou estrutura inesperada)'}`,
  );

  if (alerts.length === 0 && SEVERITY_FILTER === 'critical-high') {
    console.log(
      'Dica: com filtro critical-high a API só retorna Critical/High. Se o Security mostra mais alertas (moderate/low), rode o workflow com severity-filter "all".',
    );
  }

  if (formattedAlerts.length === 0) {
    if (alerts.length > 0) {
      console.log(
        'Nenhum alerta do registry npm na resposta filtrada. Ecossistemas retornados:',
        ecosystemsInApi.join(', ') || '(vazio — verifique estrutura da API).',
      );
    } else {
      console.log(
        'Nenhum alerta do registry npm para processar. Outros ecossistemas (Actions, Docker, Maven, Rubygems, etc.) não são cobertos por este fluxo.',
      );
    }
    if (GITHUB_OUTPUT) writeFileSync(GITHUB_OUTPUT, 'has_alerts=false\n', { flag: 'a' });
    process.exit(0);
  }

  if (GITHUB_OUTPUT) writeFileSync(GITHUB_OUTPUT, 'has_alerts=true\n', { flag: 'a' });
  console.log(`${formattedAlerts.length} alerta(s) do registry npm encontrado(s). Acionando agente Cursor...`);

  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const nomadActionsPath = NOMAD_ACTIONS_PATH ?? join(scriptDir, '../..');
  const repoCwd = GITHUB_WORKSPACE ?? process.cwd();
  const packageManager = (PACKAGE_MANAGER ?? '').trim() || detectPackageManager(repoCwd);
  const guideDoc = readFileSync(
    join(nomadActionsPath, 'docs/cursor-vulnerability-fixer.md'),
    'utf8',
  );

  const prBodyPath = PR_BODY_PATH ? PR_BODY_PATH : join(repoCwd, 'pr-body.md');
  writeFileSync(prBodyPath, buildPrBody(formattedAlerts, packageManager), 'utf8');

  console.log(`Rodando audit local (${packageManager}) para mapear o grafo...`);
  const auditJson = runAudit(repoCwd, packageManager);

  const prompt = buildPrompt(formattedAlerts, guideDoc, auditJson, repoCwd, packageManager);

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
