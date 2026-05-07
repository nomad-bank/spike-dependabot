const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');

const UNIFIED_BRANCH = 'security/dependabot-remediation';
const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_API_VERSION = '2026-03-10';
let PKG_ROOT, REPO_ROOT, PACKAGE_MANAGER;

function buildGithubHeaders(token) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'cursor-fixer',
  };
}

async function githubRequestJson(url, token) {
  const res = await fetch(url, { headers: buildGithubHeaders(token) });
  const link = res.headers.get('link') || '';
  const text = await res.text();
  if (!text) return { ok: res.ok, status: res.status, text, json: null, link };
  try {
    return { ok: res.ok, status: res.status, text, json: JSON.parse(text), link };
  } catch {
    return { ok: res.ok, status: res.status, text, json: null, link };
  }
}

function executeCommand(cmd, args = [], options = {}) {
  const baseToken = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  const token =
    options.ghToken !== undefined && options.ghToken !== '' ? options.ghToken : baseToken;
  const env = { ...process.env, GH_TOKEN: token, ...options.env };
  try {
    return execFileSync(cmd, args, {
      cwd: options.cwd || REPO_ROOT,
      env,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (error) {
    if (options.ignoreError) return error.stdout || '';
    throw new Error(`Command execution failure: ${cmd} ${args.join(' ')}\nError: ${error.stderr || error.message}`);
  }
}

function prepareEnvironment() {
  REPO_ROOT = process.env.GITHUB_WORKSPACE
    ? path.resolve(process.env.GITHUB_WORKSPACE)
    : findGitRoot(process.cwd());
  const relativePkgPath = process.env.SECURITY_PACKAGE_ROOT || '.';
  PKG_ROOT = path.resolve(REPO_ROOT, relativePkgPath);

  PACKAGE_MANAGER = fs.existsSync(path.join(PKG_ROOT, 'pnpm-lock.yaml')) ? 'pnpm' : 'npm';
  console.log(`Environment ready: [${PACKAGE_MANAGER.toUpperCase()}] in ${relativePkgPath}`);
}

function findGitRoot(startDir) {
  let current = startDir;
  while (current !== path.parse(current).root) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    current = path.dirname(current);
  }
  return current;
}

function buildRemediationPrompt(alerts, graphMap) {
  const guidePath = path.join(REPO_ROOT, 'docs/verify-issues-dependabot.md');
  if (!fs.existsSync(guidePath)) {
    throw new Error('Remediation guide not found at docs/verify-issues-dependabot.md');
  }

  const guide = fs.readFileSync(guidePath, 'utf8');
  const packageJsonPath = path.join(PKG_ROOT, 'package.json');
  const currentPackageJson = fs.readFileSync(packageJsonPath, 'utf8');

  const alertsSection = alerts
    .map(({ pkg, severity, currentVersion, fixVersion, graph }) => {
      return [
        `### ${pkg}`,
        `- Severity: ${severity}`,
        `- Current version: ${currentVersion}`,
        `- First patched version: ${fixVersion}`,
        `- Dependency graph (npm ls):`,
        '```json',
        graph,
        '```',
      ].join('\n');
    })
    .join('\n\n');

  const auditRaw = executeCommand(PACKAGE_MANAGER, ['audit', '--json'], {
    cwd: PKG_ROOT,
    ignoreError: true,
  });

  return [
    guide,
    '',
    '---',
    '',
    '## Open Dependabot Alerts to Fix',
    '',
    alertsSection,
    '',
    '---',
    '',
    '## Current package.json',
    '',
    '```json',
    currentPackageJson,
    '```',
    '',
    '## Audit output',
    '',
    '```json',
    auditRaw,
    '```',
    '',
    '---',
    '',
    '## Your task',
    '',
    `Package manager: **${PACKAGE_MANAGER}**`,
    `package.json path: \`${packageJsonPath}\``,
    '',
    'For each alert above, apply the appropriate remediation strategy as described in the guide:',
    '1. Prefer a direct bump when the package is a direct dependency.',
    '2. Use pnpm.overrides / overrides when the package is transitive.',
    `3. After editing package.json, run \`${PACKAGE_MANAGER} install\` to apply changes.`,
    '4. All versions must be exact (no ^ or ~ prefixes).',
    '5. Do not remove or reorder any existing keys in package.json.',
  ].join('\n');
}

async function callCursorAgent(prompt) {
  const { Agent, CursorAgentError } = await import('@cursor/sdk');

  const apiKey = process.env.CURSOR_TOKEN;
  if (!apiKey) {
    throw new Error('CURSOR_TOKEN environment variable is not set. Cannot invoke Cursor agent.');
  }

  console.log('Invoking Cursor agent for security remediation...');

  try {
    const result = await Agent.prompt(prompt, {
      apiKey,
      model: { id: 'composer-2' },
      local: { cwd: REPO_ROOT },
    });

    if (result.status === 'error') {
      throw new Error(`Cursor agent run failed (run id: ${result.id}). Check the Cursor dashboard for details.`);
    }

    console.log(`Cursor agent completed with status: ${result.status}`);
  } catch (err) {
    if (err instanceof CursorAgentError) {
      const retryNote = err.isRetryable ? ' (retryable)' : ' (non-retryable)';
      throw new Error(`Cursor agent failed to start${retryNote}: ${err.message}`);
    }
    throw err;
  }
}

function hasUncommittedChanges() {
  const diff = executeCommand('git', ['diff', '--name-only'], { ignoreError: true });
  return diff.trim().length > 0;
}

function extractAfterParamFromLinkHeader(linkHeader) {
  if (!linkHeader) return null;
  const parts = String(linkHeader)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const next = parts.find(p => /;\s*rel="next"\s*$/.test(p));
  if (!next) return null;

  const match = next.match(/<([^>]+)>/);
  if (!match) return null;

  try {
    const u = new URL(match[1]);
    return u.searchParams.get('after');
  } catch {
    return null;
  }
}

async function fetchOpenDependabotAlerts(repoSlug, token) {
  const aggregated = [];
  let afterParam = null;

  for (;;) {
    const url = new URL(`${GITHUB_API_BASE}/repos/${repoSlug}/dependabot/alerts`);
    url.searchParams.set('state', 'open');
    url.searchParams.set('per_page', '100');
    if (afterParam) url.searchParams.set('after', afterParam);

    const { ok, status, text, json, link } = await githubRequestJson(url, token);
    if (!ok) {
      let detail = text.slice(0, 500);
      if (json && typeof json === 'object' && json.message) {
        detail = String(json.message);
        if (json.documentation_url) detail += ` ${json.documentation_url}`;
      }
      if (status === 401 || status === 403) {
        throw new Error(
          `Dependabot alerts API HTTP ${status}: ${detail}. Check token permissions (PAT classic: repo or security_events; fine-grained: Dependabot alerts Read; org SSO if applicable).`,
        );
      }
      throw new Error(`Dependabot alerts API HTTP ${status}: ${detail}.`);
    }

    const chunk = json;
    if (!Array.isArray(chunk) || chunk.length === 0) break;
    aggregated.push(...chunk);
    const nextAfter = extractAfterParamFromLinkHeader(link);
    if (!nextAfter) break;
    afterParam = nextAfter;
  }

  return aggregated;
}

async function runRemediation() {
  prepareEnvironment();

  const repoSlug = (
    process.env.GITHUB_REPOSITORY ||
    executeCommand('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']).trim()
  ).trim();
  const alertsToken =
    process.env.GH_DEPENDABOT_ALERTS_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (!alertsToken) {
    throw new Error('No token for Dependabot alerts (GH_DEPENDABOT_ALERTS_TOKEN or GH_TOKEN).');
  }

  const alerts = await fetchOpenDependabotAlerts(repoSlug, alertsToken);
  const npmAlerts = alerts.filter(a => a.dependency.package.ecosystem === 'npm');

  if (npmAlerts.length === 0) {
    return console.log('No open vulnerabilities found. Task completed.');
  }

  console.log(`Found ${npmAlerts.length} open npm alert(s). Preparing context...`);
  executeCommand('git', ['checkout', '-B', UNIFIED_BRANCH]);

  const alertContexts = npmAlerts
    .filter(a => a.security_vulnerability?.first_patched_version?.identifier)
    .map(alert => {
      const pkg = alert.dependency.package.name;
      const fixVersion = alert.security_vulnerability.first_patched_version.identifier;
      const severity = alert.security_vulnerability.severity;
      const graphRaw = executeCommand('npm', ['ls', pkg, '--json'], { cwd: PKG_ROOT, ignoreError: true });
      const graphJson = JSON.parse(graphRaw || '{}');
      const currentVersion = graphJson.dependencies?.[pkg]?.version ?? 'n/a';

      return { pkg, severity, currentVersion, fixVersion, graph: graphRaw };
    });

  if (alertContexts.length === 0) {
    return console.log('No alerts with available patches. Task completed.');
  }

  const prompt = buildRemediationPrompt(alertContexts);
  await callCursorAgent(prompt);

  if (!hasUncommittedChanges()) {
    return console.log('Cursor agent completed but no file changes detected.');
  }

  executeCommand('git', ['add', '.']);
  executeCommand('git', ['commit', '-m', `security: remediate ${alertContexts.length} vulnerabilities via Cursor agent`], {
    ignoreError: true,
  });
  executeCommand('git', ['push', '-u', 'origin', 'HEAD', '--force']);

  console.log(`Remediation committed to branch ${UNIFIED_BRANCH}.`);
}

runRemediation().catch(err => {
  console.error('Fatal error during orchestration:');
  console.error(err);
  process.exit(1);
});
