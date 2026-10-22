/**
 * GitHub App credential minting and the two isolated release dispatches.
 * The release-automation GitHub App is the credential: its installed
 * permissions (actions:write on ct-release + the component repos) are the
 * audited cross-repo boundary; a fresh installation token is minted per call
 * and never cached or logged.
 */

export interface DispatchEnv {
  GITHUB_ORG: string;
  GITHUB_REPOS: string;
  GH_APP_ID: string;
  GH_INSTALLATION_ID: string;
  GH_APP_PRIVATE_KEY: string;
}

export const RELEASE_TASKS = Object.freeze([
  {
    name: 'release_bundle_run',
    description: 'The isolated RC bundle task: query the release-plan schema, dry-run it, or dispatch unified-release.yml from the plan receipt and wait for the RC bundle. Maps onto calltelemetry/ct-release workflow release-bundle-rc.yml. No testing, no UAT — the qualification evidence is produced by the ct-uat suites and consumed by its own gates.',
    workflow: 'release-bundle-rc.yml',
    repo: 'ct-release',
    inputs: ['mode', 'target_branch', 'source_repository', 'source_sha', 'release_line', 'version', 'train', 'alias_of', 'skip_component_releases', 'dispatch_ova'],
    required: ['mode', 'target_branch'],
  },
  {
    name: 'cut_component_image',
    description: 'The isolated single-image cut: dispatch the component repo\'s own image-publication lane for one branch at one sha, then verify the Docker Hub tag landed. No other components, no bundle, no testing. Maps onto calltelemetry/ct-release workflow cut-component-image.yml.',
    workflow: 'cut-component-image.yml',
    repo: 'ct-release',
    inputs: ['component', 'branch', 'sha', 'release_line', 'train', 'tag', 'image_workflow'],
    required: ['component', 'branch'],
  },
]);

const enc = new TextEncoder();

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** RS256 GitHub App JWT (exp 9 minutes, iat 60 s clock skew). */
export async function appJwt(appId: string, privateKeyPem: string, now = Date.now()): Promise<string> {
  const header = base64url(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const payload = base64url(enc.encode(JSON.stringify({ iat: Math.floor(now / 1000) - 60, exp: Math.floor(now / 1000) + 540, iss: appId })));
  const signingInput = `${header}.${payload}`;
  const keyData = new Uint8Array(pemBody(privateKeyPem)).buffer as ArrayBuffer;
  const key = await crypto.subtle.importKey('pkcs8', keyData, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(signingInput));
  return `${signingInput}.${base64url(signature)}`;
}

function pemBody(pem: string): Uint8Array {
  const body = String(pem).replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  const raw = atob(body);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

async function installationToken(env: DispatchEnv, fetchImpl: typeof fetch): Promise<string> {
  const jwt = await appJwt(env.GH_APP_ID, env.GH_APP_PRIVATE_KEY);
  const response = await fetchImpl(`https://api.github.com/app/installations/${env.GH_INSTALLATION_ID}/access_tokens`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  if (!response.ok) throw new Error(`installation token mint failed: ${response.status}`);
  const body = (await response.json()) as { token: string };
  return body.token;
}

export function repoAllowed(env: Pick<DispatchEnv, 'GITHUB_ORG' | 'GITHUB_REPOS'>, repo: string): boolean {
  return env.GITHUB_REPOS.split(',').map((r) => r.trim()).includes(repo);
}

export interface DispatchResult { run_url: string; run_id: number; repo: string; workflow: string; dispatched_at: string }

/** Dispatch one release task workflow and resolve the run. */
export async function dispatchReleaseTask(
  env: DispatchEnv,
  taskName: string,
  inputs: Record<string, string>,
  fetchImpl: typeof fetch = fetch,
): Promise<DispatchResult> {
  const task = RELEASE_TASKS.find((t) => t.name === taskName);
  if (!task) throw new Error(`unknown release task: ${taskName} (known: ${RELEASE_TASKS.map((t) => t.name).join(', ')})`);
  const repo = `${env.GITHUB_ORG}/${task.repo}`;
  if (!repoAllowed(env, task.repo)) throw new Error(`repo ${repo} is not in the dispatch allowlist`);
  for (const required of task.required) {
    if (!inputs[required] && required !== 'sha') throw new Error(`missing required input: ${required}`);
  }
  const token = await installationToken(env, fetchImpl);
  const dispatched_at = new Date().toISOString();
  const response = await fetchImpl(`https://api.github.com/repos/${repo}/actions/workflows/${task.workflow}/dispatches`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ref: 'main', inputs }),
  });
  if (response.status !== 204) throw new Error(`workflow dispatch failed: ${response.status} ${await response.text().catch(() => '')}`.slice(0, 300));

  // Resolve the run: the newest workflow_dispatch run created after our dispatch.
  for (let attempt = 0; attempt < 15; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const listResponse = await fetchImpl(
      `https://api.github.com/repos/${repo}/actions/workflows/${task.workflow}/runs?event=workflow_dispatch&per_page=5`,
      { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } },
    );
    if (!listResponse.ok) continue;
    const list = (await listResponse.json()) as { workflow_runs: Array<{ id: number; created_at: string; html_url: string }> };
    const run = list.workflow_runs?.find((r) => r.created_at >= dispatched_at);
    if (run) return { run_url: run.html_url, run_id: run.id, repo, workflow: task.workflow, dispatched_at };
  }
  throw new Error('dispatched but the run id did not resolve within the wait window');
}

/** Validate a tool input payload against the task's declared inputs. */
export function validateInputs(taskName: string, inputs: Record<string, unknown>): Record<string, string> {
  const task = RELEASE_TASKS.find((t) => t.name === taskName);
  if (!task) throw new Error(`unknown release task: ${taskName}`);
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(inputs ?? {})) {
    if (value == null) continue;
    if (!task.inputs.includes(key)) throw new Error(`unknown input for ${taskName}: ${key} (known: ${task.inputs.join(', ')})`);
    out[key] = String(value);
  }
  for (const required of task.required) {
    if (!out[required] && required !== 'sha') throw new Error(`missing required input: ${required}`);
  }
  return out;
}
