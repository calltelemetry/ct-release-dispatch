import { describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import {
  appJwt,
  cachedInstallationToken,
  dispatchReleaseTask,
  INSTALLATION_TOKEN_KV_TTL_SECONDS,
  INSTALLATION_TOKEN_REFRESH_MS,
  invalidateInstallationToken,
  RELEASE_TASKS,
  repoAllowed,
  validateInputs,
  type DispatchEnv,
} from '../src/github.js';

const env = {
  GITHUB_ORG: 'calltelemetry',
  GITHUB_REPOS: 'ct-release,cisco-cdr,ct-quasar',
  GH_APP_ID: '12345',
  GH_INSTALLATION_ID: '67890',
  GH_APP_PRIVATE_KEY: 'not-a-real-pem',
};

describe('release task catalog', () => {
  it('declares the two isolated release tasks with their workflow bindings', () => {
    expect(RELEASE_TASKS.map((t) => t.name)).toEqual(['release_bundle_run', 'cut_component_image']);
    expect(RELEASE_TASKS[0].workflow).toBe('release-bundle-rc.yml');
    expect(RELEASE_TASKS[0].repo).toBe('ct-release');
    expect(RELEASE_TASKS[1].workflow).toBe('cut-component-image.yml');
  });
  it('declares required inputs per task', () => {
    expect(RELEASE_TASKS[0].required).toEqual(['mode', 'target_branch', 'source_repository', 'source_sha', 'release_line']);
    expect(RELEASE_TASKS[1].required).toEqual(['component', 'branch']);
  });
});

describe('repo allowlist', () => {
  it('allows listed repos and refuses others', () => {
    expect(repoAllowed(env, 'ct-release')).toBe(true);
    expect(repoAllowed(env, 'cisco-cdr')).toBe(true);
    expect(repoAllowed(env, 'some-other-repo')).toBe(false);
  });
});

describe('validateInputs', () => {
  it('accepts declared inputs and coerces to strings', () => {
    const out = validateInputs('release_bundle_run', { mode: 'query', target_branch: '0.8.7-stable', source_repository: 'cisco-cdr', source_sha: 'a'.repeat(40), release_line: '0.8.7' });
    expect(out).toEqual({ mode: 'query', target_branch: '0.8.7-stable', source_repository: 'cisco-cdr', source_sha: 'a'.repeat(40), release_line: '0.8.7' });
  });
  it('drops null values and rejects undeclared inputs', () => {
    expect(validateInputs('cut_component_image', { component: 'ct-media-go', branch: '0.8.7-stable', tag: null })).toEqual({ component: 'ct-media-go', branch: '0.8.7-stable' });
    expect(() => validateInputs('cut_component_image', { component: 'x', branch: 'b', evil: '1' })).toThrow(/unknown input/);
  });
  it('enforces required inputs', () => {
    expect(() => validateInputs('release_bundle_run', {})).toThrow(/missing required input: mode/);
    expect(() => validateInputs('cut_component_image', { component: 'ct-media-go' })).toThrow(/missing required input: branch/);
  });
});

describe('appJwt', () => {
  it('produces a three-segment RS256 JWT with the app id as issuer', async () => {
    // A minimal valid PKCS8 RSA key (2048-bit) for the signature round trip.
    const pem = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const spki = await crypto.subtle.exportKey('spki', pem.publicKey);
    expect(spki.byteLength).toBeGreaterThan(0);
    const pemText = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(2048 / 8)))}\n-----END PRIVATE KEY-----`;
    // A random PEM body will fail importKey; the JWT contract is what we assert.
    await expect(appJwt('12345', pemText)).rejects.toThrow();
    const jwt = await appJwt('12345', await fakePkcs8());
    const [, payload] = jwt.split('.');
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    expect(claims.iss).toBe('12345');
    expect(claims.exp - claims.iat).toBe(600);
  });
});

/** A deterministic PKCS8 RSA key for the JWT signing round trip. */
async function fakePkcs8(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  let body = '';
  const bytes = new Uint8Array(pkcs8);
  for (const b of bytes) body += String.fromCharCode(b);
  const b64 = btoa(body).replace(/(.{64})/g, '$1\n');
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----`;
}

// ---------------------------------------------------------------------------
// Installation-token cache (UAT-1815 / K3 audit): the worker used to mint a
// fresh RS256 app JWT + installation token per call. Tokens are now cached by
// installation id (Workers KV under TOKEN_CACHE, the in-isolate cache as the
// floor) for the ~55-minute usable lifetime, and a 401 invalidates the cached
// token and re-mints exactly once.
// ---------------------------------------------------------------------------

interface RecordedCall { url: string; method: string; authorization: string }

interface FakeGitHub {
  calls: RecordedCall[];
  fetch: typeof fetch;
  mintCount: () => number;
  dispatchCount: () => number;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** A recording GitHub API fake: mints installation tokens, accepts dispatches, lists runs. */
function fakeGitHub(options: { mintedTokens?: string[]; dispatchStatuses?: number[] } = {}): FakeGitHub {
  const tokens = options.mintedTokens ?? [];
  const dispatchStatuses = options.dispatchStatuses ?? [];
  const calls: RecordedCall[] = [];
  let mints = 0;
  let dispatches = 0;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = String(init?.method ?? 'GET');
    const authorization = String((init?.headers as Record<string, string>)?.Authorization ?? '');
    calls.push({ url, method, authorization });
    if (url.includes('/app/installations/') && url.endsWith('/access_tokens')) {
      const token = tokens[mints] ?? `tok-${mints + 1}`;
      mints++;
      return jsonResponse(201, { token });
    }
    if (url.includes('/dispatches')) {
      const status = dispatchStatuses[dispatches] ?? 204;
      dispatches++;
      return new Response(null, { status });
    }
    if (url.includes('/runs?')) {
      return jsonResponse(200, {
        workflow_runs: [{ id: 424242, created_at: new Date(Date.now() + 60_000).toISOString(), html_url: 'https://github.com/calltelemetry/ct-release/actions/runs/424242' }],
      });
    }
    return jsonResponse(404, { message: 'unexpected call' });
  }) as unknown as typeof fetch;
  return { calls, fetch: fetchImpl, mintCount: () => mints, dispatchCount: () => dispatches };
}

/** A tiny in-memory KVNamespace stub. */
function kvStub(entries = new Map<string, { value: string; ttl?: number }>()):
  KVNamespace & { store: Map<string, { value: string; ttl?: number }> } {
  return {
    store: entries,
    async get(key: string, type: 'json'): Promise<unknown> {
      const hit = entries.get(key);
      if (!hit) return null;
      return type === 'json' ? JSON.parse(hit.value) : hit.value;
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> {
      entries.set(key, { value, ttl: opts?.expirationTtl });
    },
    async delete(key: string): Promise<void> {
      entries.delete(key);
    },
  } as unknown as KVNamespace & { store: Map<string, { value: string; ttl?: number }> };
}

function envFor(installationId: string, tokenCache?: KVNamespace): DispatchEnv {
  return {
    GITHUB_ORG: 'calltelemetry',
    GITHUB_REPOS: 'ct-release,cisco-cdr,ct-quasar',
    GH_APP_ID: '12345',
    GH_INSTALLATION_ID: installationId,
    GH_APP_PRIVATE_KEY: TEST_APP_PEM,
    MCP_TOKEN: 'mcp-secret',
    ...(tokenCache ? { TOKEN_CACHE: tokenCache } : {}),
  };
}

// The mint path signs a real RS256 app JWT, so the fixtures need a valid PKCS8 PEM.
const TEST_APP_PEM = await fakePkcs8();

const DISPATCH_INPUTS = { mode: 'query', target_branch: '0.8.7-stable', source_repository: 'cisco-cdr', source_sha: 'a'.repeat(40), release_line: '0.8.7' };

describe('installation token cache', () => {
  it('mints once and reuses the in-isolate token for consecutive calls', async () => {
    const env = envFor('cache-isolate-1');
    const github = fakeGitHub({ mintedTokens: ['tok-iso-1'] });
    const first = await cachedInstallationToken(env, github.fetch);
    const second = await cachedInstallationToken(env, github.fetch);
    expect(first).toBe('tok-iso-1');
    expect(second).toBe('tok-iso-1');
    expect(github.mintCount()).toBe(1);
  });

  it('serves a fresh KV entry without minting and repopulates the isolate cache', async () => {
    const kv = kvStub();
    const env = envFor('cache-kv-1', kv);
    await kv.put('gh-installation-token:cache-kv-1', JSON.stringify({ token: 'tok-kv-warm', cached_at: Date.now() }), { expirationTtl: INSTALLATION_TOKEN_KV_TTL_SECONDS });
    const github = fakeGitHub();
    expect(await cachedInstallationToken(env, github.fetch)).toBe('tok-kv-warm');
    expect(github.mintCount()).toBe(0);
  });

  it('re-mints when the KV entry is older than the 50-minute refresh window', async () => {
    const kv = kvStub();
    const env = envFor('cache-kv-stale', kv);
    await kv.put('gh-installation-token:cache-kv-stale', JSON.stringify({ token: 'tok-stale', cached_at: Date.now() - INSTALLATION_TOKEN_REFRESH_MS - 1000 }), { expirationTtl: INSTALLATION_TOKEN_KV_TTL_SECONDS });
    const github = fakeGitHub({ mintedTokens: ['tok-fresh'] });
    expect(await cachedInstallationToken(env, github.fetch)).toBe('tok-fresh');
    expect(github.mintCount()).toBe(1);
    expect(JSON.parse(kv.store.get('gh-installation-token:cache-kv-stale')!.value)).toMatchObject({ token: 'tok-fresh' });
  });

  it('stores a fresh mint in KV with the 55-minute backstop TTL', async () => {
    const kv = kvStub();
    const env = envFor('cache-kv-put', kv);
    const github = fakeGitHub({ mintedTokens: ['tok-put'] });
    expect(await cachedInstallationToken(env, github.fetch)).toBe('tok-put');
    const stored = kv.store.get('gh-installation-token:cache-kv-put');
    expect(JSON.parse(stored!.value)).toMatchObject({ token: 'tok-put' });
    expect(stored!.ttl).toBe(55 * 60);
  });

  it('keeps minting and dispatching when the KV binding is unbound or failing', async () => {
    const broken = {
      get: () => Promise.reject(new Error('kv down')),
      put: () => Promise.reject(new Error('kv down')),
      delete: () => Promise.reject(new Error('kv down')),
    } as unknown as KVNamespace;
    const env = envFor('cache-broken-kv', broken);
    const github = fakeGitHub({ mintedTokens: ['tok-broken', 'tok-broken-2'] });
    expect(await cachedInstallationToken(env, github.fetch)).toBe('tok-broken');
    expect(await cachedInstallationToken(env, github.fetch, { force: true })).toBe('tok-broken-2');
    expect(github.mintCount()).toBe(2);
  });

  it('drops every cached copy on invalidateInstallationToken', async () => {
    const kv = kvStub();
    const env = envFor('cache-invalidate', kv);
    const github = fakeGitHub({ mintedTokens: ['tok-old'] });
    await cachedInstallationToken(env, github.fetch);
    await invalidateInstallationToken(env);
    expect(kv.store.has('gh-installation-token:cache-invalidate')).toBe(false);
    const next = fakeGitHub({ mintedTokens: ['tok-new'] });
    expect(await cachedInstallationToken(env, next.fetch)).toBe('tok-new');
    expect(next.mintCount()).toBe(1);
  });
});

describe('dispatch token invalidation on 401', () => {
  it('re-mints once and retries when a cached token is rejected with 401', async () => {
    const kv = kvStub();
    const env = envFor('dispatch-401', kv);
    const warm = fakeGitHub({ mintedTokens: ['tok-warm'] });
    await cachedInstallationToken(env, warm.fetch); // prime isolate + KV with tok-warm

    const github = fakeGitHub({ mintedTokens: ['tok-fresh'], dispatchStatuses: [401, 204] });
    const result = await dispatchReleaseTask(env, 'release_bundle_run', DISPATCH_INPUTS, github.fetch);
    expect(result.run_id).toBe(424242);
    expect(github.mintCount()).toBe(1); // exactly one re-mint, not a loop
    expect(github.dispatchCount()).toBe(2);
    const dispatchCalls = github.calls.filter((call) => call.url.includes('/dispatches'));
    expect(dispatchCalls[0].authorization).toBe('Bearer tok-warm'); // the cached token was tried first
    expect(dispatchCalls[1].authorization).toBe('Bearer tok-fresh'); // and the fresh token succeeded
    expect(kv.store.has('gh-installation-token:dispatch-401')).toBe(true); // the fresh token is cached again
    expect(JSON.parse(kv.store.get('gh-installation-token:dispatch-401')!.value)).toMatchObject({ token: 'tok-fresh' });
    // the invalidated token must be gone from every cache layer
    expect(kv.store.get('gh-installation-token:dispatch-401')!.value).not.toContain('tok-warm');
  });

  it('does not re-mint on non-401 dispatch failures', async () => {
    const env = envFor('dispatch-403');
    const github = fakeGitHub({ mintedTokens: ['tok-403'], dispatchStatuses: [403] });
    await expect(dispatchReleaseTask(env, 'release_bundle_run', DISPATCH_INPUTS, github.fetch)).rejects.toThrow(/workflow dispatch failed: 403/);
    expect(github.mintCount()).toBe(1);
    expect(github.dispatchCount()).toBe(1);
  });

  it('reuses the cached token across two dispatches without minting again', async () => {
    const env = envFor('dispatch-reuse');
    const github = fakeGitHub({ mintedTokens: ['tok-once'] });
    await dispatchReleaseTask(env, 'release_bundle_run', DISPATCH_INPUTS, github.fetch);
    await dispatchReleaseTask(env, 'cut_component_image', { component: 'ct-media-go', branch: '0.8.7-stable' }, github.fetch);
    expect(github.mintCount()).toBe(1);
    expect(github.dispatchCount()).toBe(2);
    const authorizations = github.calls.filter((call) => call.url.includes('/dispatches')).map((call) => call.authorization);
    expect(authorizations).toEqual(['Bearer tok-once', 'Bearer tok-once']);
  });
});

describe('MCP_TOKEN bearer gate (must stay)', () => {
  const base = 'https://worker.example/mcp';

  it('fails closed without a bearer token and on a wrong token', async () => {
    const noToken = envFor('gate-unset');
    delete (noToken as Partial<DispatchEnv>).MCP_TOKEN;
    expect((await worker.fetch(new Request(base), noToken)).status).toBe(401);
    const wrong = new Request(base, { headers: { Authorization: 'Bearer nope' } });
    expect((await worker.fetch(wrong, envFor('gate-wrong'))).status).toBe(401);
  });

  it('serves the MCP surface with the correct bearer token', async () => {
    const ok = new Request(base, { method: 'POST', headers: { Authorization: 'Bearer mcp-secret', 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    const response = await worker.fetch(ok, envFor('gate-ok'));
    expect(response.status).toBe(200);
    const body = await response.json() as { result: { tools: Array<{ name: string }> } };
    expect(body.result.tools.map((tool) => tool.name)).toEqual(['release_bundle_run', 'cut_component_image']);
  });
});
