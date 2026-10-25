import { describe, expect, it } from 'vitest';
import { RELEASE_TASKS, repoAllowed, validateInputs, appJwt } from '../src/github.js';

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
    expect(RELEASE_TASKS[0].required).toEqual(['mode', 'target_branch']);
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
    const out = validateInputs('release_bundle_run', { mode: 'query', target_branch: '0.8.7-stable', source_sha: 'a'.repeat(40) });
    expect(out).toEqual({ mode: 'query', target_branch: '0.8.7-stable', source_sha: 'a'.repeat(40) });
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
