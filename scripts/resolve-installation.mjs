/**
 * Resolve the GitHub App installation id for one org, from the App ID + PEM.
 * Mints an RS256 app JWT, lists /app/installations, and prints the id of the
 * installation whose account login matches the org. --verify does a full
 * round trip: mint an installation token and report its expiry.
 */
import crypto from 'node:crypto';

/** RS256 GitHub App JWT; node:crypto accepts PKCS#1 and PKCS#8 PEMs. */
function appJwt(appId, pem) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ iat: now - 60, exp: now + 540, iss: Number(appId) })).toString('base64url');
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  signer.end();
  return `${header}.${payload}.${signer.sign(pem).toString('base64url')}`;
}

async function main() {
  const [appId, pemFile, org, mode] = process.argv.slice(2);
  if (!appId || !pemFile || !org) {
    console.error('usage: resolve-installation.mjs <app-id> <pem-file> <org> [--verify]');
    process.exit(1);
  }
  const pem = (await import('node:fs')).readFileSync(pemFile, 'utf8');
  const jwt = await appJwt(appId, pem);
  const headers = { Authorization: `Bearer ${jwt}`, Accept: 'application/vnd.github+json' };
  const listResponse = await fetch('https://api.github.com/app/installations?per_page=100', { headers });
  if (!listResponse.ok) {
    console.error(`listing installations failed: ${listResponse.status} ${await listResponse.text().catch(() => '')}`);
    process.exit(1);
  }
  const installations = (await listResponse.json());
  const match = installations.find((i) => (i.account?.login || '').toLowerCase() === org.toLowerCase());
  if (!match) {
    console.error(`no installation for org ${org}; found: ${installations.map((i) => i.account?.login).join(', ')}`);
    process.exit(1);
  }
  if (mode !== '--verify') {
    console.log(String(match.id));
    return;
  }
  const tokenResponse = await fetch(`https://api.github.com/app/installations/${match.id}/access_tokens`, { method: 'POST', headers });
  if (!tokenResponse.ok) {
    console.error(`installation token mint failed: ${tokenResponse.status}`);
    process.exit(1);
  }
  const token = (await tokenResponse.json());
  const perms = Object.entries(token.permissions || {}).map(([k, v]) => `${k}=${v}`).join(', ');
  console.log(`installation ${match.id} OK; token expires ${token.expires_at}; permissions: ${perms}`);
}

main().catch((error) => { console.error(error?.message || error); process.exit(1); });
