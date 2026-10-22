/**
 * Resolve the GitHub App installation id for one org, from the App ID + PEM.
 * Mints an RS256 app JWT, lists /app/installations, and prints the id of the
 * installation whose account login matches the org. --verify does a full
 * round trip: mint an installation token and report its expiry.
 */
const enc = new TextEncoder();

function pemBody(pem) {
  const body = String(pem).replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  const raw = atob(body);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function base64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function appJwt(appId, pem) {
  const header = base64url(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(enc.encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: Number(appId) })));
  const key = await crypto.subtle.importKey('pkcs8', pemBody(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(`${header}.${payload}`));
  return `${header}.${payload}.${base64url(sig)}`;
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
