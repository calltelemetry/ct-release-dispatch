#!/usr/bin/env bash
# Deploy ct-release-dispatch and wire its GitHub App secrets.
#
# Sources, in order of preference:
#   1. Doppler ai-workspace/release-dispatch (the dedicated config): RELEASE_APP_ID
#      + RELEASE_APP_PRIVATE_KEY (+ RELEASE_APP_INSTALLATION_ID, RELEASE_APP_SLUG)
#   2. Doppler ai-workspace/dev (legacy names)
#   3. Environment: GH_APP_ID + a PEM file at $GH_APP_KEY_FILE (or ./release-automation.pem)
#
# The installation id is RESOLVED automatically from the app credentials
# (mint an app JWT -> GET /app/installations -> the calltelemetry org entry),
# so the only operator inputs are the App ID and its private key PEM.
#
# Where to find them: github.com/organizations/calltelemetry/settings/installations
# -> the release-automation app -> its settings page shows the App ID and
# "Generate a private key" (the PEM downloads once; keep it in Doppler).
set -euo pipefail
cd "$(dirname "$0")"

: "${CLOUDFLARE_ACCOUNT_ID:?export from Doppler ai-workspace/dev}"
: "${CLOUDFLARE_API_TOKEN:?export from Doppler ai-workspace/dev}"
ORG="${GITHUB_ORG:-calltelemetry}"

DOPPLER_CONFIG="${DOPPLER_CONFIG:-release-dispatch}"
APP_ID="${GH_APP_ID:-$(doppler secrets get RELEASE_APP_ID --project ai-workspace --config "$DOPPLER_CONFIG" --plain 2>/dev/null || doppler secrets get RELEASE_APP_ID --project ai-workspace --config dev --plain 2>/dev/null || true)}"
PEM_FILE=""
if [ -n "${GH_APP_KEY_FILE:-}" ] && [ -f "${GH_APP_KEY_FILE}" ]; then
  PEM_FILE="${GH_APP_KEY_FILE}"
elif [ -f "./release-automation.pem" ]; then
  PEM_FILE="./release-automation.pem"
else
  APP_KEY="$(doppler secrets get RELEASE_APP_PRIVATE_KEY --project ai-workspace --config "$DOPPLER_CONFIG" --plain 2>/dev/null || doppler secrets get RELEASE_APP_PRIVATE_KEY --project ai-workspace --config dev --plain 2>/dev/null || true)"
  if [ -n "$APP_KEY" ]; then
    PEM_FILE="$(mktemp -t release-app.XXXXXX.pem)"
    printf '%s\n' "$APP_KEY" > "$PEM_FILE"
    chmod 600 "$PEM_FILE"
  fi
fi

[ -n "$APP_ID" ] || { echo "missing the release-automation App ID (set GH_APP_ID, or Doppler RELEASE_APP_ID in ai-workspace/dev)"; exit 1; }
[ -n "$PEM_FILE" ] || { echo "missing the release-automation App private key PEM (set GH_APP_KEY_FILE=/path/to.pem, drop ./release-automation.pem, or Doppler RELEASE_APP_PRIVATE_KEY)"; exit 1; }

# The worker uses WebCrypto, which requires PKCS#8; GitHub Apps export PKCS#1.
if head -1 "$PEM_FILE" | grep -q "BEGIN RSA PRIVATE KEY"; then
  normalized="$(mktemp -t release-app-pkcs8.XXXXXX.pem)"
  openssl pkey -in "$PEM_FILE" -out "$normalized" 2>/dev/null
  PEM_FILE="$normalized"
fi

echo "== resolving the installation id for app $APP_ID (org $ORG)"
INSTALLATION_ID="$(node scripts/resolve-installation.mjs "$APP_ID" "$PEM_FILE" "$ORG")"
[ -n "$INSTALLATION_ID" ] || { echo "could not resolve the installation id — check the App ID / PEM"; exit 1; }
echo "installation: $INSTALLATION_ID"

echo "== deploying the worker"
npx wrangler deploy

echo "== wiring the secrets"
printf '%s' "$APP_ID" | npx wrangler secret put GH_APP_ID
printf '%s' "$INSTALLATION_ID" | npx wrangler secret put GH_INSTALLATION_ID
npx wrangler secret put GH_APP_PRIVATE_KEY < "$PEM_FILE"

# Gate the MCP endpoint itself (K3 audit: unauthenticated endpoint + wildcard CORS).
MCP_TOKEN="$(doppler secrets get MCP_TOKEN --project ai-workspace --config "$DOPPLER_CONFIG" --plain 2>/dev/null || true)"
[ -n "$MCP_TOKEN" ] || { echo "FAIL: MCP_TOKEN missing in doppler://ai-workspace/$DOPPLER_CONFIG" >&2; exit 1; }
printf '%s' "$MCP_TOKEN" | npx wrangler secret put MCP_TOKEN

echo "deployed and secrets wired."
