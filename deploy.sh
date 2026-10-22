#!/usr/bin/env bash
# Deploy ct-release-dispatch and wire its secrets from Doppler.
# Prereq: the release-automation GitHub App's key synced into Doppler
# ai-workspace/dev as RELEASE_APP_ID / RELEASE_APP_PRIVATE_KEY (operator step —
# the key lives in the calltelemetry/ct-release GitHub repo secrets, which are
# write-only and cannot be read back).
set -euo pipefail
: "${CLOUDFLARE_ACCOUNT_ID:?set from Doppler ai-workspace/dev}"
: "${CLOUDFLARE_API_TOKEN:?set from Doppler ai-workspace/dev}"
APP_ID="$(doppler secrets get RELEASE_APP_ID --project ai-workspace --config dev --plain 2>/dev/null || true)"
APP_KEY="$(doppler secrets get RELEASE_APP_PRIVATE_KEY --project ai-workspace --config dev --plain 2>/dev/null || true)"
[ -n "$APP_ID" ] || { echo "missing Doppler RELEASE_APP_ID (ai-workspace/dev) — sync the release-automation App id first"; exit 1; }
[ -n "$APP_KEY" ] || { echo "missing Doppler RELEASE_APP_PRIVATE_KEY (ai-workspace/dev) — sync the release-automation App private key first"; exit 1; }
INSTALLATION_ID="$(curl -sS -X POST -H "Accept: application/vnd.github+json" "https://api.github.com/app/installations" ... )"
echo "use scripts/mint-jwt.mjs style helper to resolve the installation id, or set it manually"
npx wrangler deploy
printf '%s' "$APP_ID" | npx wrangler secret put GH_APP_ID
printf '%s' "$INSTALLATION_ID" | npx wrangler secret put GH_INSTALLATION_ID
printf '%s' "$APP_KEY" | npx wrangler secret put GH_APP_PRIVATE_KEY
echo "deployed and secrets wired"
