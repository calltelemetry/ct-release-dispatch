# ct-release-dispatch

Cloudflare MCP Worker that dispatches the **isolated release tasks** into GitHub
Actions via the release-automation GitHub App: the RC bundle (`release-bundle-rc.yml`)
and the single component image cut (`cut-component-image.yml`). The lab
qualification happens through the ct-uat qualification suites (UAT-1663) and its
own evidence gates — this worker only cuts and bundles, mirroring the operator
direction of 2026-10-22.

## Tools (direct-only)

| Tool | Dispatches | Required inputs |
|---|---|---|
| `release_bundle_run` | `release-bundle-rc.yml` on calltelemetry/ct-release | `mode` (query\|dry-run\|dispatch), `target_branch` |
| `cut_component_image` | `cut-component-image.yml` on calltelemetry/ct-release → the component's own image lane | `component`, `branch` |

`release_bundle_run` with `mode=dispatch` is operator-gated: it requires
`confirm="DISPATCH"` in the call so a stale or replayed request cannot cut.

## Auth

The **release-automation GitHub App** (the same app the release workflows mint
per-job tokens from). The worker holds `GH_APP_ID`, `GH_INSTALLATION_ID` and
`GH_APP_PRIVATE_KEY` as wrangler secrets; a fresh installation token
(`actions:write`, short TTL) is minted per call via the RS256 app JWT and never
cached or logged. The repo allowlist in `wrangler.toml` (`GITHUB_REPOS`) is the
cross-repo boundary — the tools refuse anything outside it.

## Deploy

```bash
npx wrangler secret put GH_APP_ID
npx wrangler secret put GH_INSTALLATION_ID
npx wrangler secret put GH_APP_PRIVATE_KEY   # the release-automation App PEM
npx wrangler deploy
```

The release-automation App installation must cover calltelemetry/ct-release and
every repo listed in `GITHUB_REPOS` — the app's installed permission set
(`actions:write`) is the audited cross-repo boundary.

## Test

```bash
npx vitest run
```
