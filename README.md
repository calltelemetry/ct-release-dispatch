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
`GH_APP_PRIVATE_KEY` as wrangler secrets, and the MCP endpoint is gated by the
`MCP_TOKEN` bearer secret (fail-closed when unset).

### Installation-token cache (UAT-1815 / K3 audit)

Installation tokens (`actions:write`, GitHub TTL ~1h) used to be minted per
call — a fresh RS256 app JWT plus a token round-trip on every tool invocation.
They are now cached **by installation id** for their ~55-minute usable life:

- refresh at **50 minutes** (`INSTALLATION_TOKEN_REFRESH_MS`) so a cached token
  always has runway left;
- the Workers KV entry lives **55 minutes** (`INSTALLATION_TOKEN_KV_TTL_SECONDS`)
  as a backstop — the freshness check is what forces the re-mint;
- a GitHub **401** (rotated installation, revocation, clock drift) drops every
  cached copy and re-mints exactly once, then retries the dispatch;
- the **in-isolate cache is the floor**: with no `TOKEN_CACHE` binding (or when
  KV errors), consecutive calls in one isolate still reuse the token, and a
  dispatch never depends on the cache being available.

Optional KV binding (tokens then survive isolate eviction across PoPs):

```bash
npx wrangler kv namespace create RELEASE_TOKEN_CACHE
# then uncomment the [[kv_namespaces]] block in wrangler.toml with the printed id
```

The repo allowlist in `wrangler.toml` (`GITHUB_REPOS`) is the cross-repo
boundary — the tools refuse anything outside it.

## Deploy

```bash
npx wrangler secret put GH_APP_ID
npx wrangler secret put GH_INSTALLATION_ID
npx wrangler secret put GH_APP_PRIVATE_KEY   # the release-automation App PEM
npx wrangler secret put MCP_TOKEN            # bearer gate for the MCP endpoint
npx wrangler deploy
```

The release-automation App installation must cover calltelemetry/ct-release and
every repo listed in `GITHUB_REPOS` — the app's installed permission set
(`actions:write`) is the audited cross-repo boundary.

## Test

```bash
npx vitest run        # worker contract tests, including the token cache and the bearer gate
npx tsc --noEmit      # typecheck (local devDependency)
```
