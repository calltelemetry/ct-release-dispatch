/**
 * ct-release-dispatch MCP worker: streamable-HTTP MCP (spec 2025-06-18 shape),
 * the same frames as ct-qualification-mcp. Two direct-only tools dispatch the
 * isolated release tasks (the image cut and the RC bundle); there is no portal
 * exposure — the tools are the direct surface, matching qualification_run's
 * direct-only guard.
 *
 * Auth: the release-automation GitHub App. A fresh installation token is minted
 * per call (RS256 app JWT → installation access token, actions:write) and never
 * cached or logged. The dispatch allowlist in wrangler vars is the repo boundary.
 */
import { RELEASE_TASKS, dispatchReleaseTask, validateInputs, type DispatchEnv } from './github.js';

export const SERVER_NAME = 'ct-release-dispatch';
export const SERVER_VERSION = '1.0.0';

// Direct-only MCP over a bearer token (K3 audit finding 6: the endpoint was
// unauthenticated with wildcard CORS — anyone with the URL could mint GitHub
// runs). No browser client exists, so no Access-Control-Allow-Origin is sent.
const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, Mcp-Method, Mcp-Name, MCP-Protocol-Version, x-ct-agent',
};

/** Constant-time bearer check against env.MCP_TOKEN (Doppler ai-workspace/release-dispatch). */
function authorized(request: Request, env: DispatchEnv): boolean {
  const expected = (env.MCP_TOKEN ?? '').trim();
  if (!expected) return false; // fail closed when unset
  const got = (request.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '').trim();
  if (got.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ got.charCodeAt(i);
  return diff === 0;
}

function jsonResponse(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } });
}

function toolDefs() {
  return RELEASE_TASKS.map((task) => ({
    name: task.name,
    description: task.description,
    annotations: { readOnlyHint: false },
    inputSchema: {
      type: 'object',
      properties: Object.fromEntries(task.inputs.map((input) => [input, { type: 'string' }])),
      required: task.required,
      additionalProperties: false,
    },
  }));
}

function jsonRpcError(id: unknown, code: number, message: string): Response {
  return jsonResponse(200, { jsonrpc: '2.0', id, error: { code, message } });
}

export default {
  async fetch(request: Request, env: DispatchEnv): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });

    if (!authorized(request, env)) {
      return new Response(JSON.stringify({ error: 'unauthorized: supply Authorization: Bearer <MCP_TOKEN>' }),
        { status: 401, headers: { 'Content-Type': 'application/json', ...CORS_HEADERS } });
    }

    if (request.method === 'GET') {
      return jsonResponse(200, {
        status: 'ok', service: SERVER_NAME, version: SERVER_VERSION, transport: 'streamable-http',
        tools_count: RELEASE_TASKS.length, repos: env.GITHUB_REPOS.split(','),
      });
    }
    if (request.method !== 'POST') return jsonResponse(404, { error: 'not found' });

    let body: Record<string, unknown>;
    try { body = (await request.json()) as Record<string, unknown>; }
    catch { return jsonResponse(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: Invalid JSON' } }); }

    const { id, method, params } = body;
    const typedParams = (params as Record<string, unknown>) || {};

    if (method === 'initialize') {
      return jsonResponse(200, {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: (typedParams.protocolVersion as string) || '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        },
      });
    }
    if (method === 'notifications/initialized') return new Response(null, { status: 202, headers: CORS_HEADERS });
    if (method === 'ping') return jsonResponse(200, { jsonrpc: '2.0', id, result: {} });
    if (method === 'tools/list') return jsonResponse(200, { jsonrpc: '2.0', id, result: { tools: toolDefs() } });

    if (method === 'tools/call') {
      const rawName = String(typedParams.name || '');
      const toolName = rawName.replace(/^ct[-_]release[-_]dispatch[-_.:]/, '');
      const task = RELEASE_TASKS.find((t) => t.name === toolName);
      if (!task) return jsonRpcError(id, -32602, `Unknown ct-release-dispatch MCP tool: ${rawName}`);
      const args = (typedParams.arguments as Record<string, unknown>) || {};
      if (task.name === 'release_bundle_run' && String(args.mode || '') === 'dispatch') {
        // The dispatch mode is operator-gated: it requires an explicit confirm
        // token in the call so a stale or replayed portal request cannot cut.
        if (String(args.confirm ?? '') !== 'DISPATCH') {
          return jsonRpcError(id, -32003, 'release_bundle_run mode=dispatch requires confirm="DISPATCH" (operator-gated)');
        }
      }
      try {
        const inputs = validateInputs(task.name, args);
        const result = await dispatchReleaseTask(env, task.name, inputs);
        return jsonResponse(200, {
          jsonrpc: '2.0', id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            structuredContent: result,
          },
        });
      } catch (error) {
        return jsonRpcError(id, -32000, String((error as Error)?.message || error).slice(0, 400));
      }
    }

    return jsonRpcError(id, -32601, `Unknown method: ${method}`);
  },
};
