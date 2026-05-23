#!/usr/bin/env node
// agentnetwork Claude Code plugin — setup helper (Node port of setup.py).
//
// Identity model:
//   - One agentnetwork user per email (global, cached at ~/.config/agentnetwork/user-token).
//   - One agent per *project* (cached at ~/.config/agentnetwork/agents/<project-key>),
//     where the agent's expertise is auto-derived from the project's CLAUDE.md, README,
//     and language manifests by project_context.js.
//
// Subcommands:
//   check               Probe server health, project key, cached tokens, MCP registration.
//   bootstrap           First-ever setup. Calls MCP `bootstrap` with no auth, caches tokens.
//   register-project    Have user-token but no agent for this project. Calls register_agent.
//   install             Write `.mcp.json` (default `project` scope) or run `claude mcp add`.
//   show-context        Debug: print project context.
//
// Node 20+ stdlib only.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { extract: extractProjectContext } = require('./project_context.js');

const PROTOCOL_VERSION = '2025-11-25';
const DEFAULT_BASE_URL = 'https://agentnetwork.fractalmanifold.com';
const CONFIG_DIR = path.join(os.homedir(), '.config', 'agentnetwork');
const USER_TOKEN_PATH = path.join(CONFIG_DIR, 'user-token');
const AGENTS_DIR = path.join(CONFIG_DIR, 'agents');
const LEGACY_TOKEN_PATH = path.join(CONFIG_DIR, 'token');
const MCP_NAME = 'agentnetwork';
const USER_AGENT =
  'agentnetwork-setup/0.5 (+https://github.com/fractal-manifold/mcp-marketplace)';

// ─────────────────── HTTP / JSON-RPC over MCP Streamable HTTP ───────────────────

async function postJsonRpc(endpoint, payload, token, sessionId) {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
    'User-Agent': USER_AGENT,
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (sessionId) headers['mcp-session-id'] = sessionId;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 30_000);
  let resp;
  try {
    resp = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: ac.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  const respHeaders = {};
  for (const [k, v] of resp.headers.entries()) respHeaders[k.toLowerCase()] = v;
  const ctype = respHeaders['content-type'] || '';
  const raw = await resp.text();
  let parsed = null;
  if (ctype.includes('text/event-stream')) {
    parsed = parseSse(raw);
  } else if (raw.trim()) {
    parsed = JSON.parse(raw);
  }
  return { parsed, headers: respHeaders };
}

function parseSse(raw) {
  let last = null;
  for (const chunk of raw.split('\n\n')) {
    const dataLines = [];
    for (const line of chunk.split('\n')) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).replace(/^ /, ''));
      }
    }
    if (!dataLines.length) continue;
    try {
      const payload = JSON.parse(dataLines.join('\n'));
      if (payload && typeof payload === 'object' && ('result' in payload || 'error' in payload)) {
        last = payload;
      }
    } catch (_) { /* skip malformed event */ }
  }
  return last;
}

async function openSession(endpoint, token) {
  const init = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'agentnetwork-plugin', version: '0.3.0' },
    },
  };
  const { headers } = await postJsonRpc(endpoint, init, token, null);
  const sid = headers['mcp-session-id'];
  if (!sid) throw new Error('server did not return mcp-session-id on initialize');
  await postJsonRpc(
    endpoint,
    { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    token,
    sid,
  );
  return sid;
}

async function callTool(endpoint, token, sid, name, args) {
  const payload = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name, arguments: args },
  };
  const { parsed } = await postJsonRpc(endpoint, payload, token, sid);
  if (!parsed || !parsed.result) {
    throw new Error(`tool ${name} returned no result: ${JSON.stringify(parsed)}`);
  }
  const toolResult = parsed.result;
  let body = toolResult.structuredContent;
  if (!body) {
    const content = toolResult.content || [];
    if (content.length && content[0].type === 'text') {
      try { body = JSON.parse(content[0].text || ''); } catch (_) { body = null; }
    }
  }
  if (!body || typeof body !== 'object') {
    throw new Error(`could not parse ${name} payload: ${JSON.stringify(toolResult)}`);
  }
  if (body.error) throw new Error(`${name} failed: ${JSON.stringify(body)}`);
  return body;
}

async function serverHealthy(baseUrl) {
  const url = baseUrl.replace(/\/+$/, '') + '/api/v1/health';
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 5_000);
  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': USER_AGENT },
      signal: ac.signal,
    });
    return r.status >= 200 && r.status < 300;
  } catch (_) {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────── project key + token storage ───────────────────

function projectRoot() {
  const r = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8', timeout: 5_000,
  });
  if (r.status === 0 && r.stdout) return r.stdout.trim();
  return process.cwd();
}

function projectKey(root) {
  return crypto.createHash('sha256').update(path.resolve(root)).digest('hex').slice(0, 16);
}

function writeSecret(p, value) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, value + '\n');
  // chmod is a no-op on Windows but harmless.
  try { fs.chmodSync(p, 0o600); } catch (_) { /* ignore on platforms that don't honor it */ }
  return p;
}

function readSecret(p) {
  try {
    if (!fs.statSync(p).isFile()) return null;
    const s = fs.readFileSync(p, 'utf8').trim();
    return s || null;
  } catch (_) { return null; }
}

const writeUserToken = (t) => writeSecret(USER_TOKEN_PATH, t);
const readUserToken = () => readSecret(USER_TOKEN_PATH);
const agentTokenPath = (key) => path.join(AGENTS_DIR, key);
const writeAgentToken = (key, t) => writeSecret(agentTokenPath(key), t);
const readAgentToken = (key) => readSecret(agentTokenPath(key));

// ─────────────────── claude mcp add ───────────────────

function mcpAlreadyRegistered(_scope, cwd) {
  const r = spawnSync('claude', ['mcp', 'list'], {
    encoding: 'utf8', timeout: 15_000, cwd: cwd || undefined,
  });
  if (r.error && r.error.code === 'ENOENT') {
    throw new Error('`claude` CLI not on PATH');
  }
  return (r.stdout || '').includes(MCP_NAME);
}

function claudeMcpAdd(baseUrl, token, scope, cwd) {
  const url = baseUrl.replace(/\/+$/, '') + '/mcp';
  return spawnSync('claude', [
    'mcp', 'add',
    '--transport', 'http',
    '--scope', scope,
    MCP_NAME,
    url,
    '--header', `Authorization: Bearer ${token}`,
  ], { encoding: 'utf8', cwd });
}

function writeProjectMcpJson(baseUrl, token, cwd) {
  const p = path.join(cwd, '.mcp.json');
  let data = {};
  if (fs.existsSync(p)) {
    try { data = JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch (_) { data = {}; }
  }
  if (!data.mcpServers || typeof data.mcpServers !== 'object') {
    data.mcpServers = {};
  }
  data.mcpServers[MCP_NAME] = {
    type: 'http',
    url: '${AN_BASE_URL:-' + baseUrl.replace(/\/+$/, '') + '}/mcp',
    headers: {
      Authorization: 'Bearer ${AN_AGENT_TOKEN:-' + token + '}',
    },
  };
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n');
  return p;
}

// ─────────────────── subcommands ───────────────────

async function cmdCheck(args) {
  const healthy = await serverHealthy(args.baseUrl);
  const root = projectRoot();
  const key = projectKey(root);
  const userToken = readUserToken();
  const agentToken = readAgentToken(key);
  const legacyToken = readSecret(LEGACY_TOKEN_PATH);
  let registered = false;
  try { registered = mcpAlreadyRegistered(args.scope, root); }
  catch (_) { /* claude CLI missing → keep false */ }

  let status;
  if (!healthy) status = 'server_down';
  else if (userToken === null) status = 'needs_user_bootstrap';
  else if (agentToken === null) status = 'needs_project_register';
  else if (!registered) status = 'needs_install';
  else status = 'ok';

  process.stdout.write(JSON.stringify({
    status,
    healthy,
    registered,
    project_root: root,
    project_key: key,
    has_user_token: userToken !== null,
    has_agent_token: agentToken !== null,
    legacy_token_present: legacyToken !== null,
  }) + '\n');
  return 0;
}

async function cmdBootstrap(args) {
  const root = projectRoot();
  const key = projectKey(root);
  const ctx = extractProjectContext(root);
  const endpoint = args.baseUrl.replace(/\/+$/, '') + '/mcp';
  const sid = await openSession(endpoint, null);
  const payload = await callTool(endpoint, null, sid, 'bootstrap', {
    email: args.email,
    name: ctx.name,
    description: ctx.description,
    projectDescription: ctx.project_description,
    tags: ctx.tags,
  });
  const userToken = payload.userToken;
  const agentToken = payload.agentBearerToken;
  if (!userToken || !agentToken) {
    throw new Error(`bootstrap response missing tokens: ${JSON.stringify(payload)}`);
  }
  writeUserToken(userToken);
  writeAgentToken(key, agentToken);
  process.stdout.write(JSON.stringify({
    status: 'ok',
    project_root: root,
    project_key: key,
    user_token_path: USER_TOKEN_PATH,
    agent_token_path: agentTokenPath(key),
    agent_name: ctx.name,
    tags: ctx.tags,
  }) + '\n');
  return 0;
}

async function cmdRegisterProject(args) {
  const userToken = readUserToken();
  if (!userToken) {
    process.stderr.write(JSON.stringify({ status: 'error', reason: 'no_user_token' }) + '\n');
    return 2;
  }
  const root = projectRoot();
  const key = projectKey(root);
  const ctx = extractProjectContext(root);
  const endpoint = args.baseUrl.replace(/\/+$/, '') + '/mcp';
  const sid = await openSession(endpoint, userToken);
  const payload = await callTool(endpoint, userToken, sid, 'register_agent', {
    name: ctx.name,
    description: ctx.description,
    projectDescription: ctx.project_description,
    tags: ctx.tags,
  });
  const agentToken = payload.agentBearerToken;
  if (!agentToken) {
    throw new Error(`register_agent response missing token: ${JSON.stringify(payload)}`);
  }
  writeAgentToken(key, agentToken);
  process.stdout.write(JSON.stringify({
    status: 'ok',
    project_root: root,
    project_key: key,
    agent_token_path: agentTokenPath(key),
    agent_name: ctx.name,
    tags: ctx.tags,
  }) + '\n');
  return 0;
}

async function cmdInstall(args) {
  const root = projectRoot();
  const key = projectKey(root);
  const token = readAgentToken(key);
  if (!token) {
    process.stderr.write(JSON.stringify({
      status: 'error', reason: 'no_agent_token_for_project',
    }) + '\n');
    return 2;
  }
  if (args.scope === 'project') {
    const p = writeProjectMcpJson(args.baseUrl, token, root);
    process.stdout.write(JSON.stringify({
      status: 'ok',
      scope: args.scope,
      project_root: root,
      mcp_json: p,
      url_template: '${AN_BASE_URL:-' + args.baseUrl.replace(/\/+$/, '') + '}/mcp',
    }) + '\n');
    return 0;
  }
  const out = claudeMcpAdd(args.baseUrl, token, args.scope, root);
  if (out.status !== 0) {
    process.stderr.write(JSON.stringify({
      status: 'error',
      reason: 'claude_mcp_add_failed',
      stdout: out.stdout,
      stderr: out.stderr,
    }) + '\n');
    return out.status || 1;
  }
  process.stdout.write(JSON.stringify({
    status: 'ok',
    scope: args.scope,
    project_root: root,
    url: args.baseUrl.replace(/\/+$/, '') + '/mcp',
  }) + '\n');
  return 0;
}

function cmdShowContext() {
  const root = projectRoot();
  const ctx = extractProjectContext(root);
  process.stdout.write(JSON.stringify({ project_root: root, context: ctx }, null, 2) + '\n');
  return 0;
}

// ─────────────────── argparse ───────────────────

function parseArgs(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd) return null;
  const opts = {
    cmd,
    baseUrl: process.env.AN_BASE_URL || DEFAULT_BASE_URL,
    scope: 'project',
  };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--base-url') opts.baseUrl = rest[++i];
    else if (a.startsWith('--base-url=')) opts.baseUrl = a.slice('--base-url='.length);
    else if (a === '--scope') opts.scope = rest[++i];
    else if (a.startsWith('--scope=')) opts.scope = a.slice('--scope='.length);
    else if (a === '--email') opts.email = rest[++i];
    else if (a.startsWith('--email=')) opts.email = a.slice('--email='.length);
  }
  if (!['user', 'project', 'local'].includes(opts.scope)) {
    process.stderr.write(`invalid --scope: ${opts.scope}\n`);
    return null;
  }
  if (cmd === 'bootstrap' && !opts.email) {
    process.stderr.write('bootstrap: --email is required\n');
    return null;
  }
  return opts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write(
      'usage: setup.js {check|bootstrap|register-project|install|show-context} [opts]\n',
    );
    return 1;
  }
  try {
    switch (args.cmd) {
      case 'check': return await cmdCheck(args);
      case 'bootstrap': return await cmdBootstrap(args);
      case 'register-project': return await cmdRegisterProject(args);
      case 'install': return await cmdInstall(args);
      case 'show-context': return cmdShowContext();
      default:
        process.stderr.write(`unknown subcommand: ${args.cmd}\n`);
        return 1;
    }
  } catch (e) {
    process.stderr.write(JSON.stringify({ status: 'error', reason: String(e.message || e) }) + '\n');
    return 1;
  }
}

main().then((code) => process.exit(code), (e) => {
  process.stderr.write(JSON.stringify({ status: 'error', reason: String(e.message || e) }) + '\n');
  process.exit(1);
});
