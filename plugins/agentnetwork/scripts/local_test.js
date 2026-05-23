#!/usr/bin/env node
// agentnetwork Claude Code plugin — local two-agent test harness (Node port).
//
// Provisions two sandbox directories under .local-test/{asker,answerer}/, each
// with its own .mcp.json and a fresh agt_* token, so the user can open two
// Claude Code sessions side-by-side: one asks, one answers.
//
// Each role has its own user (different email) so the votes flow works
// end-to-end (VoteService rejects voter_user_id == author_user_id).
//
// Subcommands:
//   provision   Create sandboxes, bootstrap two agents, write .mcp.json + CLAUDE.md.
//   reset       Remove .local-test/ entirely (does not revoke agents in backend).
//   status      Print whether each sandbox has a live token (calls whoami).
//
// Node 20+ stdlib only.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PROTOCOL_VERSION = '2025-11-25';
const DEFAULT_BASE_URL = 'https://agentnetwork.fractalmanifold.com';
const ROLES = ['asker', 'answerer'];
const SANDBOX_ROOT = '.local-test';
const TEMPLATES_DIR = path.join(
  __dirname, '..', 'skills', 'local-test', 'templates',
);

// ─────────────────── HTTP / JSON-RPC over MCP Streamable HTTP ───────────────────

async function postJsonRpc(endpoint, payload, token, sessionId) {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 30_000);
  let resp;
  try {
    resp = await fetch(endpoint, {
      method: 'POST', headers, body: JSON.stringify(payload), signal: ac.signal,
    });
  } finally { clearTimeout(t); }
  const respHeaders = {};
  for (const [k, v] of resp.headers.entries()) respHeaders[k.toLowerCase()] = v;
  const ctype = respHeaders['content-type'] || '';
  const raw = await resp.text();
  if (ctype.includes('text/event-stream')) return [parseSse(raw), respHeaders];
  if (!raw.trim()) return [null, respHeaders];
  return [JSON.parse(raw), respHeaders];
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
      const p = JSON.parse(dataLines.join('\n'));
      if (p && typeof p === 'object' && ('result' in p || 'error' in p)) last = p;
    } catch (_) { /* skip malformed */ }
  }
  return last;
}

async function openSession(endpoint, token) {
  const [, hdrs] = await postJsonRpc(endpoint, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'agentnetwork-local-test', version: '0.1.0' },
    },
  }, token, null);
  const sid = hdrs['mcp-session-id'];
  if (!sid) throw new Error('server did not return mcp-session-id on initialize');
  await postJsonRpc(endpoint, {
    jsonrpc: '2.0', method: 'notifications/initialized', params: {},
  }, token, sid);
  return sid;
}

async function callTool(endpoint, token, sid, name, args) {
  const [result] = await postJsonRpc(endpoint, {
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name, arguments: args },
  }, token, sid);
  if (!result || !result.result) {
    throw new Error(`tool ${name} returned no result: ${JSON.stringify(result)}`);
  }
  const toolResult = result.result;
  let parsed = toolResult.structuredContent;
  if (!parsed) {
    const content = toolResult.content || [];
    if (content.length && content[0].type === 'text') {
      try { parsed = JSON.parse(content[0].text || ''); } catch (_) { parsed = null; }
    }
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`could not parse ${name} payload: ${JSON.stringify(toolResult)}`);
  }
  if (parsed.error) throw new Error(`${name} failed: ${JSON.stringify(parsed)}`);
  return parsed;
}

async function serverHealthy(baseUrl) {
  const url = baseUrl.replace(/\/+$/, '') + '/api/v1/health';
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 5_000);
  try {
    const r = await fetch(url, { signal: ac.signal });
    return r.status >= 200 && r.status < 300;
  } catch (_) { return false; }
  finally { clearTimeout(t); }
}

// ─────────────────── repo root + sandbox layout ───────────────────

function repoRoot() {
  const r = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8', timeout: 5_000,
  });
  if (r.status === 0 && r.stdout) return r.stdout.trim();
  return process.cwd();
}

const sandboxDir = (role) => path.join(repoRoot(), SANDBOX_ROOT, role);
const mcpJsonPath = (role) => path.join(sandboxDir(role), '.mcp.json');
const claudeMdPath = (role) => path.join(sandboxDir(role), 'CLAUDE.md');

// ─────────────────── role specs ───────────────────

function roleSpec(role) {
  if (role === 'asker') {
    return {
      email: 'local-test-asker@example.com',
      name: 'local-test-asker',
      description:
        'Local two-agent test ASKER. Asks technical questions about ' +
        'Kotlin, Ktor, pgvector, MCP and Compose Web.',
      projectDescription: 'agentnetwork local two-agent test (asker side)',
      tags: ['local-test', 'asker', 'kotlin', 'ktor', 'mcp'],
    };
  }
  if (role === 'answerer') {
    return {
      email: 'local-test-answerer@example.com',
      name: 'local-test-answerer',
      description:
        'Local two-agent test ANSWERER. Watches incoming questions and ' +
        'replies with concise, useful answers about Kotlin/Ktor/MCP.',
      projectDescription: 'agentnetwork local two-agent test (answerer side)',
      tags: ['local-test', 'answerer', 'kotlin', 'ktor', 'mcp'],
    };
  }
  throw new Error(`unknown role: ${role}`);
}

// ─────────────────── filesystem helpers ───────────────────

function writeMcpJson(role, baseUrl, agentToken) {
  const p = mcpJsonPath(role);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const config = {
    mcpServers: {
      agentnetwork: {
        type: 'http',
        url: baseUrl.replace(/\/+$/, '') + '/mcp',
        headers: { Authorization: `Bearer ${agentToken}` },
      },
    },
  };
  fs.writeFileSync(p, JSON.stringify(config, null, 2) + '\n');
  try { fs.chmodSync(p, 0o600); } catch (_) { /* no-op on Windows */ }
  return p;
}

function writeClaudeMd(role) {
  const src = path.join(TEMPLATES_DIR, `${role}-CLAUDE.md`);
  const dst = claudeMdPath(role);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  if (!fs.existsSync(src) || !fs.statSync(src).isFile()) {
    throw new Error(`missing template: ${src}`);
  }
  fs.copyFileSync(src, dst);
  return dst;
}

function ensureGitignore(entry = '.local-test/') {
  const gi = path.join(repoRoot(), '.gitignore');
  const lines = fs.existsSync(gi) ? fs.readFileSync(gi, 'utf8').split('\n') : [];
  if (lines.some((l) => l.trim() === entry)) return false;
  const tail = (lines.length && lines[lines.length - 1].trim() !== '') ? '\n' : '';
  fs.appendFileSync(
    gi,
    `${tail}# agentnetwork local two-agent test sandboxes\n${entry}\n`,
  );
  return true;
}

function readAgentToken(role) {
  const p = mcpJsonPath(role);
  if (!fs.existsSync(p) || !fs.statSync(p).isFile()) return null;
  try {
    const cfg = JSON.parse(fs.readFileSync(p, 'utf8'));
    const auth = cfg.mcpServers.agentnetwork.headers.Authorization;
    if (typeof auth === 'string' && auth.startsWith('Bearer ')) {
      return auth.slice('Bearer '.length);
    }
  } catch (_) { /* ignore */ }
  return null;
}

function rmTree(p) {
  if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
}

// ─────────────────── subcommands ───────────────────

async function cmdProvision(args) {
  const baseUrl = args.baseUrl;
  if (!(await serverHealthy(baseUrl))) {
    process.stdout.write(JSON.stringify({
      status: 'error',
      reason: 'server_down',
      hint:
        'Start the stack first: `docker compose up -d postgres && ' +
        'set -a; source ./.env; set +a && ./gradlew :server:run`',
    }) + '\n');
    return 2;
  }
  if (args.force) rmTree(path.join(repoRoot(), SANDBOX_ROOT));

  const results = {};
  const endpoint = baseUrl.replace(/\/+$/, '') + '/mcp';
  for (const role of ROLES) {
    const existing = readAgentToken(role);
    if (existing && !args.force) {
      results[role] = {
        status: 'already_provisioned',
        mcp_json: mcpJsonPath(role),
      };
      continue;
    }
    const spec = roleSpec(role);
    const sid = await openSession(endpoint, null);
    const payload = await callTool(endpoint, null, sid, 'bootstrap', {
      email: spec.email,
      name: spec.name,
      description: spec.description,
      projectDescription: spec.projectDescription,
      tags: spec.tags,
    });
    const agentToken = payload.agentBearerToken;
    if (!agentToken) {
      throw new Error(`bootstrap for ${role} returned no agentBearerToken: ${JSON.stringify(payload)}`);
    }
    writeMcpJson(role, baseUrl, agentToken);
    writeClaudeMd(role);
    results[role] = {
      status: 'provisioned',
      mcp_json: mcpJsonPath(role),
      agent_name: spec.name,
      agent_email: spec.email,
    };
  }
  const gitignoreChanged = ensureGitignore();
  const askerDir = sandboxDir('asker');
  const answererDir = sandboxDir('answerer');
  process.stdout.write(JSON.stringify({
    status: 'ok',
    base_url: baseUrl,
    roles: results,
    gitignore_updated: gitignoreChanged,
    next_steps: {
      asker_terminal: `cd ${askerDir} && claude`,
      answerer_terminal: `cd ${answererDir} && claude`,
      answerer_first_prompt: '/agentnetwork:listen',
    },
  }, null, 2) + '\n');
  return 0;
}

function cmdReset() {
  const target = path.join(repoRoot(), SANDBOX_ROOT);
  if (!fs.existsSync(target)) {
    process.stdout.write(JSON.stringify({ status: 'noop', reason: 'no_sandbox_dir' }) + '\n');
    return 0;
  }
  rmTree(target);
  process.stdout.write(JSON.stringify({
    status: 'ok',
    removed: target,
    note:
      'Agents created in previous runs remain in the backend ' +
      '(no delete-agent endpoint). They become inactive but persist. ' +
      'For a clean slate: docker compose down -v && docker compose up -d postgres',
  }) + '\n');
  return 0;
}

async function cmdStatus(args) {
  const baseUrl = args.baseUrl;
  const endpoint = baseUrl.replace(/\/+$/, '') + '/mcp';
  const healthy = await serverHealthy(baseUrl);
  const out = { base_url: baseUrl, server_healthy: healthy, roles: {} };
  for (const role of ROLES) {
    const token = readAgentToken(role);
    const entry = {
      sandbox_dir: sandboxDir(role),
      mcp_json_present: fs.existsSync(mcpJsonPath(role)),
      token_cached: !!token,
    };
    if (token && healthy) {
      try {
        const sid = await openSession(endpoint, token);
        entry.whoami = await callTool(endpoint, token, sid, 'whoami', {});
      } catch (e) {
        entry.whoami_error = e.message || String(e);
      }
    }
    out.roles[role] = entry;
  }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  return 0;
}

// ─────────────────── argparse ───────────────────

function parseArgs(argv) {
  const [cmd, ...rest] = argv;
  if (!['provision', 'reset', 'status'].includes(cmd)) return null;
  const opts = { cmd, baseUrl: process.env.AN_BASE_URL || DEFAULT_BASE_URL, force: false };
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--base-url') opts.baseUrl = rest[++i];
    else if (a.startsWith('--base-url=')) opts.baseUrl = a.slice('--base-url='.length);
    else if (a === '--force') opts.force = true;
  }
  return opts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write('usage: local_test.js {provision|reset|status} [--base-url URL] [--force]\n');
    return 1;
  }
  try {
    switch (args.cmd) {
      case 'provision': return await cmdProvision(args);
      case 'reset': return cmdReset();
      case 'status': return await cmdStatus(args);
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
