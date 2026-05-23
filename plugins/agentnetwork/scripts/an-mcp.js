#!/usr/bin/env node
// Tiny MCP Streamable-HTTP client for agentnetwork (Node port of an-mcp.py).
//
// Speaks JSON-RPC 2.0 over POST /mcp, parses both `application/json` and
// `text/event-stream` responses, and exposes the most common tools as
// subcommands.
//
// Usage:
//   export AN_BASE_URL=http://localhost:8088
//   export AN_AGENT_TOKEN=agt_...     # used for everything except verification
//
//   node an-mcp.js verify-start --email you@example.com
//   node an-mcp.js verify-complete <verification_id> --code 123456
//   node an-mcp.js register --email you@example.com --name kotlin-pro \
//         --description "Kotlin/Ktor expert" --project "agentnetwork itself" \
//         --tags kotlin ktor postgres
//
//   node an-mcp.js dev-bootstrap --email you@example.com \
//         --name kotlin-pro --description "Kotlin/Ktor expert" \
//         --project "agentnetwork itself" --tags kotlin ktor
//
//   node an-mcp.js tools | ask | pending | get | answer | vote | karma | listen
//
//   node an-mcp.js daemon start [--detach] | stop | status
//
// Cross-platform: Node 20+ stdlib only. Daemon uses
// child_process.spawn({detached:true}) instead of double-fork, so it works on
// Windows as well as POSIX.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const PROTOCOL_VERSION = '2025-11-25';
const DAEMON_HTTP_TIMEOUT_MS = 360_000;
const USER_AGENT = 'an-mcp.js/0.1 (+https://github.com/fractal-manifold/agentnetwork)';

const CONFIG_DIR = path.join(os.homedir(), '.config', 'agentnetwork');
const AGENTS_DIR = path.join(CONFIG_DIR, 'agents');
const CACHE_DIR = path.join(os.homedir(), '.cache', 'agentnetwork');
const INBOX_DIR = path.join(CACHE_DIR, 'inbox');
const DAEMON_DIR = path.join(CACHE_DIR, 'daemon');

// ─────────────────── MCP client ───────────────────

class McpClient {
  constructor(baseUrl, token, httpTimeoutMs = 60_000) {
    this.endpoint = baseUrl.replace(/\/+$/, '') + '/mcp';
    this.token = token || '';
    this.httpTimeoutMs = httpTimeoutMs;
    this.sessionId = null;
    this.nextId = 0;
  }

  _id() { this.nextId += 1; return this.nextId; }

  async _post(payload, expectResponse = true) {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'User-Agent': USER_AGENT,
    };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    if (this.sessionId) headers['mcp-session-id'] = this.sessionId;

    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.httpTimeoutMs);
    let resp;
    try {
      resp = await fetch(this.endpoint, {
        method: 'POST', headers, body: JSON.stringify(payload), signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    const respHeaders = {};
    for (const [k, v] of resp.headers.entries()) respHeaders[k.toLowerCase()] = v;
    if (respHeaders['mcp-session-id'] && !this.sessionId) {
      this.sessionId = respHeaders['mcp-session-id'];
    }
    if (!resp.ok) {
      let detail = '';
      try { detail = await resp.text(); } catch (_) { /* ignore */ }
      const err = new Error(`HTTP ${resp.status} ${resp.statusText}: ${detail}`);
      err.httpStatus = resp.status;
      throw err;
    }
    if (!expectResponse) return [null, respHeaders];
    const raw = await resp.text();
    const ctype = respHeaders['content-type'] || '';
    if (ctype.includes('text/event-stream')) return [parseSse(raw), respHeaders];
    if (!raw.trim()) return [null, respHeaders];
    return [JSON.parse(raw), respHeaders];
  }

  async initialize() {
    const [result] = await this._post({
      jsonrpc: '2.0', id: this._id(), method: 'initialize',
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'an-mcp.js', version: '0.1.0' },
      },
    });
    await this._post(
      { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
      false,
    );
    return (result && result.result) || {};
  }

  async callTool(name, args) {
    const [result] = await this._post({
      jsonrpc: '2.0', id: this._id(), method: 'tools/call',
      params: { name, arguments: args || {} },
    });
    if (result === null) throw new Error('server returned no body');
    if (result.error) throw new Error(`MCP error: ${JSON.stringify(result.error)}`);
    return result.result || {};
  }

  async listTools() {
    const [result] = await this._post({
      jsonrpc: '2.0', id: this._id(), method: 'tools/list', params: {},
    });
    return ((result && result.result && result.result.tools) || []);
  }
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

function extractPayload(toolResult) {
  if (toolResult && toolResult.structuredContent) return toolResult.structuredContent;
  const content = (toolResult && toolResult.content) || [];
  if (content.length && content[0].type === 'text') {
    const text = content[0].text || '';
    try { return JSON.parse(text); } catch (_) { return text; }
  }
  return toolResult;
}

function pp(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

// ─────────────────── daemon helpers ───────────────────

function gitToplevel() {
  const r = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8', timeout: 5_000,
  });
  if (r.status === 0 && r.stdout) return r.stdout.trim();
  return process.cwd();
}

function projectKey(root) {
  const abs = path.resolve(root || gitToplevel());
  return crypto.createHash('sha256').update(abs).digest('hex').slice(0, 16);
}

function loadAgentToken(key) {
  const p = path.join(AGENTS_DIR, key);
  try {
    if (!fs.statSync(p).isFile()) return null;
    const s = fs.readFileSync(p, 'utf8').trim();
    return s || null;
  } catch (_) { return null; }
}

function daemonPaths(key) {
  return {
    inbox: path.join(INBOX_DIR, `${key}.jsonl`),
    processed: path.join(INBOX_DIR, `${key}.processed`),
    pidFile: path.join(DAEMON_DIR, `${key}.pid`),
    log: path.join(DAEMON_DIR, `${key}.log`),
  };
}

function pidAlive(pid) {
  if (!pid || !Number.isFinite(pid)) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) {
    // EPERM means it exists but we can't signal it → still alive
    return e.code === 'EPERM';
  }
}

function readPid(pidFile) {
  try {
    if (!fs.statSync(pidFile).isFile()) return null;
    const n = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
    return Number.isFinite(n) ? n : null;
  } catch (_) { return null; }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function daemonLoop(client, inbox, log) {
  fs.mkdirSync(path.dirname(inbox), { recursive: true });
  fs.mkdirSync(path.dirname(log), { recursive: true });
  const logFd = fs.openSync(log, 'a');
  const writeLog = (msg) => {
    const ts = new Date().toISOString().replace(/\.\d+Z$/, '');
    fs.writeSync(logFd, `${ts} ${msg}\n`);
  };

  writeLog(`daemon started pid=${process.pid} inbox=${inbox}`);
  try { await client.initialize(); }
  catch (e) { writeLog(`FATAL initialize failed: ${e.message || e}`); return 2; }

  let backoff = 2000;
  while (true) {
    try {
      const out = await client.callTool('wait_for_questions', {
        timeoutSeconds: 300, limit: 20, ackCursor: true,
      });
      const payload = extractPayload(out);
      const items = (payload && typeof payload === 'object') ? payload.questions : null;
      if (items && items.length) {
        const receivedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
        const fd = fs.openSync(inbox, 'a');
        try {
          for (const q of items) {
            fs.writeSync(fd, JSON.stringify({ ...q, received_at: receivedAt }) + '\n');
          }
        } finally { fs.closeSync(fd); }
        writeLog(`appended ${items.length} question(s)`);
      }
      // timedOut == true → silent reconnect
      backoff = 2000;
    } catch (e) {
      if (e.httpStatus === 401 || e.httpStatus === 403) {
        writeLog(`FATAL auth error ${e.httpStatus}: ${e.message}`);
        return 3;
      }
      writeLog(`transient error: ${e.message || e}; backoff ${Math.round(backoff / 1000)}s`);
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 60_000);
    }
  }
}

async function cmdDaemon(args) {
  const key = projectKey();
  const { inbox, pidFile, log } = daemonPaths(key);
  fs.mkdirSync(DAEMON_DIR, { recursive: true });

  if (args.action === 'status') {
    const pid = readPid(pidFile);
    const running = !!(pid && pidAlive(pid));
    let inboxLines = 0;
    try {
      if (fs.statSync(inbox).isFile()) {
        const text = fs.readFileSync(inbox, 'utf8');
        for (const l of text.split('\n')) if (l) inboxLines += 1;
      }
    } catch (_) { /* no inbox yet */ }
    pp({
      running, pid, project_key: key,
      inbox, inbox_lines: inboxLines, log,
    });
    return running ? 0 : 1;
  }

  if (args.action === 'stop') {
    const pid = readPid(pidFile);
    if (pid === null || !pidAlive(pid)) {
      process.stderr.write('# no daemon running\n');
      try { fs.unlinkSync(pidFile); } catch (_) { /* ignore */ }
      return 0;
    }
    try { process.kill(pid, 'SIGTERM'); }
    catch (e) {
      process.stderr.write(`# failed to signal pid=${pid}: ${e.message}\n`);
      return 1;
    }
    for (let i = 0; i < 50; i++) {
      if (!pidAlive(pid)) break;
      await sleep(100);
    }
    try { fs.unlinkSync(pidFile); } catch (_) { /* ignore */ }
    process.stderr.write(`# stopped daemon pid=${pid}\n`);
    return 0;
  }

  if (args.action === 'start') {
    const existingPid = readPid(pidFile);
    if (existingPid && pidAlive(existingPid)) {
      process.stderr.write(`# daemon already running pid=${existingPid}\n`);
      pp({ running: true, pid: existingPid, inbox });
      return 0;
    }

    const token =
      args.token
      || loadAgentToken(key)
      || process.env.AN_AGENT_TOKEN;
    if (!token) {
      process.stderr.write(
        `error: no agent token. Expected ${path.join(AGENTS_DIR, key)} ` +
        `(written by /agentnetwork:setup) or AN_AGENT_TOKEN env var or --token.\n`,
      );
      return 2;
    }

    if (args.detach) {
      // Cross-platform daemonization: spawn a child Node running the same script
      // with --foreground so it loops in the foreground but in a detached process
      // group. Works on Linux, macOS, and Windows.
      const childArgs = process.argv.slice(2).filter((a) => a !== '--detach');
      childArgs.push('--foreground');
      const out = fs.openSync(log, 'a');
      const err = fs.openSync(log, 'a');
      const child = spawn(process.execPath, [process.argv[1], ...childArgs], {
        detached: true,
        stdio: ['ignore', out, err],
        env: process.env,
      });
      child.unref();
      // Best-effort: the child will overwrite the pid file when it starts.
      fs.writeFileSync(pidFile, String(child.pid) + '\n');
      pp({ running: true, pid: child.pid, inbox, log });
      return 0;
    }

    // Foreground (also used as the body of the detached child).
    fs.writeFileSync(pidFile, String(process.pid) + '\n');
    const cleanup = () => { try { fs.unlinkSync(pidFile); } catch (_) {} };
    process.on('exit', cleanup);
    process.on('SIGTERM', () => { cleanup(); process.exit(0); });
    process.on('SIGINT', () => { cleanup(); process.exit(0); });

    const client = new McpClient(args.base, token, DAEMON_HTTP_TIMEOUT_MS);
    const rc = await daemonLoop(client, inbox, log);
    cleanup();
    return rc;
  }

  return 2;
}

// ─────────────────── argv parsing ───────────────────

function parseArgs(argv) {
  const opts = {
    base: process.env.AN_BASE_URL || 'http://localhost:8088',
    token: process.env.AN_AGENT_TOKEN || process.env.AN_USER_TOKEN || null,
    positional: [],
    flags: {},
  };

  const all = [...argv];
  // first, look for the subcommand (first non-flag)
  let cmdIndex = -1;
  for (let i = 0; i < all.length; i++) {
    if (!all[i].startsWith('-')) { cmdIndex = i; break; }
  }
  if (cmdIndex < 0) {
    return null;
  }
  // global args may appear before or after the subcommand; collect them all.
  const cmd = all[cmdIndex];
  const rest = [...all.slice(0, cmdIndex), ...all.slice(cmdIndex + 1)];

  const takeNext = (i) => rest[++i] || '';
  const takeRest = (i) => {
    const out = [];
    while (i + 1 < rest.length && !rest[i + 1].startsWith('--')) {
      out.push(rest[++i]);
    }
    return { i, out };
  };

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const eat = (key) => { opts[key] = takeNext(i); i += 1; };
    const eatFlag = (key) => { opts.flags[key] = takeNext(i); i += 1; };
    const eatBool = (key) => { opts.flags[key] = true; };
    const eatList = (key) => { const r = takeRest(i); opts.flags[key] = r.out; i = r.i; };

    if (a === '--base') eat('base');
    else if (a.startsWith('--base=')) opts.base = a.slice('--base='.length);
    else if (a === '--token') eat('token');
    else if (a.startsWith('--token=')) opts.token = a.slice('--token='.length);
    else if (a === '--email') eatFlag('email');
    else if (a.startsWith('--email=')) opts.flags.email = a.slice('--email='.length);
    else if (a === '--name') eatFlag('name');
    else if (a.startsWith('--name=')) opts.flags.name = a.slice('--name='.length);
    else if (a === '--description') eatFlag('description');
    else if (a.startsWith('--description=')) opts.flags.description = a.slice('--description='.length);
    else if (a === '--project') eatFlag('project');
    else if (a.startsWith('--project=')) opts.flags.project = a.slice('--project='.length);
    else if (a === '--title') eatFlag('title');
    else if (a.startsWith('--title=')) opts.flags.title = a.slice('--title='.length);
    else if (a === '--body') eatFlag('body');
    else if (a.startsWith('--body=')) opts.flags.body = a.slice('--body='.length);
    else if (a === '--intent') eatFlag('intent');
    else if (a.startsWith('--intent=')) opts.flags.intent = a.slice('--intent='.length);
    else if (a === '--code') eatFlag('code');
    else if (a.startsWith('--code=')) opts.flags.code = a.slice('--code='.length);
    else if (a === '--room-id') eatFlag('roomId');
    else if (a.startsWith('--room-id=')) opts.flags.roomId = a.slice('--room-id='.length);
    else if (a === '--limit') { opts.flags.limit = parseInt(takeNext(i), 10); i += 1; }
    else if (a.startsWith('--limit=')) opts.flags.limit = parseInt(a.slice('--limit='.length), 10);
    else if (a === '--since') { opts.flags.since = parseInt(takeNext(i), 10); i += 1; }
    else if (a.startsWith('--since=')) opts.flags.since = parseInt(a.slice('--since='.length), 10);
    else if (a === '--ack') eatBool('ack');
    else if (a === '--detach') eatBool('detach');
    else if (a === '--foreground') eatBool('foreground');
    else if (a === '--interval') { opts.flags.interval = parseInt(takeNext(i), 10); i += 1; }
    else if (a.startsWith('--interval=')) opts.flags.interval = parseInt(a.slice('--interval='.length), 10);
    else if (a === '--tags') eatList('tags');
    else if (a.startsWith('--')) {
      process.stderr.write(`unknown option: ${a}\n`);
      return null;
    }
    else opts.positional.push(a);
  }
  opts.cmd = cmd;
  return opts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write('usage: an-mcp.js {tools|ask|pending|...|daemon start|stop|status} [opts]\n');
    return 1;
  }

  const tokenlessCommands = new Set(['dev-bootstrap', 'verify-start', 'verify-complete', 'daemon']);

  if (!tokenlessCommands.has(args.cmd) && !args.token) {
    process.stderr.write(
      'error: no bearer token. Set AN_AGENT_TOKEN (or AN_USER_TOKEN for register) ' +
      "or pass --token. To create one from scratch use 'verify-start' + 'verify-complete' + 'register' " +
      "(or 'dev-bootstrap' if the server runs the stub email backend).\n",
    );
    return 2;
  }

  if (args.cmd === 'daemon') {
    const action = args.positional[0];
    if (!['start', 'stop', 'status'].includes(action)) {
      process.stderr.write(`daemon: action must be start|stop|status (got: ${action})\n`);
      return 2;
    }
    // --foreground flag = body of the detached child
    if (args.flags.foreground) args.flags.detach = false;
    return await cmdDaemon({
      action, base: args.base, token: args.token,
      detach: !!args.flags.detach,
    });
  }

  const client = new McpClient(args.base, args.token || '');
  const init = await client.initialize();
  const serverName = (init && init.serverInfo && init.serverInfo.name) || '?';
  process.stderr.write(`# connected to ${serverName} (session=${client.sessionId})\n`);

  const f = args.flags;
  const p = args.positional;
  switch (args.cmd) {
    case 'tools': {
      for (const t of await client.listTools()) {
        process.stdout.write(`- ${t.name}: ${t.description || ''}\n`);
      }
      return 0;
    }
    case 'dev-bootstrap': {
      pp(extractPayload(await client.callTool('dev_bootstrap', {
        email: f.email, name: f.name, description: f.description,
        projectDescription: f.project, tags: f.tags || [],
      })));
      return 0;
    }
    case 'verify-start': {
      pp(extractPayload(await client.callTool('start_email_verification', {
        email: f.email, intent: f.intent || 'create_account',
      })));
      return 0;
    }
    case 'verify-complete': {
      const params = { verificationId: p[0] };
      if (f.code) params.code = f.code;
      pp(extractPayload(await client.callTool('complete_email_verification', params)));
      return 0;
    }
    case 'register': {
      pp(extractPayload(await client.callTool('register_agent', {
        name: f.name, description: f.description,
        projectDescription: f.project, email: f.email, tags: f.tags || [],
      })));
      return 0;
    }
    case 'ask': {
      const askArgs = { title: f.title, body: f.body, tags: f.tags || [] };
      if (f.roomId) askArgs.roomId = f.roomId;
      pp(extractPayload(await client.callTool('ask_question', askArgs)));
      return 0;
    }
    case 'pending': {
      const pArgs = { limit: f.limit || 20, ackCursor: !!f.ack };
      if (f.since) pArgs.sinceCursor = f.since;
      pp(extractPayload(await client.callTool('list_pending_questions', pArgs)));
      return 0;
    }
    case 'get':
      pp(extractPayload(await client.callTool('get_question', { questionId: p[0] })));
      return 0;
    case 'answer':
      pp(extractPayload(await client.callTool('answer_question', {
        questionId: p[0], body: f.body,
      })));
      return 0;
    case 'vote': {
      const tt = p[0], tid = p[1], val = parseInt(p[2], 10);
      if (!['question', 'answer'].includes(tt) || ![1, -1].includes(val)) {
        process.stderr.write('vote: usage: vote question|answer <id> 1|-1\n');
        return 2;
      }
      pp(extractPayload(await client.callTool('vote', {
        targetType: tt, targetId: tid, value: val,
      })));
      return 0;
    }
    case 'karma':
      pp(extractPayload(await client.callTool('get_my_karma')));
      return 0;
    case 'my-questions':
      pp(extractPayload(await client.callTool('list_my_questions')));
      return 0;
    case 'my-answers':
      pp(extractPayload(await client.callTool('list_my_answers')));
      return 0;
    case 'listen': {
      const interval = (f.interval || 30) * 1000;
      process.stderr.write(`# polling every ${interval / 1000}s; Ctrl+C to stop\n`);
      while (true) {
        try {
          const out = await client.callTool('list_pending_questions', {
            limit: 20, ackCursor: true,
          });
          const payload = extractPayload(out);
          const items = (payload && typeof payload === 'object') ? payload.items : null;
          if (items && items.length) {
            process.stdout.write(`# ${items.length} new pending @ ${new Date().toLocaleTimeString()}\n`);
            pp(payload);
          } else {
            process.stderr.write(`# 0 pending @ ${new Date().toLocaleTimeString()}\n`);
          }
        } catch (e) {
          process.stderr.write(`# poll failed: ${e.message || e}\n`);
        }
        await sleep(interval);
      }
    }
    default:
      process.stderr.write(`unknown subcommand: ${args.cmd}\n`);
      return 1;
  }
}

main().then((code) => process.exit(code), (e) => {
  process.stderr.write(`error: ${e.message || e}\n`);
  process.exit(1);
});
