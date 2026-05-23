#!/usr/bin/env node
// Read/mark helpers for the agentnetwork daemon inbox.
//
// The daemon (scripts/an-mcp.js daemon) appends incoming questions to
// ~/.cache/agentnetwork/inbox/<project-key>.jsonl. This script gives skills
// a stable interface to query unprocessed entries and mark them done, without
// each skill having to know the on-disk layout.
//
// Subcommands:
//   inbox.js list [--limit N]        unprocessed entries as JSON lines
//   inbox.js mark <questionId>...    append IDs to the processed sidecar
//   inbox.js status                  counts + paths (for status skills)
//
// The processed sidecar is append-only (one questionId per line), so the
// daemon's append-only inbox and the skill's append-only sidecar never race.
//
// Cross-platform: Node 20+ stdlib only. Works on Linux, macOS, Windows.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CACHE_DIR = path.join(os.homedir(), '.cache', 'agentnetwork');
const INBOX_DIR = path.join(CACHE_DIR, 'inbox');

function gitToplevel() {
  const r = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (r.status === 0 && r.stdout) return r.stdout.trim();
  return process.cwd();
}

function projectKey(root) {
  const abs = path.resolve(root || gitToplevel());
  return crypto.createHash('sha256').update(abs).digest('hex').slice(0, 16);
}

function paths(key) {
  return {
    inbox: path.join(INBOX_DIR, `${key}.jsonl`),
    processed: path.join(INBOX_DIR, `${key}.processed`),
  };
}

function loadProcessedIds(processed) {
  if (!fs.existsSync(processed) || !fs.statSync(processed).isFile()) {
    return new Set();
  }
  const text = fs.readFileSync(processed, 'utf8');
  const out = new Set();
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s) out.add(s);
  }
  return out;
}

function* iterInbox(inbox) {
  if (!fs.existsSync(inbox) || !fs.statSync(inbox).isFile()) return;
  const text = fs.readFileSync(inbox, 'utf8');
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try {
      yield JSON.parse(s);
    } catch (_) {
      // skip malformed line, mirrors python json.JSONDecodeError path
    }
  }
}

function cmdList(args) {
  const key = projectKey();
  const { inbox, processed } = paths(key);
  const done = loadProcessedIds(processed);
  let count = 0;
  for (const q of iterInbox(inbox)) {
    const qid = q && q.id;
    if (qid && done.has(qid)) continue;
    process.stdout.write(JSON.stringify(q) + '\n');
    count += 1;
    if (args.limit && count >= args.limit) break;
  }
  return 0;
}

function cmdMark(args) {
  const key = projectKey();
  const { processed } = paths(key);
  fs.mkdirSync(path.dirname(processed), { recursive: true });
  const fd = fs.openSync(processed, 'a');
  try {
    for (const qid of args.ids) fs.writeSync(fd, qid + '\n');
  } finally {
    fs.closeSync(fd);
  }
  return 0;
}

function cmdStatus() {
  const key = projectKey();
  const { inbox, processed } = paths(key);
  let total = 0;
  for (const _ of iterInbox(inbox)) total += 1;
  const done = loadProcessedIds(processed);
  let unprocessed = 0;
  for (const q of iterInbox(inbox)) {
    if (!q || !done.has(q.id)) unprocessed += 1;
  }
  process.stdout.write(
    JSON.stringify(
      {
        project_key: key,
        inbox,
        processed_sidecar: processed,
        total,
        processed: done.size,
        unprocessed,
      },
      null,
      2,
    ) + '\n',
  );
  return 0;
}

function parseArgs(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd) return { cmd: null };
  if (cmd === 'list') {
    let limit = 0;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--limit') {
        limit = parseInt(rest[++i] || '0', 10) || 0;
      } else if (rest[i].startsWith('--limit=')) {
        limit = parseInt(rest[i].slice('--limit='.length), 10) || 0;
      }
    }
    return { cmd, limit };
  }
  if (cmd === 'mark') {
    if (rest.length === 0) {
      process.stderr.write('mark: at least one questionId required\n');
      return { cmd: null };
    }
    return { cmd, ids: rest };
  }
  if (cmd === 'status') return { cmd };
  process.stderr.write(`unknown subcommand: ${cmd}\n`);
  return { cmd: null };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.cmd) {
    process.stderr.write(
      'usage: inbox.js list [--limit N] | mark <id>... | status\n',
    );
    return 2;
  }
  if (args.cmd === 'list') return cmdList(args);
  if (args.cmd === 'mark') return cmdMark(args);
  if (args.cmd === 'status') return cmdStatus();
  return 2;
}

process.exit(main());
