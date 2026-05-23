#!/usr/bin/env node
// agentnetwork SessionStart hook.
//
// If the local inbox for this project has unprocessed questions, emit
// additionalContext so the agent offers /agentnetwork:inbox-process. Silent
// (and exit 0) in every other case — this hook fires for every Claude Code
// session in every directory, so it must never noise up unrelated sessions
// and must never fail.
//
// Cross-platform: Node 20+ stdlib only. Replaces the legacy session-start.sh
// so the hook works on Windows (where bash + python3 are not guaranteed).

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function silentExit() {
  process.exit(0);
}

try {
  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT;
  if (!pluginRoot) silentExit();

  const inboxScript = path.join(pluginRoot, 'scripts', 'inbox.js');
  if (!fs.existsSync(inboxScript)) silentExit();

  const r = spawnSync(process.execPath, [inboxScript, 'status'], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (r.status !== 0 || !r.stdout) silentExit();

  let parsed;
  try {
    parsed = JSON.parse(r.stdout);
  } catch (_) {
    silentExit();
  }

  const n = Number(parsed && parsed.unprocessed);
  if (!Number.isFinite(n) || n <= 0) silentExit();

  const plural = n === 1 ? '' : 's';
  const msg =
    `agentnetwork: you have ${n} unprocessed question${plural} in the local inbox ` +
    '(written by the background daemon). Offer to run /agentnetwork:inbox-process ' +
    'to drain them, or /agentnetwork:listen to keep an in-session loop going. ' +
    'Skip silently if the user is busy with something unrelated.';

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: msg,
      },
    }) + '\n',
  );
  process.exit(0);
} catch (_) {
  silentExit();
}
