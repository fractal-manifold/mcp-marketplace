import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, utimesSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  acquireDaemonLock, createLease, daemonLogTail, liveSessionCount, runtimeDir, waitForNoSessions,
} from "../src/sessionLife.js";
import { loadSharedSnapshot, Role, State } from "../src/state.js";

test("runtime dir and lease files are shared through TMON_RUNTIME_DIR", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "tmon-session-js-"));
  const old = process.env.TMON_RUNTIME_DIR;
  process.env.TMON_RUNTIME_DIR = dir;
  try {
    assert.equal(runtimeDir(), dir);
    const lease = createLease();
    assert.equal(liveSessionCount(), 1);
    lease.close();
    assert.equal(liveSessionCount(), 0);
  } finally {
    if (old == null) delete process.env.TMON_RUNTIME_DIR;
    else process.env.TMON_RUNTIME_DIR = old;
  }
});

test("daemon lock is singleton and can be reacquired", async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "tmon-lock-js-"));
  const old = process.env.TMON_RUNTIME_DIR;
  process.env.TMON_RUNTIME_DIR = dir;
  try {
    const a = await acquireDaemonLock();
    assert.equal(a.acquired, true);
    const b = await acquireDaemonLock();
    assert.equal(b.acquired, false);
    a.close();
    const c = await acquireDaemonLock();
    assert.equal(c.acquired, true);
    c.close();
  } finally {
    if (old == null) delete process.env.TMON_RUNTIME_DIR;
    else process.env.TMON_RUNTIME_DIR = old;
  }
});

test("stale leases are reaped and idle monitor resolves", async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "tmon-stale-js-"));
  const old = process.env.TMON_RUNTIME_DIR;
  process.env.TMON_RUNTIME_DIR = dir;
  try {
    const lease = createLease();
    lease.close();
    const stale = path.join(dir, "sessions", "session-dead");
    writeFileSync(stale, "0\n");
    const oldDate = new Date(Date.now() - 10_000);
    utimesSync(stale, oldDate, oldDate);
    assert.equal(liveSessionCount(Date.now(), 100), 0);
    const wait = waitForNoSessions(null, { pollMs: 5, idleGraceMs: 10, staleAfterMs: 100 });
    await wait.promise;
    wait.cancel();
  } finally {
    if (old == null) delete process.env.TMON_RUNTIME_DIR;
    else process.env.TMON_RUNTIME_DIR = old;
  }
});

test("daemon log tail is shared with MCP adapters", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "tmon-log-js-"));
  const old = process.env.TMON_RUNTIME_DIR;
  process.env.TMON_RUNTIME_DIR = dir;
  try {
    writeFileSync(path.join(dir, "broker.log"), "one\ntwo\nthree\n");
    assert.deepEqual(daemonLogTail(2), { total_available: 3, lines: ["two", "three"] });
  } finally {
    if (old == null) delete process.env.TMON_RUNTIME_DIR;
    else process.env.TMON_RUNTIME_DIR = old;
  }
});

test("daemon state snapshot is shared with MCP adapters", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "tmon-state-js-"));
  const old = process.env.TMON_RUNTIME_DIR;
  process.env.TMON_RUNTIME_DIR = dir;
  try {
    const state = new State();
    state.setRole(Role.LEADER);
    state.enableShared();
    state.recordRequest("192.168.1.4:1234", 200, 1700000000);
    const snap = loadSharedSnapshot();
    assert.equal(snap.role, "leader");
    assert.equal(snap.requests_total, 1);
    assert.equal(snap.last_request_status, 200);
  } finally {
    if (old == null) delete process.env.TMON_RUNTIME_DIR;
    else process.env.TMON_RUNTIME_DIR = old;
  }
});
