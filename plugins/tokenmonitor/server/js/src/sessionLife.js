// Cross-runtime MCP-session leases and broker-daemon singleton.

import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmodSync, closeSync, mkdirSync, openSync, readFileSync, readdirSync,
  renameSync, rmSync, statSync, utimesSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

export const HEARTBEAT_MS = 5_000;
export const STALE_AFTER_MS = 30_000;
export const IDLE_GRACE_MS = 10_000;
const MAX_DAEMON_LOG_BYTES = 2 * 1024 * 1024;

export function runtimeDir(env = process.env) {
  if ((env.TMON_RUNTIME_DIR || "").trim()) return env.TMON_RUNTIME_DIR.trim();
  if ((env.XDG_RUNTIME_DIR || "").trim()) return path.join(env.XDG_RUNTIME_DIR.trim(), "tokenmonitor");
  const cache = (env.XDG_CACHE_HOME || "").trim() || path.join(os.homedir(), ".cache");
  return path.join(cache, "tokenmonitor", "runtime");
}

function ensureRuntimeDir() {
  const dir = runtimeDir();
  mkdirSync(path.join(dir, "sessions"), { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch {}
  try { chmodSync(path.join(dir, "sessions"), 0o700); } catch {}
  return dir;
}

export function createLease() {
  const dir = ensureRuntimeDir();
  const token = randomBytes(12).toString("hex");
  const leasePath = path.join(dir, "sessions", `session-${process.pid}-${token}`);
  writeFileSync(leasePath, `${process.pid}\n`, { mode: 0o600 });
  const timer = setInterval(() => {
    const now = new Date();
    try { utimesSync(leasePath, now, now); }
    catch {
      // After host suspend, the daemon may reap an old mtime before this
      // process resumes. Recreate the lease within the daemon's grace window.
      try { writeFileSync(leasePath, `${process.pid}\n`, { mode: 0o600 }); } catch {}
    }
  }, HEARTBEAT_MS);
  timer.unref?.();
  let closed = false;
  return {
    path: leasePath,
    close() {
      if (closed) return;
      closed = true;
      clearInterval(timer);
      try { rmSync(leasePath); } catch {}
    },
  };
}

function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e?.code === "EPERM"; }
}

function lockPath() { return path.join(ensureRuntimeDir(), "broker.lock"); }

function readLockPid(lockDir) {
  try { return Number.parseInt(readFileSync(path.join(lockDir, "pid"), "utf8").trim(), 10) || 0; }
  catch { return 0; }
}

export function daemonRunning() {
  const p = lockPath();
  return processAlive(readLockPid(p));
}

export async function acquireDaemonLock() {
  const p = lockPath();
  for (let tries = 0; tries < 3; tries++) {
    try {
      mkdirSync(p, { mode: 0o700 });
      const owner = String(process.pid);
      writeFileSync(path.join(p, "pid"), owner + "\n", { mode: 0o600 });
      let closed = false;
      return {
        acquired: true,
        close() {
          if (closed) return;
          closed = true;
          try {
            if (readFileSync(path.join(p, "pid"), "utf8").trim() === owner) {
              try { rmSync(path.join(runtimeDir(), "broker-state.json")); } catch {}
              rmSync(p, { recursive: true });
            }
          } catch {}
        },
      };
    } catch (e) {
      if (e?.code !== "EEXIST") throw e;
    }
    const pid = readLockPid(p);
    if (processAlive(pid)) return { acquired: false, close() {} };
    if (!pid && tries === 0) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      continue;
    }
    try { rmSync(p, { recursive: true }); } catch {}
  }
  throw new Error("could not acquire broker singleton lock");
}

export function startDaemon(entryPath, configPath = "") {
  if (daemonRunning()) return;
  const dir = ensureRuntimeDir();
  const logPath = path.join(dir, "broker.log");
  try {
    if (statSync(logPath).size > MAX_DAEMON_LOG_BYTES) renameSync(logPath, logPath + ".1");
  } catch {}
  const logFd = openSync(logPath, "a", 0o600);
  const args = [entryPath, "--daemon"];
  if (configPath) args.push("--config", configPath);
  try {
    const child = spawn(process.execPath, args, {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      windowsHide: true,
    });
    child.unref();
  } finally {
    closeSync(logFd);
  }
}

export function daemonLogTail(limit) {
  const raw = readFileSync(path.join(runtimeDir(), "broker.log"), "utf8").replace(/[\r\n]+$/, "");
  const all = raw ? raw.split("\n") : [];
  return { total_available: all.length, lines: all.slice(-limit) };
}

export function liveSessionCount(nowMs = Date.now(), staleAfterMs = STALE_AFTER_MS) {
  const sessions = path.join(ensureRuntimeDir(), "sessions");
  let live = 0;
  for (const ent of readdirSync(sessions, { withFileTypes: true })) {
    if (!ent.isFile() || !ent.name.startsWith("session-")) continue;
    const p = path.join(sessions, ent.name);
    try {
      if (nowMs - statSync(p).mtimeMs > staleAfterMs) rmSync(p);
      else live++;
    } catch {}
  }
  return live;
}

export function waitForNoSessions(logger, {
  pollMs = 2_000,
  idleGraceMs = IDLE_GRACE_MS,
  staleAfterMs = STALE_AFTER_MS,
} = {}) {
  let emptySince = 0;
  let timer;
  let settled = false;
  let resolvePromise;
  const promise = new Promise((resolve) => { resolvePromise = resolve; });
  const tick = () => {
    let count;
    try { count = liveSessionCount(Date.now(), staleAfterMs); }
    catch (e) { logger?.warn?.(`sessions: ${e.message}`); return; }
    if (count > 0) { emptySince = 0; return; }
    const now = Date.now();
    if (!emptySince) { emptySince = now; return; }
    if (now - emptySince < idleGraceMs) return;
    logger?.info?.("sessions: none remain; stopping broker daemon");
    settled = true;
    clearInterval(timer);
    resolvePromise();
  };
  timer = setInterval(tick, pollMs);
  tick();
  return {
    promise,
    cancel() {
      if (!settled) clearInterval(timer);
      settled = true;
    },
  };
}
