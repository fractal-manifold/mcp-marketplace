#!/usr/bin/env node
// cwm-mcp-js entry point. Same CLI flags as the Go impl.

import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import process from "node:process";

import { VERSION, RUNTIME } from "./version.js";
import * as auth from "./auth.js";
import * as creds from "./creds.js";
import * as usage from "./usage.js";
import { load as loadConfig, devicesPath } from "./config.js";
import { Buffer as LogBuffer } from "./logbuf.js";
import { State, Role } from "./state.js";
import { Registry } from "./registry/store.js";
import { createHandler } from "./broker/server.js";
import { run as leaderRun, tryListen } from "./leader.js";
import { serve as mcpServe } from "./mcp/server.js";
import { Publisher as MdnsPublisher } from "./mdns.js";
import { Tailer } from "./serialTailer.js";

function parseFlags(argv) {
  const out = { config: "", daemon: false, once: false, status: false, logs: false, version: false, probe: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config") out.config = argv[++i] || "";
    else if (a.startsWith("--config=")) out.config = a.slice(9);
    else if (a === "--daemon") out.daemon = true;
    else if (a === "--once") out.once = true;
    else if (a === "--status") out.status = true;
    else if (a === "--logs") out.logs = true;
    else if (a === "--version") out.version = true;
    else if (a === "--probe") out.probe = true;
    else if (a === "-h" || a === "--help") { printHelp(); process.exit(0); }
  }
  return out;
}

function printHelp() {
  process.stderr.write([
    "cwm-mcp-js — Node.js implementation of cwm-mcp",
    "",
    "Usage:",
    "  cwm-mcp-js [--config PATH]          # MCP stdio + leader-elected broker (default)",
    "  cwm-mcp-js --daemon [--config PATH] # standalone broker only",
    "  cwm-mcp-js --once                   # validate creds and exit",
    "  cwm-mcp-js --status                 # probe local broker, print JSON",
    "  cwm-mcp-js --version | --probe",
    "",
  ].join("\n"));
}

const stderrLogger = {
  info: (msg) => process.stderr.write(`${new Date().toISOString()} INFO  ${msg}\n`),
  warn: (msg) => process.stderr.write(`${new Date().toISOString()} WARN  ${msg}\n`),
  error: (msg) => process.stderr.write(`${new Date().toISOString()} ERROR ${msg}\n`),
};

function buildLogger(buf, level) {
  const teed = (lvl) => (msg) => {
    const line = `${new Date().toISOString()} ${lvl} ${msg}`;
    process.stderr.write(line + "\n");
    buf.writeLine(line);
  };
  return { info: teed("INFO"), warn: teed("WARN"), error: teed("ERROR") };
}

function openRegistry(logger) {
  try { return new Registry(devicesPath()); }
  catch (e) { logger.warn(`registry: ${e.message} (per-device control plane disabled)`); return null; }
}

function runOnce(cfg) {
  try { var c = creds.load(cfg.oauthPathAbs()); }
  catch (e) { process.stderr.write(`creds: ${e.message}\n`); return 1; }
  if (c.isExpired(Date.now())) { process.stderr.write(`creds: expired at ${c.expiresAtISO()}\n`); return 1; }
  process.stdout.write(`creds OK (expires_at=${c.expiresAtISO()})\n`);
  return 0;
}

function runStatus(cfg) {
  return new Promise((resolve) => {
    const addr = `${cfg.server.bind}:${cfg.server.port}`;
    const host = (cfg.server.bind === "0.0.0.0" || !cfg.server.bind) ? "127.0.0.1" : cfg.server.bind;
    const url = `http://${host}:${cfg.server.port}/credentials`;
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = "0123456789abcdef0123456789abcdef";
    const sig = auth.computeSignature(cfg.psk(), "GET", "/credentials", ts, nonce, "", "");
    const out = { addr, probe_url: url };
    const req = httpRequest({
      host, port: cfg.server.port, path: "/credentials", method: "GET", timeout: 2000,
      headers: { "X-Cwm-Timestamp": ts, "X-Cwm-Nonce": nonce, "X-Cwm-Signature": sig },
    }, (res) => {
      res.on("data", () => {}); res.on("end", () => {
        out.http_status = res.statusCode;
        out.broker = res.statusCode === 200 ? "leader_elsewhere" : "up_but_rejecting";
        process.stdout.write(JSON.stringify(out) + "\n"); resolve(0);
      });
    });
    req.on("error", (e) => { out.broker = "down"; out.error = e.message; process.stdout.write(JSON.stringify(out) + "\n"); resolve(0); });
    req.on("timeout", () => { req.destroy(); out.broker = "down"; out.error = "timeout"; process.stdout.write(JSON.stringify(out) + "\n"); resolve(0); });
    req.end();
  });
}

async function runDaemon(cfg, logs, logger) {
  const state = new State();
  state.setRole(Role.LEADER);
  const cache = new auth.NonceCache(cfg.security.nonce_cache_ttl_seconds);
  const registry = openRegistry(logger);
  const fwBuf = new LogBuffer(cfg.serial.lines || 2000);
  let tailer = null;
  if (cfg.serial.device) { tailer = new Tailer(cfg.serial.device, fwBuf, { baud: cfg.serial.baud }); tailer.start(); }
  const fwLogs = (limit) => ({ connected: tailer ? tailer.connected() : false, total_available: fwBuf.length, lines: fwBuf.tail(limit) });
  const usageCache = usage.buildCache(cfg, { credsModule: creds, logger });
  const handler = createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache });
  const server = await tryListen(() => createServer(handler), cfg.server.bind, cfg.server.port);
  if (!server) { logger.error(`listen ${cfg.server.bind}:${cfg.server.port}: address in use`); return 1; }
  logger.info(`broker: serving on ${cfg.server.bind}:${cfg.server.port}`);
  let mdnsPub = null;
  if (registry) {
    try { mdnsPub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry, logger); }
    catch (e) { logger.warn(`mdns: ${e.message} (broker discovery disabled)`); }
  }
  try {
    await new Promise(() => {}); // run until killed
  } finally {
    if (mdnsPub) await mdnsPub.close();
  }
  return 0;
}

async function runMCP(cfg, logs, logger) {
  const state = new State();
  const cache = new auth.NonceCache(cfg.security.nonce_cache_ttl_seconds);
  const fwBuf = new LogBuffer(cfg.serial.lines || 2000);
  let tailer = null;
  const fwLogs = (limit) => ({ connected: tailer ? tailer.connected() : false, total_available: fwBuf.length, lines: fwBuf.tail(limit) });
  const abortCtrl = new AbortController();
  const registry = openRegistry(logger);

  // makeServer is called by tryListen on each leadership attempt. The
  // server it returns is the actual HTTP server — no probe-then-relisten.
  const makeServer = () => {
    if (cfg.serial.device && !tailer) {
      tailer = new Tailer(cfg.serial.device, fwBuf, { baud: cfg.serial.baud });
      tailer.start();
    }
    const usageCache = usage.buildCache(cfg, { credsModule: creds, logger });
  const handler = createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache });
    return createServer(handler);
  };

  const onAcquired = async (_server) => {
    // The HTTP server is already listening. Hold until aborted.
    // mDNS publication is scoped to the leader: only the process that
    // actually owns the bound port should answer "I'm the broker" on
    // the LAN.
    let mdnsPub = null;
    if (registry) {
      try { mdnsPub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry, logger); }
      catch (e) { logger.warn(`mdns: ${e.message} (broker discovery disabled)`); }
    }
    try {
      await new Promise((resolve) => {
        abortCtrl.signal.addEventListener("abort", resolve, { once: true });
      });
    } finally {
      if (mdnsPub) await mdnsPub.close();
      if (tailer) { tailer.stop(); tailer = null; }
    }
  };

  const leaderTask = leaderRun({
    host: cfg.server.bind, port: cfg.server.port, state, makeServer, onAcquired,
    abortSignal: abortCtrl.signal, logger,
  });

  const deps = { cfg, state, logs, registry, version: VERSION };
  try { await mcpServe(deps); }
  finally { abortCtrl.abort(); await leaderTask; }
  return 0;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  if (flags.version) { process.stdout.write(VERSION + "\n"); return 0; }
  if (flags.probe) {
    try {
      await import("@iarna/toml");
      await import("@modelcontextprotocol/sdk/server/index.js");
    } catch (e) {
      process.stderr.write(`js probe: missing dependency: ${e.message}\n`);
      return 1;
    }
    process.stderr.write(`${RUNTIME} ${VERSION}\n`);
    return 0;
  }

  let cfg;
  try { cfg = loadConfig(flags.config || ""); }
  catch (e) { process.stderr.write(`config: ${e.message}\n`); return 2; }

  const logs = new LogBuffer(200);
  const logger = buildLogger(logs, cfg.logging.level);
  if (flags.once) return runOnce(cfg);
  if (flags.status) return await runStatus(cfg);
  if (flags.daemon) return await runDaemon(cfg, logs, logger);
  return await runMCP(cfg, logs, logger);
}

main().then((code) => process.exit(code ?? 0)).catch((e) => {
  process.stderr.write(`fatal: ${e.stack || e.message}\n`); process.exit(1);
});
