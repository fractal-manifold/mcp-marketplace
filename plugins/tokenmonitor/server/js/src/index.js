#!/usr/bin/env node
// tokenmonitor-mcp-js entry point. Same CLI flags as the Go impl.

import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { VERSION, RUNTIME } from "./version.js";
import * as auth from "./auth.js";
import * as creds from "./creds.js";
import * as ota from "./ota.js";
import * as updatecheck from "./updatecheck.js";
import * as usage from "./usage.js";
import * as spend from "./spend.js";
import { load as loadConfig, devicesPath, unusableConfig } from "./config.js";
import { Buffer as LogBuffer } from "./logbuf.js";
import { State, Role } from "./state.js";
import { Registry } from "./registry/store.js";
import { createHandler } from "./broker/server.js";
import { tryListen } from "./leader.js";
import { serve as mcpServe } from "./mcp/server.js";
import { Publisher as MdnsPublisher } from "./mdns.js";
import { Tailer, TailerController } from "./serialTailer.js";
import { LeaseManager, NopController } from "./usbprov/lease.js";
import { PanelGenerator } from "./panelGenerator.js";
import { acquireDaemonLock, createLease, startDaemon, waitForNoSessions } from "./sessionLife.js";

const ENTRY_PATH = fileURLToPath(import.meta.url);

function parseFlags(argv) {
  const out = { config: "", daemon: false, persistentDaemon: false, once: false, status: false, logs: false, version: false, probe: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config") out.config = argv[++i] || "";
    else if (a.startsWith("--config=")) out.config = a.slice(9);
    else if (a === "--daemon") out.daemon = true;
    else if (a === "--persistent-daemon") out.persistentDaemon = true;
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
    "tokenmonitor-mcp-js — Node.js implementation of tokenmonitor-mcp",
    "",
    "Usage:",
    "  tokenmonitor-mcp-js [--config PATH]          # MCP stdio; keeps one shared daemon alive",
    "  tokenmonitor-mcp-js --daemon [--config PATH] # broker until the last session exits",
    "  tokenmonitor-mcp-js --persistent-daemon      # explicit always-on broker",
    "  tokenmonitor-mcp-js --once                   # validate creds and exit",
    "  tokenmonitor-mcp-js --status                 # probe local broker, print JSON",
    "  tokenmonitor-mcp-js --version | --probe",
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
  catch (e) {
    if (/flock/.test(e.message)) {
      // fs-ext native module missing/uncompiled. This is a deployment bug,
      // not a normal "no devices yet" state (the dir is auto-created). Do
      // NOT downgrade quietly: without per-device PSKs every device on a
      // per-device key authenticates against the global PSK and is REJECTED
      // (bad signature). Make it loud and actionable.
      logger.error(`registry: ${e.message} — per-device auth DISABLED; devices on a per-device PSK will be REJECTED (bad signature). Fix: rebuild js deps (npm rebuild fs-ext in the runtime dir) or run the py/go runtime.`);
    } else {
      logger.warn(`registry: ${e.message} (per-device control plane disabled)`);
    }
    return null;
  }
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
      headers: { "X-Tmon-Timestamp": ts, "X-Tmon-Nonce": nonce, "X-Tmon-Signature": sig },
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

async function runDaemon(cfg, logs, logger, persistent = false) {
  const daemonLock = await acquireDaemonLock();
  if (!daemonLock.acquired) {
    logger.info("daemon singleton: another broker daemon is already running");
    return 0;
  }
  try { return await serveDaemon(cfg, logs, logger, persistent); }
  finally { daemonLock.close(); }
}

async function serveDaemon(cfg, logs, logger, persistent) {
  const state = new State();
  state.setRole(Role.LEADER);
  state.enableShared();
  const cache = new auth.NonceCache(cfg.security.nonce_cache_ttl_seconds);
  const registry = openRegistry(logger);
  const fwBuf = new LogBuffer(cfg.serial.lines || 2000);
  let tailer = null;
  if (cfg.serial.device) { tailer = new Tailer(cfg.serial.device, fwBuf, { baud: cfg.serial.baud }); tailer.start(); }
  const fwLogs = (limit) => ({ connected: tailer ? tailer.connected() : false, total_available: fwBuf.length, lines: fwBuf.tail(limit) });
  // Serial-lease table: followers ask this leader to yield the USB port. The
  // controller is the live tailer when a serial device is configured, else a
  // NopController (every port free). Mirrors Go main.go.
  const serialCtrl = cfg.serial.device
    ? new TailerController(() => tailer)
    : new NopController();
  const leaseManager = new LeaseManager(serialCtrl, 0);
  const usageCache = usage.buildCache(cfg, { credsModule: creds, logger });
  const spendCache = spend.buildSpendCache(cfg, { logger });
  const handler = createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache, spendCache, leaseManager });
  const server = await tryListen(() => createServer(handler), cfg.server.bind, cfg.server.port);
  if (!server) {
    logger.error(`listen ${cfg.server.bind}:${cfg.server.port}: address in use`);
    return 1;
  }
  logger.info(`broker: serving on ${cfg.server.bind}:${cfg.server.port}`);
  let mdnsPub = null;
  if (registry) {
    try { mdnsPub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry, logger,
        () => state.lastRequestAt()); }
    catch (e) { logger.warn(`mdns: ${e.message} (broker discovery disabled)`); }
  }
  // Pull-OTA poller (inert unless [ota] is configured). This process is the
  // leader by construction in daemon mode — it owns the bound socket.
  const otaAbort = new AbortController();
  // Reap lapsed leases so a follower that crashed mid-session cannot wedge the
  // tailer off its port forever. Scoped to the leader's lifecycle.
  const leaseReaper = setInterval(() => { try { leaseManager.ReapExpired(); } catch {} }, 1000);
  otaAbort.signal.addEventListener("abort", () => clearInterval(leaseReaper), { once: true });
  ota.run(cfg, registry, otaAbort.signal, logger);
  // Custom-panel generators: leader-scoped (daemon is always the leader).
  // No-op when [panel.command] is unconfigured; shares the OTA abort.
  const panelGen = new PanelGenerator(cfg, registry, logger);
  panelGen.start(otaAbort.signal);
  // Broker self-version check: best-effort, started once at startup (not
  // leader-scoped — a daemon is the leader by construction). Shares the OTA
  // abort so it tears down with the process. Mirrors Go's go updatecheck.Run.
  updatecheck.run(state, { baked: VERSION, logger, abortSignal: otaAbort.signal });
  const idleWait = persistent ? null : waitForNoSessions(logger);
  try {
    // SIGTERM/SIGINT → graceful shutdown so the finally runs and children are
    // reaped. Registering a listener also overrides Node's default abrupt exit,
    // which would otherwise orphan the detached generators (Go gets this via
    // signal.NotifyContext).
    const signalWait = new Promise((resolve) => {
      const done = () => resolve();
      process.once("SIGTERM", done);
      process.once("SIGINT", done);
    });
    await (idleWait ? Promise.race([signalWait, idleWait.promise]) : signalWait);
  } finally {
    idleWait?.cancel();
    otaAbort.abort();
    clearInterval(leaseReaper);
    await panelGen.stop();
    if (mdnsPub) await mdnsPub.close();
    if (tailer) tailer.stop();
    await new Promise((resolve) => server.close(resolve));
  }
  return 0;
}

async function runMCP(cfg, logs, logger, configErr = null, configPath = "") {
  if (configErr) {
    // Degraded start: tools up so the user can be told what is wrong, but no
    // broker. The config we are holding is invented (unusableConfig), so
    // serving devices with it would answer every signed request with the wrong
    // key — worse than not answering at all. It also must never win leader
    // election and displace a healthy peer that CAN serve.
    logger.error(`config: ${configErr.message}`);
    logger.error(
      "config: starting degraded — MCP tools only, broker NOT started. " +
        "Fix the config and restart; run tokenmonitor_health for details.",
    );
    // It must not spawn a daemon with invented credentials, but this is still
    // a live CLI/UI session and therefore keeps a healthy daemon owned by a
    // different adapter alive.
    let sessionLease = null;
    try { sessionLease = createLease(); }
    catch (e) { logger.error(`sessions: ${e.message}`); }
    try {
      await mcpServe({
        cfg,
        state: new State(),
        logs,
        registry: openRegistry(logger),
        version: VERSION,
        configErr,
      });
    } finally {
      sessionLease?.close();
    }
    return 0;
  }

  const state = new State();
  state.setRole(Role.FOLLOWER);
  const abortCtrl = new AbortController();
  const registry = openRegistry(logger);

  let sessionLease = null;
  let daemonSupervisor = null;
  try {
    sessionLease = createLease();
    startDaemon(ENTRY_PATH, configPath);
    daemonSupervisor = setInterval(() => {
      try { startDaemon(ENTRY_PATH, configPath); }
      catch (e) { logger.error(`sessions: start broker daemon: ${e.message}`); }
    }, 5_000);
    daemonSupervisor.unref?.();
  } catch (e) {
    logger.error(`sessions: ${e.message}`);
  }

  // Broker self-version check: best-effort, started once at startup and NOT
  // scoped to leadership — even a follower session should surface "broker
  // outdated" via tokenmonitor_health / tokenmonitor_status. Shares the MCP
  // abort so it stops when the server shuts down. Mirrors Go's
  // go updatecheck.Run(ctx, Version, st, logger).
  updatecheck.run(state, { baked: VERSION, logger, abortSignal: abortCtrl.signal });

  const deps = { cfg, state, logs, registry, version: VERSION };
  try { await mcpServe(deps); }
  finally {
    abortCtrl.abort();
    if (daemonSupervisor) clearInterval(daemonSupervisor);
    sessionLease?.close();
  }
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
  let configErr = null;
  try {
    cfg = loadConfig(flags.config || "");
  } catch (e) {
    // Every mode but stdio MCP has a human reading stderr, so a broken config
    // stays fatal there. In MCP mode exiting is the worst possible response:
    // the client never sees `initialize`, drops the server from the session,
    // and the user is told nothing. Start degraded instead — tools up, broker
    // down (see runMCP).
    if (flags.once || flags.status || flags.daemon || flags.persistentDaemon) {
      process.stderr.write(`config: ${e.message}\n`);
      return 2;
    }
    configErr = e;
    cfg = unusableConfig();
  }

  const logs = new LogBuffer(200);
  const logger = buildLogger(logs, cfg.logging.level);

  // A partially-loaded config still serves, but the user has to be told which
  // of their settings are not in effect — otherwise "it works" quietly means
  // "it works, ignoring half of what you wrote".
  if (cfg.salvaged && cfg.salvaged.length > 0) {
    logger.warn(`config: loaded with ${cfg.salvaged.length - 1} section(s) ignored: ${cfg.salvaged.join("; ")}`);
  }

  // Process-level guards. A throw escaping the http 'request' listener (or a
  // rejected promise inside a handler) would otherwise take the whole process
  // down — broker socket, mDNS advertiser and the OTA poller with it. The
  // broker is a long-lived daemon serving devices in the field, so we log and
  // keep running rather than crash. Per-request errors are still mapped to a
  // 4xx/5xx inside the handlers; these handlers only catch what slips past.
  process.on("uncaughtException", (e) => {
    logger.error(`uncaughtException: ${e && (e.stack || e.message) || e}`);
  });
  process.on("unhandledRejection", (reason) => {
    logger.error(`unhandledRejection: ${reason && (reason.stack || reason.message) || reason}`);
  });

  if (flags.once) return runOnce(cfg);
  if (flags.status) return await runStatus(cfg);
  if (flags.daemon || flags.persistentDaemon) return await runDaemon(cfg, logs, logger, flags.persistentDaemon);
  return await runMCP(cfg, logs, logger, configErr, flags.config);
}

main().then((code) => process.exit(code ?? 0)).catch((e) => {
  process.stderr.write(`fatal: ${e.stack || e.message}\n`); process.exit(1);
});
