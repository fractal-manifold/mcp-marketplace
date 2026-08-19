#!/usr/bin/env node
// tokenmonitor-mcp-js entry point. Same CLI flags as the Go impl.

import { createServer } from "node:http";
import { request as httpRequest } from "node:http";
import process from "node:process";

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
import { run as leaderRun, tryListen } from "./leader.js";
import { serve as mcpServe } from "./mcp/server.js";
import { Publisher as MdnsPublisher } from "./mdns.js";
import { Tailer, TailerController } from "./serialTailer.js";
import { LeaseManager, NopController } from "./usbprov/lease.js";
import { PanelGenerator } from "./panelGenerator.js";

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
    "tokenmonitor-mcp-js — Node.js implementation of tokenmonitor-mcp",
    "",
    "Usage:",
    "  tokenmonitor-mcp-js [--config PATH]          # MCP stdio + leader-elected broker (default)",
    "  tokenmonitor-mcp-js --daemon [--config PATH] # standalone broker only",
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

async function runDaemon(cfg, logs, logger) {
  const state = new State();
  state.setRole(Role.LEADER);
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
  if (!server) { logger.error(`listen ${cfg.server.bind}:${cfg.server.port}: address in use`); return 1; }
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
  try {
    // SIGTERM/SIGINT → graceful shutdown so the finally runs and children are
    // reaped. Registering a listener also overrides Node's default abrupt exit,
    // which would otherwise orphan the detached generators (Go gets this via
    // signal.NotifyContext).
    await new Promise((resolve) => {
      const done = () => resolve();
      process.once("SIGTERM", done);
      process.once("SIGINT", done);
    });
  } finally {
    otaAbort.abort();
    await panelGen.stop();
    if (mdnsPub) await mdnsPub.close();
  }
  return 0;
}

async function runMCP(cfg, logs, logger, configErr = null) {
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
    await mcpServe({
      cfg,
      state: new State(),
      logs,
      registry: openRegistry(logger),
      version: VERSION,
      configErr,
    });
    return 0;
  }

  const state = new State();
  const cache = new auth.NonceCache(cfg.security.nonce_cache_ttl_seconds);
  const fwBuf = new LogBuffer(cfg.serial.lines || 2000);
  let tailer = null;
  const fwLogs = (limit) => ({ connected: tailer ? tailer.connected() : false, total_available: fwBuf.length, lines: fwBuf.tail(limit) });
  const abortCtrl = new AbortController();
  const registry = openRegistry(logger);
  // Serial-lease table: followers ask this leader to yield the USB port. Built
  // once; the controller reaches the lazily-created tailer via a getter. When
  // no serial device is configured, a NopController leaves every port free.
  const serialCtrl = cfg.serial.device
    ? new TailerController(() => tailer)
    : new NopController();
  const leaseManager = new LeaseManager(serialCtrl, 0);

  // Broker self-version check: best-effort, started once at startup and NOT
  // scoped to leadership — even a follower session should surface "broker
  // outdated" via tokenmonitor_health / tokenmonitor_status. Shares the MCP
  // abort so it stops when the server shuts down. Mirrors Go's
  // go updatecheck.Run(ctx, Version, st, logger).
  updatecheck.run(state, { baked: VERSION, logger, abortSignal: abortCtrl.signal });

  // makeServer is called by tryListen on each leadership attempt. The
  // server it returns is the actual HTTP server — no probe-then-relisten.
  const makeServer = () => {
    if (cfg.serial.device && !tailer) {
      tailer = new Tailer(cfg.serial.device, fwBuf, { baud: cfg.serial.baud });
      tailer.start();
    }
    const usageCache = usage.buildCache(cfg, { credsModule: creds, logger });
    const spendCache = spend.buildSpendCache(cfg, { logger });
    const handler = createHandler({ cfg, cache, state, fwLogs, registry, logger, usageCache, spendCache, leaseManager });
    return createServer(handler);
  };

  const onAcquired = async (_server) => {
    // Reap lapsed leases (leader-scoped): a crashed follower's lease must not
    // wedge the tailer off its port forever.
    const leaseReaper = setInterval(() => { try { leaseManager.ReapExpired(); } catch {} }, 1000);
    // The HTTP server is already listening. Hold until aborted.
    // mDNS publication is scoped to the leader: only the process that
    // actually owns the bound port should answer "I'm the broker" on
    // the LAN.
    let mdnsPub = null;
    if (registry) {
      try { mdnsPub = await MdnsPublisher.start(cfg.server.bind, cfg.server.port, registry, logger,
        () => state.lastRequestAt()); }
      catch (e) { logger.warn(`mdns: ${e.message} (broker discovery disabled)`); }
    }
    // Pull-OTA poller, scoped to leadership: it shares the leader's abort
    // signal, so losing the bind tears it down alongside mDNS/the tailer.
    ota.run(cfg, registry, abortCtrl.signal, logger);
    // Custom-panel generators, scoped to leadership: torn down (SIGTERM →
    // SIGKILL) when this peer loses the bound port.
    const panelGen = new PanelGenerator(cfg, registry, logger);
    panelGen.start(abortCtrl.signal);
    try {
      await new Promise((resolve) => {
        abortCtrl.signal.addEventListener("abort", resolve, { once: true });
      });
    } finally {
      clearInterval(leaseReaper);
      await panelGen.stop();
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
  let configErr = null;
  try {
    cfg = loadConfig(flags.config || "");
  } catch (e) {
    // Every mode but stdio MCP has a human reading stderr, so a broken config
    // stays fatal there. In MCP mode exiting is the worst possible response:
    // the client never sees `initialize`, drops the server from the session,
    // and the user is told nothing. Start degraded instead — tools up, broker
    // down (see runMCP).
    if (flags.once || flags.status || flags.daemon) {
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
  if (flags.daemon) return await runDaemon(cfg, logs, logger);
  return await runMCP(cfg, logs, logger, configErr);
}

main().then((code) => process.exit(code ?? 0)).catch((e) => {
  process.stderr.write(`fatal: ${e.stack || e.message}\n`); process.exit(1);
});
