// TOML config loader, schema-compatible with cwm-mcp Go.

import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

import TOML from "@iarna/toml";

export const DEFAULT_PATH = "~/.config/claude-wall-monitor/cwm.toml";
export const LEGACY_PATH = "~/.config/claude-wall-monitor/service.toml";
export const DEVICES_DIR = "~/.config/claude-wall-monitor/devices";
export const FIRMWARE_DIR = "~/.config/claude-wall-monitor/firmware";

export function expandUser(p) {
  if (!p) return p;
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

export function devicesPath() {
  return expandUser(DEVICES_DIR);
}

export function firmwarePath() {
  return expandUser(FIRMWARE_DIR);
}

// Default ordered list of model IDs exposed in /usage/gemini.slots when
// [gemini].models is unset. Pro is the headline model; Flash burns
// fastest. The firmware dashboard renders at most MAX_GEMINI_MODELS.
export const DEFAULT_GEMINI_MODELS = ["gemini-2.5-pro", "gemini-2.5-flash"];
export const MAX_GEMINI_MODELS = 3;

function defaults() {
  return {
    server: { bind: "127.0.0.1", port: 8765 },
    auth: { psk_passphrase: "", psk_hex: "" },
    credentials: { oauth_path: "~/.claude/.credentials.json" },
    codex: { enabled: false, auth_path: "~/.codex/auth.json" },
    gemini: {
      enabled: false,
      creds_path: "~/.gemini/oauth_creds.json",
      projects_path: "~/.gemini/projects.json",
      models: [],
    },
    usage: { cache_ttl_seconds: 30 },
    security: { max_timestamp_skew_seconds: 60, nonce_cache_ttl_seconds: 300 },
    logging: { level: "INFO" },
    serial: { device: "", baud: 115200, lines: 2000 },
    pskBytes: Buffer.alloc(0),
  };
}

function mergeSection(target, src, name) {
  if (!src || !src[name]) return;
  Object.assign(target[name], src[name]);
}

export function load(path) {
  const explicit = !!path;
  let resolved = expandUser(path || DEFAULT_PATH);
  if (!existsSync(resolved) && !explicit) {
    const legacy = expandUser(LEGACY_PATH);
    if (existsSync(legacy)) resolved = legacy;
  }
  if (!existsSync(resolved)) throw new Error(`read ${resolved}: file not found`);

  const raw = readFileSync(resolved, "utf8");
  const parsed = TOML.parse(raw);
  const cfg = defaults();
  for (const k of ["server", "auth", "credentials", "codex", "gemini", "usage", "security", "logging", "serial"]) {
    mergeSection(cfg, parsed, k);
  }
  if (cfg.auth.psk_passphrase) {
    if (cfg.auth.psk_passphrase.length < 8) throw new Error("auth.psk_passphrase must be at least 8 characters");
    cfg.pskBytes = createHash("sha256").update(cfg.auth.psk_passphrase, "utf8").digest();
  } else if (cfg.auth.psk_hex) {
    if (cfg.auth.psk_hex.length !== 64) throw new Error("auth.psk_hex must be exactly 64 hex characters");
    if (!/^[0-9a-fA-F]{64}$/.test(cfg.auth.psk_hex)) throw new Error("auth.psk_hex is not valid hex");
    cfg.pskBytes = Buffer.from(cfg.auth.psk_hex, "hex");
    cfg.auth.psk_hex = cfg.auth.psk_hex.toLowerCase();
  } else {
    throw new Error("auth: either psk_passphrase or psk_hex is required");
  }
  cfg.logging.level = (cfg.logging.level || "INFO").toUpperCase();

  cfg.psk = () => cfg.pskBytes;
  cfg.oauthPathAbs = () => expandUser(cfg.credentials.oauth_path);
  cfg.codexAuthPathAbs = () => expandUser(cfg.codex.auth_path);
  cfg.geminiCredsPathAbs = () => expandUser(cfg.gemini.creds_path);
  cfg.geminiProjectsPathAbs = () => expandUser(cfg.gemini.projects_path);
  cfg.geminiModels = () => {
    const src = (cfg.gemini.models && cfg.gemini.models.length > 0)
      ? cfg.gemini.models
      : DEFAULT_GEMINI_MODELS;
    return src.slice(0, MAX_GEMINI_MODELS);
  };
  return cfg;
}
