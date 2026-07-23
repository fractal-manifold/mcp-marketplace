// TOML config loader, schema-compatible with tokenmonitor-mcp Go.

import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

import TOML from "@iarna/toml";

export const DEFAULT_PATH = "~/.config/tokenmonitor/tokenmonitor.toml";
export const LEGACY_PATH = "~/.config/tokenmonitor/service.toml";
export const DEVICES_DIR = "~/.config/tokenmonitor/devices";
export const FIRMWARE_DIR = "~/.config/tokenmonitor/firmware";

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

// Default ordered list of model IDs exposed in /usage/antigravity.slots when
// [antigravity].models is unset. Antigravity (agy, the successor to the
// retired Gemini CLI) surfaces the Flash and Pro families; prefix matching
// tolerates the effort suffix (-low/-medium/-high) Google appends. The
// firmware dashboard renders at most MAX_ANTIGRAVITY_MODELS.
export const DEFAULT_ANTIGRAVITY_MODELS = ["gemini-3.5-flash", "gemini-3.1-pro"];
export const MAX_ANTIGRAVITY_MODELS = 3;

function defaults() {
  return {
    server: { bind: "127.0.0.1", port: 8765 },
    auth: { psk_passphrase: "", psk_hex: "" },
    credentials: { oauth_path: "~/.claude/.credentials.json" },
    // Default config tracks all three providers; one with no local creds
    // just serves "creds missing" until its CLI logs in.
    codex: { enabled: true, auth_path: "~/.codex/auth.json" },
    // Antigravity CLI (agy, successor to the retired Gemini CLI). The OAuth
    // creds the CLI writes still live under ~/.gemini/ (shared layout). A
    // legacy [gemini] section is still accepted and merged in below.
    antigravity: {
      enabled: true,
      creds_path: "~/.gemini/oauth_creds.json",
      projects_path: "~/.gemini/projects.json",
      // OS keyring service holding agy's consumer OAuth token (the quota RPC
      // requires it; the oauth_creds.json token is rejected there). Read via
      // `secret-tool lookup service <name>`.
      keyring_service: "gemini",
      models: [],
    },
    usage: { cache_ttl_seconds: 30 },
    // Locally-computed token spend (see compat/SPEND_WIRE.md). Parses the
    // CLI logs on this host; no admin key. Enabled by default — it only
    // reads files that already exist for whichever CLIs are signed in.
    spend: {
      enabled: true,
      cache_ttl_seconds: 300,
      claude_projects_path: "~/.claude/projects",
      claude_stats_cache_path: "~/.claude/stats-cache.json",
      codex_sessions_path: "~/.codex/sessions",
      // Antigravity CLI conversation trajectory store. The legacy
      // gemini_tmp_path key is merged into this in load() for back-compat.
      antigravity_conversations_path: "~/.gemini/antigravity/conversations",
    },
    // Model price table used to turn tokens into USD. Source of truth is
    // LiteLLM's machine-readable table (same data ccusage uses); cached on
    // disk with an embedded fallback so $ works offline.
    pricing: {
      url: "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json",
      cache_path: "~/.config/tokenmonitor/pricing-cache.json",
      ttl_hours: 24,
    },
    // Optional custom-panel screen source. The user's own program writes a
    // self-describing JSON document (charts / tables) that the broker serves
    // verbatim from GET /device/<id>/panel. Everything empty ⇒ feature off (404).
    // file: which document to serve — either a bare string (shorthand for the
    //   "default" entry) or a [panel.file] table keyed by device id with a
    //   "default" fallback (TOML yields a string or an object).
    // dir: per-device dir (<dir>/<id>.json wins, then <dir>/default.json);
    //   slots between the explicit file entry and file "default".
    // command: optional per-device generator the broker launches itself
    //   (leader-scoped — see panelGenerator.js). A [panel.command] table keyed
    //   by device id with a "default" fallback; each value is an argv array
    //   run without a shell.
    panel: { file: "", dir: "", command: {} },
    security: { max_timestamp_skew_seconds: 60, nonce_cache_ttl_seconds: 300 },
    logging: { level: "INFO" },
    serial: { device: "", baud: 115200, lines: 2000 },
    // Broker-driven OTA. Mirror of Go config.OTAConfig. Enabled by default
    // but inert until a [[ota.keys]] entry is added — without a pubkey the
    // broker can't verify a manifest and refuses to stage one it can't
    // authenticate.
    ota: {
      enabled: true,
      releases_repo: "https://github.com/fractal-manifold/tokenmonitor-ota-releases",
      poll_interval_minutes: 60,
      keys: [],
      // Rolling GitHub tag that holds the dev-channel prerelease assets.
      // Devices on the "dev" channel fetch
      // <repo>/releases/download/<dev_tag>/update-<SKU>.json instead of the
      // stable latest/download redirect. Must match publish.py's dev tag.
      dev_tag: "dev",
    },
    pskBytes: Buffer.alloc(0),
  };
}

function mergeSection(target, src, name) {
  if (!src || !src[name]) return;
  Object.assign(target[name], src[name]);
}

// mergeLegacyGemini folds a deprecated pre-rename [gemini] section /
// gemini_tmp_path forward into the canonical antigravity fields when the new
// keys are absent. Detection uses key presence in the parsed TOML so we don't
// confuse "not provided" with "set to a zero value". Mirror of Go
// config.mergeLegacyGemini.
function mergeLegacyGemini(cfg, parsed) {
  if (!parsed) return;
  if (parsed.antigravity == null && parsed.gemini != null) {
    const g = parsed.gemini;
    cfg.antigravity.enabled = !!g.enabled;
    if (g.creds_path) cfg.antigravity.creds_path = g.creds_path;
    if (g.projects_path) cfg.antigravity.projects_path = g.projects_path;
    if (Array.isArray(g.models) && g.models.length > 0) cfg.antigravity.models = g.models;
  }
  const sp = parsed.spend;
  if (sp && sp.antigravity_conversations_path == null && sp.gemini_tmp_path) {
    cfg.spend.antigravity_conversations_path = sp.gemini_tmp_path;
  }
  // Drop the legacy key if mergeSection copied it verbatim onto cfg.spend so
  // the resolved config exposes only the canonical field.
  if (cfg.spend && "gemini_tmp_path" in cfg.spend) delete cfg.spend.gemini_tmp_path;
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
  for (const k of ["server", "auth", "credentials", "codex", "antigravity", "usage", "spend", "pricing", "panel", "security", "logging", "serial", "ota"]) {
    mergeSection(cfg, parsed, k);
  }
  // Back-compat: a legacy tokenmonitor.toml uses [gemini] / gemini_tmp_path
  // (pre-rename, before the Gemini CLI → Antigravity CLI migration). When the
  // new keys are absent, fold the deprecated values forward so existing
  // installs keep working. Mirror of Go mergeLegacyGemini: detection is on key
  // presence in the parsed TOML, not on a zero value.
  mergeLegacyGemini(cfg, parsed);
  // @iarna/toml parses [[ota.keys]] into an array of {key_id, pubkey_b64}
  // objects; Object.assign copies it verbatim. Normalise to a clean array
  // of strings so callers don't trip on missing fields.
  cfg.ota.keys = (Array.isArray(cfg.ota.keys) ? cfg.ota.keys : []).map((k) => ({
    key_id: String((k && k.key_id) || ""),
    pubkey_b64: String((k && k.pubkey_b64) || ""),
  }));
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
  cfg.antigravityCredsPathAbs = () => expandUser(cfg.antigravity.creds_path);
  cfg.antigravityProjectsPathAbs = () => expandUser(cfg.antigravity.projects_path);
  cfg.claudeProjectsPathAbs = () => expandUser(cfg.spend.claude_projects_path);
  cfg.claudeStatsCachePathAbs = () => expandUser(cfg.spend.claude_stats_cache_path);
  cfg.codexSessionsPathAbs = () => expandUser(cfg.spend.codex_sessions_path);
  cfg.antigravityConvPathAbs = () => expandUser(cfg.spend.antigravity_conversations_path);
  cfg.pricingCachePathAbs = () => expandUser(cfg.pricing.cache_path);
  // Normalise panel.file (string shorthand or table) to an id -> path map.
  cfg.panelFileMap = () => {
    const f = cfg.panel.file;
    if (f && typeof f === "object") return f;
    if (typeof f === "string" && f) return { default: f };
    return {};
  };
  // Explicit per-device document (no "default" fallback), expanded. "" when
  // the device has no explicit entry.
  cfg.panelFileExplicitAbs = (deviceID) => {
    if (!deviceID) return "";
    const v = cfg.panelFileMap()[deviceID];
    return v ? expandUser(v) : "";
  };
  // The [panel.file] "default" entry (or the legacy bare file), expanded.
  cfg.panelFileDefaultAbs = () => {
    const v = cfg.panelFileMap().default;
    return v ? expandUser(v) : "";
  };
  cfg.panelDirAbs = () => (cfg.panel.dir ? expandUser(cfg.panel.dir) : "");
  // Generator commands keyed by device id (plus a possible "default"), every
  // argv element tilde-expanded (no shell). {} when no [panel.command] set —
  // panelGenerator treats that as "feature off".
  cfg.panelCommandMap = () => {
    const cmds = cfg.panel.command || {};
    const out = {};
    for (const [k, argv] of Object.entries(cmds)) {
      // Only a non-empty array of strings is a valid argv. Skip anything else
      // (a bare string, an array with non-string elements). Go rejects it at
      // TOML parse time; Python skips it too.
      if (!Array.isArray(argv) || argv.length === 0) continue;
      if (!argv.every((a) => typeof a === "string")) continue;
      out[k] = argv.map((a) => (a.startsWith("~/") ? expandUser(a) : a));
    }
    return out;
  };
  cfg.antigravityModels = () => {
    const src = (cfg.antigravity.models && cfg.antigravity.models.length > 0)
      ? cfg.antigravity.models
      : DEFAULT_ANTIGRAVITY_MODELS;
    return src.slice(0, MAX_ANTIGRAVITY_MODELS);
  };
  // OTA keyring helpers — mirror of Go OTAConfig.Configured()/Pubkey().
  cfg.otaConfigured = () => cfg.ota.enabled && !!cfg.ota.releases_repo && cfg.ota.keys.length > 0;
  cfg.otaPubkey = (keyID) => {
    for (const k of cfg.ota.keys) {
      if (k.key_id !== keyID) continue;
      let b;
      try { b = Buffer.from(k.pubkey_b64.trim(), "base64"); }
      catch { return null; }
      return b.length === 32 ? b : null;
    }
    return null;
  };
  return cfg;
}
