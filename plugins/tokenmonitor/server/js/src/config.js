// TOML config loader, schema-compatible with tokenmonitor-mcp Go.

import {
  readFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
  writeFileSync,
  linkSync,
  unlinkSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

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

// The token BOOTSTRAP_TOML carries where the generated passphrase goes. Kept as
// a distinct constant so the substitution can never silently no-op if the
// template is reworded.
const BOOTSTRAP_PASSPHRASE_PLACEHOLDER = "@@PSK_PASSPHRASE@@";

// Minimal first-run config. Deliberately much shorter than the Go SampleTOML:
// every key here is one a fresh install genuinely needs, and the three runtimes
// (go / py / js) carry it verbatim, so a short template is a small drift
// surface. Everything else falls back to defaults().
//
// Keep byte-identical with config.BootstrapTOML (go) and
// tmon_mcp.config.BOOTSTRAP_TOML (py).
export const BOOTSTRAP_TOML = `# TokenMonitor broker configuration.
# Created automatically on first run. Full documented reference:
# mcp-marketplace/plugins/tokenmonitor/server/go/README.md

[server]
# 0.0.0.0 so the ESP32 can reach the broker over the LAN. Use 127.0.0.1 to
# keep it host-local (the device then cannot poll it).
bind = "0.0.0.0"
port = 8765

[auth]
# Shared secret with the device; both sides SHA-256 it to derive the HMAC
# key. Generated randomly at first run — the pairing flow mints a separate
# per-device PSK, so you normally never have to type this one.
psk_passphrase = "${BOOTSTRAP_PASSPHRASE_PLACEHOLDER}"

[credentials]
oauth_path = "~/.claude/.credentials.json"

[codex]
# Shows "creds missing" until you log in with codex. Set false to hide it.
enabled = true
auth_path = "~/.codex/auth.json"

[antigravity]
# Shows "creds missing" until you log in with agy. Set false to hide it.
enabled = true
keyring_service = "gemini"

[logging]
level = "INFO"
`;

// Write a first-run config at `path` and return its text. The config dir is
// tightened to 0700 (it also holds the device registry, i.e. the per-device
// PSKs) and the file is 0600 — it holds a shared secret.
//
// Several tokenmonitor-mcp processes can start at once (leader election happens
// later, on the port), so the publish has to be atomic in BOTH directions: the
// loser of the race must adopt the winner's file rather than overwrite it with
// a second, wholly different passphrase, AND it must never observe a
// half-written one. An O_EXCL ("wx") create alone only makes the create atomic,
// not the create-then-write: the loser could open the winner's still-empty file
// and parse it as a config with no passphrase. So we write a private temp file
// first and link() it into place — under the final name the file either does
// not exist or is complete.
//
// The passphrase is 32 hex chars rather than something memorable because nobody
// is meant to type it: it is the broker's fallback key, and devices get their
// own PSK at pairing time.
export function bootstrap(path) {
  const dir = dirname(path);
  // Only the leaf is tightened: creating ~/.config itself 0700 would be a
  // surprising side effect on a home directory we are only a guest in.
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o700);
  const body = BOOTSTRAP_TOML.replace(
    BOOTSTRAP_PASSPHRASE_PLACEHOLDER,
    randomBytes(16).toString("hex"),
  );

  const [published, created] = publishAtomic(path, body);
  if (created) {
    // stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
    process.stderr.write(
      `tokenmonitor-mcp: no config found, wrote a default one at ${path} (psk_passphrase generated)\n`,
    );
  }
  return published;
}

// Write `body` to `path`; return [text now at path, did we create it].
//
// Several tokenmonitor-mcp processes can start at once (leader election happens
// later, on the port), so the publish has to be atomic in BOTH directions: the
// loser of the race must adopt the winner's file rather than overwrite it with
// different content, AND it must never observe a half-written one. An O_EXCL
// ("wx") create alone only makes the create atomic, not the create-then-write:
// the loser could open the winner's still-empty file and use it. So write a
// private temp file first and link() it into place — under the final name the
// file either does not exist or is complete.
//
// Mirrors publishAtomic() in go/internal/config/config.go and publish_atomic()
// in py/src/tmon_mcp/config.py.
export function publishAtomic(path, body) {
  const tmp = join(dirname(path), `.tmon-publish.${process.pid}.${randomBytes(6).toString("hex")}`);
  try {
    writeFileSync(tmp, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
    try {
      linkSync(tmp, path);
    } catch (e) {
      // Another process published first; its file is as good as ours.
      if (e && e.code === "EEXIST") return [readFileSync(path, "utf8"), false];
      throw e;
    }
  } finally {
    // Runs on every path: after a successful link the temp name is a stale
    // second link, and on failure it is a partial file nobody must inherit.
    try {
      unlinkSync(tmp);
    } catch {
      /* never created, or already gone */
    }
  }
  return [body, true];
}

// A config built purely from defaults, with an ephemeral random PSK, for the
// degraded start the MCP entrypoint performs when load() throws.
//
// It exists so a broken config can't take the MCP server down with it: exiting
// makes the client drop the server and the user sees nothing at all, whereas a
// live server can be asked what is wrong (tokenmonitor_health reports the load
// error). The caller MUST NOT serve the device broker with this — the PSK is
// invented and changes every start, so no device can authenticate against it.
// It is only here to keep the cfg-dependent tools from working on null.
export function unusableConfig() {
  const cfg = defaults();
  cfg.pskBytes = randomBytes(32);
  attachAccessors(cfg);
  return cfg;
}

// The sidecar holding the generated key used when the config carries no
// psk_passphrase / psk_hex. It lives next to the config as 64 lowercase hex
// chars.
//
// A sidecar rather than an edit to the TOML on purpose: patching a commented,
// user-owned config by hand means re-implementing a TOML-aware source scanner
// three times (quoted/dotted keys, inline tables, multi-line strings, a
// `psk_hex` under some other table, CRLF…), and any external editor open on the
// file would race the rewrite. A whole separate file has none of that, and the
// config always wins when it does carry a key.
export const FALLBACK_PSK_NAME = "psk";

// Return the generated fallback key from `dir`, creating it on first use.
// Publishing goes through publishAtomic, so concurrent starts converge on one
// key: whoever loses the race adopts the winner's file rather than continuing
// with a second key nobody else knows.
export function fallbackPSK(dir) {
  const path = join(dir, FALLBACK_PSK_NAME);
  if (existsSync(path)) return decodeFallbackPSK(readFileSync(path, "utf8"), path);

  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o700);
  const [published, created] = publishAtomic(path, `${randomBytes(32).toString("hex")}\n`);
  if (created) {
    // stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
    process.stderr.write(
      `tokenmonitor-mcp: config has no psk_passphrase/psk_hex, generated a fallback key at ${path}\n`,
    );
  }
  return decodeFallbackPSK(published, path);
}

// Parse the sidecar. A file that exists but does not hold a 32-byte key is an
// error, never something to overwrite: the user may have put a specific key
// there, and silently replacing it would desync every device that knows it.
function decodeFallbackPSK(raw, path) {
  const text = raw.trim();
  if (text.length !== 64) {
    throw new Error(`${path} must hold exactly 64 hex characters, has ${text.length}`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error(`${path} is not valid hex`);
  return Buffer.from(text, "hex");
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
      // Antigravity CLI conversation trajectory store. Note the "-cli":
      // ~/.gemini/antigravity also exists (the IDE's state dir) and holds no
      // conversations, so the shorter path silently yields zero spend. The
      // legacy gemini_tmp_path key is merged into this in load() for back-compat.
      antigravity_conversations_path: "~/.gemini/antigravity-cli/conversations",
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
    // - command_interval_s: optional pacing for those generators. Absent (or
    //   0) keeps the default contract — the command is a long-lived process
    //   the broker keeps alive. Set, it makes the command a periodic one-shot,
    //   re-run every N seconds. Bare number or per-device table, like `file`.
    panel: { file: "", dir: "", command: {}, command_interval_s: 0 },
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
    // Sections dropped to get a loadable config, plus the parse error that
    // caused it. Empty for a clean load. See salvageTOML.
    salvaged: [],
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

// Fields whose TOML type must be enforced by hand, because unlike Go's typed
// unmarshal mergeSection copies whatever the file said straight onto the
// config. Not the whole schema — these are the ones where a wrong type is not
// merely ignored but changes behaviour: the listener address and port, and the
// two replay-window bounds, where a non-number turns every comparison against
// it into `x > NaN` (false) rather than an error.
const TYPED_FIELDS = [
  ["auth", "psk_passphrase", "string", "a string"],
  ["auth", "psk_hex", "string", "a string"],
  ["server", "bind", "string", "a string"],
  ["server", "port", "number", "an integer"],
  ["security", "max_timestamp_skew_seconds", "number", "an integer"],
  ["security", "nonce_cache_ttl_seconds", "number", "an integer"],
];

// parseConfig turns TOML source into a validated config. It does everything
// load() does EXCEPT resolving the PSK, so it can be the predicate in
// salvageTOML without minting a sidecar key on every trial parse. Mirror of Go
// config.parseConfig.
function parseConfig(raw) {
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
  // Reject a [panel.command_interval_s] the user clearly did not mean. Go
  // refuses to start on these, so we do too — the three impls are supposed to
  // behave identically on the same toml, and a broker that silently ignores
  // the key leaves the user wondering why their pacing never took effect.
  // Whole seconds only: rounding 0.5 to 0 would quietly turn "twice a second"
  // into "long-lived process", the opposite contract.
  {
    const iv = cfg.panel.command_interval_s;
    const entries = (iv && typeof iv === "object") ? Object.entries(iv) : [["default", iv]];
    for (const [k, v] of entries) {
      if (typeof v !== "number" || !Number.isFinite(v)) {
        throw new Error(`panel.command_interval_s["${k}"]: expected integer, got ${typeof v}`);
      }
      if (v < 0) throw new Error(`panel.command_interval_s["${k}"]: must be >= 0, got ${v}`);
      if (!Number.isInteger(v)) {
        throw new Error(`panel.command_interval_s["${k}"]: whole seconds only, got ${v}`);
      }
    }
  }
  // mergeSection copies TOML values through without type enforcement, while
  // Go's typed unmarshal rejects a wrong type outright — so without this the
  // three runtimes disagree about which sections survive salvage, and worse,
  // about what a value means. `psk_hex = []` would read as "unset" here and as
  // an error in Go; `max_timestamp_skew_seconds = "off"` would make every
  // comparison against it false, silently disabling timestamp expiry.
  for (const [section, key, want, label] of TYPED_FIELDS) {
    const v = cfg[section][key];
    if (want === "number" ? !Number.isInteger(v) : typeof v !== want) {
      throw new Error(`${section}.${key} must be ${label}`);
    }
  }
  // Auth is format-checked here but not resolved: a section carrying a
  // malformed key has to fail so salvageTOML drops it, and the caller then
  // falls back to the sidecar.
  //
  // The checks follow the same precedence load() resolves by — passphrase
  // first, hex only when there is no passphrase. A stale malformed psk_hex
  // sitting under a perfectly good psk_passphrase is a value nobody reads;
  // failing on it would drop the whole [auth] section, switch the broker to the
  // sidecar key and desync every device that knows the real one.
  if (cfg.auth.psk_passphrase !== "") {
    // Bytes, not UTF-16 code units: Go measures the UTF-8 encoding and the PSK
    // is derived from those same bytes in all three runtimes.
    if (Buffer.byteLength(cfg.auth.psk_passphrase, "utf8") < 8) {
      throw new Error("auth.psk_passphrase must be at least 8 characters");
    }
  } else if (cfg.auth.psk_hex !== "") {
    if (cfg.auth.psk_hex.length !== 64) throw new Error("auth.psk_hex must be exactly 64 hex characters");
    if (!/^[0-9a-fA-F]{64}$/.test(cfg.auth.psk_hex)) throw new Error("auth.psk_hex is not valid hex");
  }
  return cfg;
}

// splitTOMLSections cuts src before every line whose first non-blank character
// is '[' (a table or array-of-tables header). The leading chunk holds any
// root-level keys written before the first header.
function splitTOMLSections(src) {
  const out = [];
  let cur = "";
  for (const line of src.split(/(?<=\n)/)) {
    if (/^[ \t]*\[/.test(line) && cur) {
      out.push(cur);
      cur = "";
    }
    cur += line;
  }
  if (cur) out.push(cur);
  return out;
}

// salvageTOML rebuilds the largest run of top-level sections that still loads,
// and returns both that source and the config it produced. Mirror of Go
// config.salvageTOML.
//
// The file is split at top-level table headers, so a section is the unit that
// survives or dies as a whole — never an individual line. Dropping a lone line
// would be worse than useless: lose a `[server]` header and every key under it
// silently joins the PREVIOUS table, which is a config that parses and means
// something the user never wrote.
//
// Sections are then re-accumulated in order, keeping each one only if the text
// so far still parses AND validates. That covers both a syntax error and a
// merely invalid value (a 4-character passphrase, a fractional
// command_interval_s) with the same mechanism, and the survivors are re-parsed
// as one document — so [[ota.keys]] arrays merge with normal TOML semantics
// instead of some hand-rolled deep merge.
//
// A chunk is only considered at all when everything BEFORE it parses as TOML.
// That test is what makes the split safe rather than merely plausible. A line
// starting with `[` inside a multi-line string is not a header, and splitting
// there would hand us a chunk like
//
//     [auth] # """
//     psk_passphrase = "…"
//
// — string content that reads as a perfectly good section the user never wrote,
// complete with a PSK. It cannot happen here: the text before such a boundary
// ends inside an unterminated string, so it never parses, so the boundary is
// never trusted. The cost is that a *syntax* error truncates the salvage at
// that point (past it we no longer know where sections begin), while a merely
// invalid value costs only its own section.
function salvageTOML(src) {
  let kept = "";
  let prefix = "";
  let cfg = defaults();
  for (const chunk of splitTOMLSections(src)) {
    // prefix is the raw text preceding this chunk — every earlier chunk, kept
    // or dropped. If it doesn't parse we are not at a known lexical state, so
    // this chunk's header is not known to be a header.
    let trusted = true;
    try {
      TOML.parse(prefix);
    } catch {
      trusted = false;
    }
    prefix += chunk;
    if (!trusted) continue;
    const candidate = kept + chunk;
    let got;
    try {
      got = parseConfig(candidate);
    } catch {
      continue;
    }
    kept = candidate;
    cfg = got;
  }
  return [kept, cfg];
}

// sectionLabel is a chunk's header line, or "<root>" for the leading keys.
function sectionLabel(chunk) {
  const line = chunk.split("\n", 1)[0].trim();
  return line.startsWith("[") ? line : "<root>";
}

// describeSalvage names what was lost, for the log line and the health report.
//
// Labels are counted, not set-tested: a header can legitimately repeat
// ([[ota.keys]] is one entry per signing key), and matching by presence would
// let a dropped second entry hide behind the first one that survived — the one
// case where the salvage really would lose data silently.
function describeSalvage(src, kept, cause) {
  const keptCount = new Map();
  for (const label of splitTOMLSections(kept).map(sectionLabel)) {
    keptCount.set(label, (keptCount.get(label) || 0) + 1);
  }
  const dropped = [];
  for (const label of splitTOMLSections(src).map(sectionLabel)) {
    const n = keptCount.get(label) || 0;
    if (n > 0) {
      keptCount.set(label, n - 1);
      continue;
    }
    dropped.push(label);
  }
  if (dropped.length === 0) {
    // The whole file failed as a unit (e.g. an unterminated string that
    // swallows every later header).
    dropped.push("<whole file>");
  }
  return [...dropped, `cause: ${cause && cause.message ? cause.message : cause}`];
}

// Matches a line that assigns the bind key. Deliberately textual: this runs
// over source the TOML parser has already rejected, where there is nothing to
// query. It is only ever used to decline to widen the bind, so a false positive
// costs reachability (recoverable, and reported) while a false negative would
// cost network exposure.
const BIND_ASSIGNMENT = /^[ \t]*bind[ \t]*=/m;

// mentionsBind reports whether the part of src the salvage could NOT keep
// assigns a bind.
function mentionsBind(src, kept) {
  const keptCount = new Map();
  for (const label of splitTOMLSections(kept).map(sectionLabel)) {
    keptCount.set(label, (keptCount.get(label) || 0) + 1);
  }
  for (const chunk of splitTOMLSections(src)) {
    const label = sectionLabel(chunk);
    const n = keptCount.get(label) || 0;
    if (n > 0) {
      keptCount.set(label, n - 1);
      continue;
    }
    if (BIND_ASSIGNMENT.test(chunk)) return true;
  }
  return false;
}

// definesKey reports whether src actually sets the given key path, as opposed
// to the value coming from defaults().
function definesKey(src, ...path) {
  let node;
  try {
    node = TOML.parse(src);
  } catch {
    return false;
  }
  for (const part of path) {
    if (!node || typeof node !== "object" || !(part in node)) return false;
    node = node[part];
  }
  return true;
}

export function load(path) {
  const explicit = !!path;
  let resolved = expandUser(path || DEFAULT_PATH);
  let raw = null;
  if (!existsSync(resolved) && !explicit) {
    const legacy = expandUser(LEGACY_PATH);
    if (existsSync(legacy)) {
      resolved = legacy;
    } else {
      // First run on this machine: neither the canonical file nor the legacy
      // one exists. Write a working default instead of throwing — an MCP client
      // that never sees the server reach "ready" simply drops the server from
      // the session, which reads as "the plugin is broken" rather than "you
      // have not configured it yet".
      raw = bootstrap(resolved);
    }
  }
  if (raw === null) {
    if (!existsSync(resolved)) throw new Error(`read ${resolved}: file not found`);
    raw = readFileSync(resolved, "utf8");
  }

  let cfg;
  try {
    cfg = parseConfig(raw);
  } catch (parseErr) {
    // An explicit --config is the operator's file: report the error and let
    // them fix it rather than second-guessing what they meant.
    if (explicit) throw new Error(`parse ${resolved}: ${parseErr.message}`);
    // Otherwise come up on whatever the file got right. Refusing to start helps
    // nobody: the broker is how the device gets configured in the first place,
    // so a typo in [panel] must not cost you the ability to set up a device.
    // See salvageTOML for what "got right" means.
    let kept;
    [kept, cfg] = salvageTOML(raw);
    cfg.salvaged = describeSalvage(raw, kept, parseErr);
    // A rescued file may have lost [server] with the rest of a bad section. The
    // code default binds loopback, which the device cannot reach — use the same
    // bind a fresh bootstrap would have written, so "it came up" also means
    // "you can provision against it".
    //
    // Unless the part we could not read was itself talking about bind. A user
    // who wrote a bind we failed to parse has said something about their
    // network boundary, and widening it to every interface on their behalf is
    // not a rescue. Fail closed and let the health report tell them which
    // section to fix.
    if (!definesKey(kept, "server", "bind") && !mentionsBind(raw, kept)) {
      cfg.server.bind = "0.0.0.0";
    }
  }

  // Absent or exactly empty means "unset". A malformed value never reaches
  // here: parseConfig rejects it, and for the default config path the section
  // carrying it has already been dropped by the salvage above.
  if (cfg.auth.psk_passphrase !== "") {
    if (cfg.auth.psk_passphrase.length < 8) throw new Error("auth.psk_passphrase must be at least 8 characters");
    cfg.pskBytes = createHash("sha256").update(cfg.auth.psk_passphrase, "utf8").digest();
  } else if (cfg.auth.psk_hex !== "") {
    if (cfg.auth.psk_hex.length !== 64) throw new Error("auth.psk_hex must be exactly 64 hex characters");
    if (!/^[0-9a-fA-F]{64}$/.test(cfg.auth.psk_hex)) throw new Error("auth.psk_hex is not valid hex");
    cfg.pskBytes = Buffer.from(cfg.auth.psk_hex, "hex");
    cfg.auth.psk_hex = cfg.auth.psk_hex.toLowerCase();
  } else if (explicit) {
    // The operator wrote that file and may be managing it from somewhere else,
    // so we do not add secrets to it behind their back.
    throw new Error("auth: either psk_passphrase or psk_hex is required");
  } else {
    // Throwing here would reproduce exactly the failure bootstrap exists to
    // prevent: the process dies before answering `initialize` and the MCP
    // client silently drops the server. Fall back to a generated key kept in a
    // sidecar file instead.
    cfg.pskBytes = fallbackPSK(dirname(resolved));
  }
  cfg.logging.level = (cfg.logging.level || "INFO").toUpperCase();

  return attachAccessors(cfg);
}

// Attach the derived accessors every caller expects on a config object
// (path expansion, panel lookups, OTA keyring). Extracted from load() so
// unusableConfig() hands back an object with the identical API — a degraded
// start must not fail with "cfg.oauthPathAbs is not a function".
function attachAccessors(cfg) {
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
// How often (seconds) to re-run a device's generator: its own
// [panel.command_interval_s] entry, else "default", else 0. Accepts the same
// two spellings as `file` — a bare number is the "default" entry.
//
// 0 means unset: panelGenerator keeps that generator as a long-lived process,
// which is what every config did before this key existed.
//
// load() already rejects a negative, fractional or non-numeric entry (as Go
// does at TOML parse time), so those never reach here from a real config
// file; the coercion below only guards a cfg built by hand in a test.
cfg.panelCommandIntervalFor = (deviceID) => {
  const iv = cfg.panel.command_interval_s;
  let raw = iv;
  if (iv && typeof iv === "object") {
    raw = deviceID in iv ? iv[deviceID] : iv.default;
  }
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) return 0;
  return raw;
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

