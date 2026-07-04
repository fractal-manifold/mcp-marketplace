// Package config loads tokenmonitor-mcp's TOML configuration, derives the PSK from
// either a passphrase (preferred) or a raw 64-hex key, and exposes the
// resulting bytes to the rest of the binary.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultPath is the canonical location of the config file. If it does not
// exist, Load() falls back to LegacyPath for users still on the older
// service-go installation.
const (
	DefaultPath = "~/.config/tokenmonitor/tokenmonitor.toml"
	LegacyPath  = "~/.config/tokenmonitor/service.toml"
	DevicesDir  = "~/.config/tokenmonitor/devices"
	// FirmwareDir holds binaries served by GET /firmware/<name>. The
	// publish_firmware MCP tool copies the .bin here and the device
	// downloads from there after a pending OTA promotion.
	FirmwareDir = "~/.config/tokenmonitor/firmware"
)

// DevicesPath returns the absolute path to the per-device registry
// directory. Exposed so main() can hand it to registry.New.
func DevicesPath() string { return expandUser(DevicesDir) }

// FirmwarePath returns the absolute path to the firmware artifact
// directory. Exposed so main() can hand it to broker.NewMux.
func FirmwarePath() string { return expandUser(FirmwareDir) }

type Config struct {
	Server      Server      `toml:"server"`
	Auth        Auth        `toml:"auth"`
	Credentials Credentials `toml:"credentials"`
	Codex       Codex       `toml:"codex"`
	Antigravity Antigravity `toml:"antigravity"`
	// Gemini is the DEPRECATED pre-rename alias for [antigravity]. Google
	// retired the Gemini CLI (2026-06-18) in favour of the Antigravity CLI
	// (`agy`); the provider was renamed accordingly. A legacy tokenmonitor.toml
	// with a [gemini] section is still honoured — Load() merges it into
	// Antigravity when the new section is absent.
	Gemini Gemini `toml:"gemini"`
	Usage  Usage  `toml:"usage"`
	Spend       Spend       `toml:"spend"`
	Pricing     Pricing     `toml:"pricing"`
	Panel       Panel       `toml:"panel"`
	Security    Security    `toml:"security"`
	Logging     Logging     `toml:"logging"`
	Serial      Serial      `toml:"serial"`
	OTA         OTAConfig   `toml:"ota"`
	pskBytes    []byte
}

type Server struct {
	Bind string `toml:"bind"`
	Port int    `toml:"port"`
}

type Auth struct {
	Passphrase string `toml:"psk_passphrase"`
	PSKHex     string `toml:"psk_hex"`
}

type Credentials struct {
	OAuthPath string `toml:"oauth_path"`
}

type Codex struct {
	Enabled  bool   `toml:"enabled"`
	AuthPath string `toml:"auth_path"`
}

// Antigravity configures the grouped weekly-quota probe for the Antigravity
// CLI (`agy`, the successor to the retired Gemini CLI). The broker reads agy's
// consumer OAuth token from the OS keyring (READ-ONLY — agy keeps it fresh)
// and POSTs to the canary cloudcode-pa host; the quota RPC requires that
// keyring token (the old oauth_creds.json token is rejected there). Verified
// end-to-end via a live capture of agy 1.0.13 (2026-06-30).
//
// KeyringService is the libsecret service name agy stores its token under
// (`secret-tool lookup service <name>`); default "gemini".
//
// CredsPath / ProjectsPath are DEPRECATED leftovers from the old
// loadCodeAssist-only probe (oauth_creds.json + projects.json). They are no
// longer read — the keyring token is the only source — but kept in the struct
// so a legacy tokenmonitor.toml parses without error.
//
// Models is the (now ignored) per-model list. The quota is grouped (Gemini
// Models / Claude+GPT), not per-model, so it no longer affects the result; the
// field is retained for config back-compat and the per-device override path.
type Antigravity struct {
	Enabled        bool     `toml:"enabled"`
	KeyringService string   `toml:"keyring_service"`
	CredsPath      string   `toml:"creds_path"`
	ProjectsPath   string   `toml:"projects_path"`
	Models         []string `toml:"models"`
}

// Gemini is the DEPRECATED pre-rename config shape, kept structurally
// identical so a legacy [gemini] section unmarshals and can be merged into
// Antigravity in Load().
type Gemini = Antigravity

// DefaultAntigravityModels is what the broker exposes when
// [antigravity].models is empty. The Antigravity CLI's quota buckets are
// keyed by model ID (e.g. gemini-3.5-flash-low); we surface the Flash and
// Pro families — prefix matching tolerates the effort suffix (-low/-medium/
// -high) Google appends. Verified model IDs: gemini-3.5-flash-{low,medium,
// high}, gemini-3.1-pro-{low,high} (agy 1.0.13, 2026-06-30).
var DefaultAntigravityModels = []string{"gemini-3.5-flash", "gemini-3.1-pro"}

// MaxAntigravityModels caps the number of model slots the broker emits — the
// firmware dashboard has 3 fixed card slots (large/large/small) and
// ignores anything past index 2.
const MaxAntigravityModels = 3

// AntigravityModels returns the configured list, clamped to
// MaxAntigravityModels. An empty config returns DefaultAntigravityModels.
func (c *Config) AntigravityModels() []string {
	src := c.Antigravity.Models
	if len(src) == 0 {
		src = DefaultAntigravityModels
	}
	if len(src) > MaxAntigravityModels {
		src = src[:MaxAntigravityModels]
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// Usage controls the cache TTL for /usage/{provider}. A device polling
// every 60 s with default TTL hits each upstream at most once per minute.
type Usage struct {
	CacheTTLSeconds int `toml:"cache_ttl_seconds"`
}

// Spend controls /spend/{provider}: locally-computed token cost from the
// CLI logs on this host (see compat/SPEND_WIRE.md). No admin key. TTL is
// longer than Usage because spend changes slowly and parsing is heavier.
type Spend struct {
	Enabled              bool   `toml:"enabled"`
	CacheTTLSeconds      int    `toml:"cache_ttl_seconds"`
	ClaudeProjectsPath   string `toml:"claude_projects_path"`
	ClaudeStatsCachePath string `toml:"claude_stats_cache_path"`
	CodexSessionsPath    string `toml:"codex_sessions_path"`
	// AntigravityConvPath is the Antigravity CLI's conversation trajectory
	// store. GeminiTmpPath is the DEPRECATED pre-rename key, merged into it
	// in Load() so a legacy tokenmonitor.toml keeps working.
	AntigravityConvPath string `toml:"antigravity_conversations_path"`
	GeminiTmpPath       string `toml:"gemini_tmp_path"`
}

// Pricing is the model price table used to turn tokens into USD. Source of
// truth is LiteLLM's machine-readable table; cached on disk with an
// embedded fallback so $ works offline.
type Pricing struct {
	URL       string `toml:"url"`
	CachePath string `toml:"cache_path"`
	TTLHours  int    `toml:"ttl_hours"`
}

// Panel feeds the device's optional custom-panel screen. The user's own
// program writes a self-describing JSON document (charts / tables) that the
// broker serves verbatim from GET /device/<id>/panel. Everything empty =
// feature off (endpoint answers 404).
//
//   - File: which document to serve, per device. Accepts either a bare
//     string (shorthand for the "default" entry, i.e. one global document)
//     or a [panel.file] sub-table keyed by device id with a "default"
//     fallback. See PanelPaths.
//   - Dir:  a directory of per-device documents; <dir>/<id>.json wins, then
//     <dir>/default.json. Slots between the explicit per-device File entry
//     and the File "default" — see broker.resolvePanelPath.
//   - Command: optional per-device generator the broker itself launches
//     (leader-scoped — see internal/panelgen). Keyed by device id with a
//     "default" fallback; each value is an argv array run without a shell.
type Panel struct {
	File    PanelPaths    `toml:"file"`
	Dir     string        `toml:"dir"`
	Command PanelCommands `toml:"command"`
}

// PanelPaths maps a device id to the panel document path to serve it, with a
// "default" key as the fallback for any device without its own entry. It
// implements toml.Unmarshaler so `file` accepts either form:
//
//	file = "~/panel.json"                 # => {"default": "~/panel.json"}
//	[panel.file]                          # per-device table
//	default     = "~/panels/default.json"
//	"tmon-ab12" = "~/panels/ab12.json"
type PanelPaths map[string]string

// UnmarshalTOML accepts a bare string (stored under "default") or a table of
// id -> path. Any other shape is a config error.
func (p *PanelPaths) UnmarshalTOML(v interface{}) error {
	out := PanelPaths{}
	switch t := v.(type) {
	case string:
		if t != "" {
			out["default"] = t
		}
	case map[string]interface{}:
		for k, raw := range t {
			s, ok := raw.(string)
			if !ok {
				return fmt.Errorf("panel.file[%q]: expected string, got %T", k, raw)
			}
			out[k] = s
		}
	default:
		return fmt.Errorf("panel.file: expected string or table, got %T", v)
	}
	*p = out
	return nil
}

// PanelCommands maps a device id to the argv of a generator process, with a
// "default" fallback. Always a [panel.command] sub-table of arrays; the argv
// is executed directly (no shell), so argv[0] is the program and the rest are
// its arguments.
type PanelCommands map[string][]string

type Security struct {
	MaxTimestampSkewSeconds int `toml:"max_timestamp_skew_seconds"`
	NonceCacheTTLSeconds    int `toml:"nonce_cache_ttl_seconds"`
}

type Logging struct {
	Level string `toml:"level"`
}

// Serial is the USB-CDC tail for the device's ESP-IDF logs. When Device is
// empty the tailer is disabled — leaving idf.py monitor free to own the
// port. When set, only the leader process opens it; followers read via
// the broker's HTTP /firmware-logs endpoint.
type Serial struct {
	Device string `toml:"device"`
	Baud   int    `toml:"baud"`
	Lines  int    `toml:"lines"`
}

// OTAConfig drives the broker's pull-based OTA: a periodic check of a
// public GitHub releases repo that auto-stages a pending firmware update
// for matching registered devices. The trust anchor is the Ed25519
// signature on the manifest — verified here AND on-device — so the .bin
// can be served from a public, unauthenticated host. The broker never
// holds a signing key; only the public verification keys below.
//
// Behaviour: the loop runs only on the leader process. It is inert
// (logs once, does nothing) unless Enabled && ReleasesRepo != "" &&
// len(Keys) > 0, because without a pubkey the broker cannot verify a
// manifest and refuses to stage one it can't authenticate.
type OTAConfig struct {
	Enabled             bool     `toml:"enabled"`
	ReleasesRepo        string   `toml:"releases_repo"`
	PollIntervalMinutes int      `toml:"poll_interval_minutes"`
	// DevTag is DEPRECATED and ignored. Dev builds now publish immutable
	// per-version prerelease tags (vX.Y.Z-dev.<ts>); the broker resolves the
	// newest one via the GitHub Releases API rather than a single rolling
	// tag. The field is still parsed so an old tokenmonitor.toml doesn't error.
	DevTag string   `toml:"dev_tag"`
	Keys   []OTAKey `toml:"keys"`
}

// OTAKey is one entry in the verification keyring: a key_id (matching the
// manifest's key_id field) and the 32-byte raw Ed25519 public key,
// base64-std encoded. Derive both with
// `python -m tmtools.lib.manifest pubkey --key <ota_signing_key.pem>`.
type OTAKey struct {
	KeyID     string `toml:"key_id"`
	PubkeyB64 string `toml:"pubkey_b64"`
}

// Configured reports whether the OTA poller has everything it needs to
// run: enabled, a repo to poll, and at least one verification key.
func (o OTAConfig) Configured() bool {
	return o.Enabled && o.ReleasesRepo != "" && len(o.Keys) > 0
}

// Pubkey returns the 32-byte raw Ed25519 public key for keyID, or
// (nil, false) when the keyring has no matching, well-formed entry.
func (o OTAConfig) Pubkey(keyID string) ([]byte, bool) {
	for _, k := range o.Keys {
		if k.KeyID != keyID {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.PubkeyB64))
		if err != nil || len(b) != 32 {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

func (c *Config) PSK() []byte { return c.pskBytes }

func (c *Config) OAuthPath() string {
	return expandUser(c.Credentials.OAuthPath)
}

func (c *Config) CodexAuthPath() string {
	return expandUser(c.Codex.AuthPath)
}

func (c *Config) AntigravityCredsPath() string {
	return expandUser(c.Antigravity.CredsPath)
}

func (c *Config) AntigravityProjectsPath() string {
	return expandUser(c.Antigravity.ProjectsPath)
}

func (c *Config) ClaudeProjectsPath() string   { return expandUser(c.Spend.ClaudeProjectsPath) }
func (c *Config) ClaudeStatsCachePath() string { return expandUser(c.Spend.ClaudeStatsCachePath) }
func (c *Config) CodexSessionsPath() string    { return expandUser(c.Spend.CodexSessionsPath) }

// AntigravityConvPath is the per-conversation SQLite trajectory store the
// Antigravity CLI writes (~/.gemini/antigravity-cli/conversations). It
// replaces the dead Gemini-CLI chat-log path; the legacy gemini_tmp_path is
// merged into it in Load() for back-compat.
func (c *Config) AntigravityConvPath() string { return expandUser(c.Spend.AntigravityConvPath) }
func (c *Config) PricingCachePath() string    { return expandUser(c.Pricing.CachePath) }

// PanelFileExplicit returns the document path configured specifically for
// deviceID under [panel.file] (no "default" fallback), expanded. Empty when
// the device has no explicit entry.
func (c *Config) PanelFileExplicit(deviceID string) string {
	if deviceID == "" {
		return ""
	}
	if p, ok := c.Panel.File[deviceID]; ok {
		return expandUser(p)
	}
	return ""
}

// PanelFileDefault returns the [panel.file] "default" entry (or the legacy
// bare `file = "..."`, which decodes to the same key), expanded.
func (c *Config) PanelFileDefault() string { return expandUser(c.Panel.File["default"]) }

// PanelDir expands the [panel] dir. The broker resolves the effective
// per-device file from these (see broker.resolvePanelPath).
func (c *Config) PanelDir() string { return expandUser(c.Panel.Dir) }

// PanelCommandMap returns the configured generator commands keyed by device
// id (plus the possible "default" key). Every argv element is tilde-expanded
// (there is no shell to do it), so `~/bin/gen.py` resolves whether it is the
// program or a script argument. Empty when no [panel.command] is configured —
// the panelgen manager treats that as "feature off" and launches nothing.
func (c *Config) PanelCommandMap() map[string][]string {
	if len(c.Panel.Command) == 0 {
		return nil
	}
	out := make(map[string][]string, len(c.Panel.Command))
	for k, argv := range c.Panel.Command {
		if len(argv) == 0 {
			continue
		}
		cp := make([]string, len(argv))
		for i, a := range argv {
			cp[i] = expandUser(a)
		}
		out[k] = cp
	}
	return out
}

func expandUser(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// Load reads the config from `path` (or the default location if empty). If
// `path` is the default and missing, it transparently tries the legacy
// service.toml so existing service-go users don't have to migrate.
func Load(path string) (*Config, error) {
	explicit := path != ""
	if path == "" {
		path = DefaultPath
	}
	resolved := expandUser(path)

	raw, err := os.ReadFile(resolved)
	if err != nil && !explicit && errors.Is(err, os.ErrNotExist) {
		legacy := expandUser(LegacyPath)
		legacyRaw, legacyErr := os.ReadFile(legacy)
		if legacyErr == nil {
			raw = legacyRaw
			resolved = legacy
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", resolved, err)
	}

	cfg := defaults()
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", resolved, err)
	}

	// Back-compat: a legacy tokenmonitor.toml uses [gemini] / gemini_tmp_path
	// (pre-rename, before the Gemini CLI → Antigravity CLI migration). If the
	// new [antigravity] section was not provided, fold the deprecated values
	// forward so existing installs keep working. We detect "provided" by a
	// non-zero deprecated section against the still-default new one.
	mergeLegacyGemini(cfg, raw)

	switch {
	case cfg.Auth.Passphrase != "":
		if len(cfg.Auth.Passphrase) < 8 {
			return nil, errors.New("auth.psk_passphrase must be at least 8 characters")
		}
		sum := sha256.Sum256([]byte(cfg.Auth.Passphrase))
		cfg.pskBytes = sum[:]
	case cfg.Auth.PSKHex != "":
		if len(cfg.Auth.PSKHex) != 64 {
			return nil, errors.New("auth.psk_hex must be exactly 64 hex characters")
		}
		psk, err := hex.DecodeString(cfg.Auth.PSKHex)
		if err != nil {
			return nil, fmt.Errorf("auth.psk_hex is not valid hex: %w", err)
		}
		cfg.pskBytes = psk
		cfg.Auth.PSKHex = strings.ToLower(cfg.Auth.PSKHex)
	default:
		return nil, errors.New("auth: either psk_passphrase or psk_hex is required")
	}
	cfg.Logging.Level = strings.ToUpper(cfg.Logging.Level)
	return cfg, nil
}

// mergeLegacyGemini folds a deprecated pre-rename [gemini] section /
// gemini_tmp_path forward into the canonical Antigravity fields when the new
// keys are absent. Detection uses TOML metadata (key presence) so we don't
// confuse "not provided" with "set to a zero value".
func mergeLegacyGemini(cfg *Config, raw []byte) {
	var probe Config
	md, err := toml.Decode(string(raw), &probe)
	if err != nil {
		return // a parse error is reported by the caller's Unmarshal
	}
	if !md.IsDefined("antigravity") && md.IsDefined("gemini") {
		// Adopt the legacy section, but keep default paths when the legacy
		// entry left them empty.
		cfg.Antigravity.Enabled = cfg.Gemini.Enabled
		if cfg.Gemini.CredsPath != "" {
			cfg.Antigravity.CredsPath = cfg.Gemini.CredsPath
		}
		if cfg.Gemini.ProjectsPath != "" {
			cfg.Antigravity.ProjectsPath = cfg.Gemini.ProjectsPath
		}
		if len(cfg.Gemini.Models) > 0 {
			cfg.Antigravity.Models = cfg.Gemini.Models
		}
	}
	if !md.IsDefined("spend", "antigravity_conversations_path") &&
		md.IsDefined("spend", "gemini_tmp_path") && cfg.Spend.GeminiTmpPath != "" {
		cfg.Spend.AntigravityConvPath = cfg.Spend.GeminiTmpPath
	}
}

func defaults() *Config {
	return &Config{
		Server: Server{Bind: "127.0.0.1", Port: 8765},
		Credentials: Credentials{
			OAuthPath: "~/.claude/.credentials.json",
		},
		Codex: Codex{
			Enabled:  false,
			AuthPath: "~/.codex/auth.json",
		},
		Antigravity: Antigravity{
			Enabled: false,
			// OS keyring service holding agy's consumer OAuth token (the quota
			// RPC requires it; the oauth_creds.json token is rejected there).
			// Read via `secret-tool lookup service <name>`.
			KeyringService: "gemini",
			// CredsPath/ProjectsPath are deprecated and no longer read; kept
			// only so a legacy tokenmonitor.toml still parses.
			CredsPath:    "~/.gemini/oauth_creds.json",
			ProjectsPath: "~/.gemini/projects.json",
			// Models left nil so AntigravityModels() returns the default —
			// keeps the zero value useful for tests that don't load TOML.
		},
		Usage: Usage{
			CacheTTLSeconds: 30,
		},
		Spend: Spend{
			Enabled:              true,
			CacheTTLSeconds:      300,
			ClaudeProjectsPath:   "~/.claude/projects",
			ClaudeStatsCachePath: "~/.claude/stats-cache.json",
			CodexSessionsPath:    "~/.codex/sessions",
			AntigravityConvPath:  "~/.gemini/antigravity-cli/conversations",
		},
		Pricing: Pricing{
			URL:       "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json",
			CachePath: "~/.config/tokenmonitor/pricing-cache.json",
			TTLHours:  24,
		},
		Security: Security{
			MaxTimestampSkewSeconds: 60,
			NonceCacheTTLSeconds:    300,
		},
		Logging: Logging{Level: "INFO"},
		Serial:  Serial{Device: "", Baud: 115200, Lines: 2000},
		OTA: OTAConfig{
			// Enabled by default, but inert until a [[ota.keys]] entry is
			// added (Configured() is false without a verification key).
			Enabled:             true,
			ReleasesRepo:        "https://github.com/fractal-manifold/tokenmonitor-ota-releases",
			PollIntervalMinutes: 60,
			DevTag:              "dev",
		},
	}
}

// SampleTOML is a self-documenting template suitable for `tokenmonitor-mcp --print-config`.
const SampleTOML = `[server]
# 0.0.0.0 to accept connections from the ESP32 over the LAN.
bind = "0.0.0.0"
port = 8765

[auth]
# A passphrase (8+ chars) shared with the device. Both sides SHA-256 it to
# derive the HMAC key, so you only need to type something memorable.
psk_passphrase = "change-me-please"
# Alternative: set psk_hex (64 hex chars from 'openssl rand -hex 32').
# psk_hex = ""

[credentials]
oauth_path = "~/.claude/.credentials.json"

[codex]
# Enable if you also use the Codex CLI. auth.json contains the ChatGPT
# bearer token plus account_id required by /backend-api/wham/usage.
enabled = false
auth_path = "~/.codex/auth.json"

[antigravity]
# Enable if you also use the Antigravity CLI (agy, the successor to the
# retired Gemini CLI). The broker reads agy's consumer OAuth token from the
# OS keyring (READ-ONLY — agy keeps it fresh while it runs) and asks the
# canary cloudcode-pa host for the grouped weekly quota (Gemini Models /
# Claude+GPT). (A legacy [gemini] section is still accepted and merged here.)
enabled = false
# libsecret service name agy stores its token under
# (secret-tool lookup service <name>). Default "gemini".
keyring_service = "gemini"
# creds_path / projects_path are DEPRECATED and no longer read (the keyring
# token is the only source); kept so a legacy config still parses.
# creds_path = "~/.gemini/oauth_creds.json"
# projects_path = "~/.gemini/projects.json"
# models is DEPRECATED — the quota is grouped (Gemini Models / Claude+GPT),
# not per-model, so this no longer affects the output. Retained for back-compat.
# models = ["gemini-3.5-flash", "gemini-3.1-pro"]

[usage]
# How long the broker caches each provider's /usage payload before
# re-fetching upstream. A device polling every 60 s with TTL 30 s hits
# each upstream once per minute at most.
cache_ttl_seconds = 30

[panel]
# Optional custom-panel screen. Your OWN program writes a self-describing
# JSON document (charts / tables) and the broker serves it verbatim from
# GET /device/<id>/panel; the device draws it on an extra screen reached by
# swiping up. Leave it empty (default) to keep the feature off — the
# endpoint then answers 404, exactly like an older broker.
#
# Single global document served to every device:
# file = "~/.config/tokenmonitor/panel.json"
#
# Or a directory of per-device documents (<dir>/<id>.json wins, then
# <dir>/default.json, then the global file):
# dir = "~/.config/tokenmonitor/panels"
#
# Or spell out the document per device explicitly (falls back to "default"):
# [panel.file]
# default     = "~/.config/tokenmonitor/panels/default.json"
# "tmon-ab12" = "~/.config/tokenmonitor/panels/ab12.json"
#
# OPTIONAL: let the broker run your generator instead of running it yourself.
# Each command is an argv array (no shell) launched ONLY by the leader broker
# and torn down when it loses the port, so exactly one copy runs. The child
# gets TMON_DEVICE_ID and TMON_PANEL_PATH in its environment. Keyed by device
# id with a "default" fallback; omit entirely to keep running it yourself.
# [panel.command]
# default     = ["python3", "~/bin/gen_panel.py"]
# "tmon-ab12" = ["python3", "~/bin/gen_special.py"]
#
# Document format + limits (tiles<=4, points<=64, body<=8KB) live in
# docs/custom-panel.md and compat/PANEL_WIRE.md.

[security]
max_timestamp_skew_seconds = 60
nonce_cache_ttl_seconds = 300

[logging]
level = "INFO"

[serial]
# USB-CDC device that streams ESP-IDF logs. Leave empty (default) to keep
# idf.py monitor as the sole owner of the port. When set, the leader
# tokenmonitor-mcp process opens it and exposes the tail via:
#   - MCP tool tokenmonitor_firmware_logs
#   - HTTP GET /firmware-logs (HMAC-signed)
# device = "/dev/esp32s3"
# baud is meaningless for true USB-CDC; the kernel ignores it. Set to
# whatever you'd pass idf.py — it's just for documentation.
baud = 115200
# Ring buffer size in lines.
lines = 2000

[ota]
# Pull-based OTA: the leader process polls a PUBLIC GitHub releases repo
# for the latest signed firmware per SKU and auto-stages a pending update
# for every registered device whose SKU matches and whose installed
# version is older. The device picks it up on its next /device/<id>/sync
# — same path as a manual tokenmonitor_publish_firmware.
#
# Trust anchor is the Ed25519 signature on the manifest, NOT the
# transport, so the .bin is served from a public, unauthenticated host.
# The broker verifies the signature against the keyring below BEFORE
# staging; the device verifies it again on-device. Enabled by default but
# INERT until at least one [[ota.keys]] entry is present.
enabled = true
releases_repo = "https://github.com/fractal-manifold/tokenmonitor-ota-releases"
poll_interval_minutes = 60
# Verification keyring. Add one entry per OTA signing key. Get the values
# with: python -m tmtools.lib.manifest pubkey --key firmware/secrets/ota_signing_key.pem
# [[ota.keys]]
# key_id = "ed25519-xxxxxxxx"
# pubkey_b64 = "<32-byte raw Ed25519 public key, base64-std>"
`
