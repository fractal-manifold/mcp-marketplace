// Package config loads tokenmonitor-mcp's TOML configuration, derives the PSK from
// either a passphrase (preferred) or a raw 64-hex key, and exposes the
// resulting bytes to the rest of the binary.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
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
	Gemini   Gemini    `toml:"gemini"`
	Usage    Usage     `toml:"usage"`
	Spend    Spend     `toml:"spend"`
	Pricing  Pricing   `toml:"pricing"`
	Panel    Panel     `toml:"panel"`
	Security Security  `toml:"security"`
	Logging  Logging   `toml:"logging"`
	Serial   Serial    `toml:"serial"`
	OTA      OTAConfig `toml:"ota"`
	pskBytes []byte
	// salvaged names the sections dropped to make a broken file loadable.
	salvaged []string
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
//   - CommandIntervalS: optional pacing for those generators. Absent (or 0)
//     keeps the default contract — the command is a long-lived process the
//     broker keeps alive. Set, it makes the command a periodic one-shot run
//     every N seconds instead. See PanelCommandIntervals.
type Panel struct {
	File             PanelPaths            `toml:"file"`
	Dir              string                `toml:"dir"`
	Command          PanelCommands         `toml:"command"`
	CommandIntervalS PanelCommandIntervals `toml:"command_interval_s"`
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

// PanelCommandIntervals maps a device id to how often (seconds) to re-run its
// generator, with a "default" fallback. It implements toml.Unmarshaler so
// `command_interval_s` accepts either form, exactly like `file`:
//
//	command_interval_s = 900              # => {"default": 900}
//	[panel.command_interval_s]            # per-device table
//	default    = 900
//	"tmon-ab12" = 60
//
// An entry of 0 means "unset" — that device's generator stays a long-lived
// supervised process. A negative value is a config error rather than a silent
// fallback: it can only be a typo, and swallowing it would leave the user
// wondering why their pacing never took effect. So is a fractional one: the
// unit is whole seconds, and rounding 0.5 to 0 would silently turn "twice a
// second" into "long-lived process" — the opposite contract. The py and js
// brokers reject both the same way, so one toml behaves identically on all
// three.
type PanelCommandIntervals map[string]int

func (p *PanelCommandIntervals) UnmarshalTOML(v interface{}) error {
	out := PanelCommandIntervals{}
	set := func(k string, raw interface{}) error {
		var n int
		switch t := raw.(type) {
		case int64:
			n = int(t)
		case float64: // `command_interval_s = 900.0` is fine; 900.7 is not
			if t != math.Trunc(t) {
				return fmt.Errorf("panel.command_interval_s[%q]: whole seconds only, got %v", k, t)
			}
			n = int(t)
		default:
			return fmt.Errorf("panel.command_interval_s[%q]: expected integer, got %T", k, raw)
		}
		if n < 0 {
			return fmt.Errorf("panel.command_interval_s[%q]: must be >= 0, got %d", k, n)
		}
		out[k] = n
		return nil
	}
	switch t := v.(type) {
	case int64, float64:
		if err := set("default", t); err != nil {
			return err
		}
	case map[string]interface{}:
		for k, raw := range t {
			if err := set(k, raw); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("panel.command_interval_s: expected integer or table, got %T", v)
	}
	*p = out
	return nil
}

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
	Enabled             bool   `toml:"enabled"`
	ReleasesRepo        string `toml:"releases_repo"`
	PollIntervalMinutes int    `toml:"poll_interval_minutes"`
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
// Antigravity CLI writes: ~/.gemini/antigravity-cli/conversations. Note the
// "-cli" — ~/.gemini/antigravity also exists (it is the IDE's state dir) and
// holds no conversations, so the shorter path silently yields zero spend. It
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

// PanelCommandIntervalFor returns how often (seconds) to re-run device id's
// generator: its own [panel.command_interval_s] entry, else "default", else 0.
// Zero means unset — panelgen keeps that generator as a long-lived process,
// which is the behaviour every config had before this key existed.
func (c *Config) PanelCommandIntervalFor(deviceID string) int {
	if n, ok := c.Panel.CommandIntervalS[deviceID]; ok {
		return n
	}
	return c.Panel.CommandIntervalS["default"]
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
// service.toml so existing service-go users don't have to migrate; if that is
// missing too, it bootstraps a fresh default config in place (see Bootstrap).
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
		switch {
		case legacyErr == nil:
			raw = legacyRaw
			resolved = legacy
			err = nil
		case errors.Is(legacyErr, os.ErrNotExist):
			// First run on this machine: neither the canonical file nor
			// the legacy one exists. Write a working default instead of
			// exiting — an MCP client that never sees the server reach
			// "ready" simply drops the server from the session, which
			// reads as "the plugin is broken" rather than "you have not
			// configured it yet".
			bootstrapped, bootstrapErr := Bootstrap(resolved)
			if bootstrapErr != nil {
				return nil, fmt.Errorf("create %s: %w", resolved, bootstrapErr)
			}
			raw = bootstrapped
			err = nil
		default:
			// The legacy config EXISTS but could not be read (e.g. it is
			// root-owned after a sudo run). Bootstrapping over it would
			// start the broker on a brand-new passphrase and silently
			// break every device paired against the old one — fail loudly
			// instead.
			return nil, fmt.Errorf("read %s: %w", legacy, legacyErr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", resolved, err)
	}

	cfg, parseErr := parseConfig(raw)
	if parseErr != nil {
		// An explicit --config is the operator's file: report the error and
		// let them fix it rather than second-guessing what they meant.
		if explicit {
			return nil, fmt.Errorf("parse %s: %w", resolved, parseErr)
		}
		// Otherwise come up on whatever the file got right. Refusing to start
		// helps nobody: the broker is how the device gets configured in the
		// first place, so a typo in [panel] must not cost you the ability to
		// set up a device. See salvageTOML for what "got right" means.
		var kept []byte
		kept, cfg = salvageTOML(raw)
		cfg.salvaged = describeSalvage(raw, kept, parseErr)
		// A rescued file may have lost [server] with the rest of a bad
		// section. The code default binds loopback, which the device cannot
		// reach — use the same bind a fresh bootstrap would have written, so
		// "it came up" also means "you can provision against it".
		//
		// Unless the part we could not read was itself talking about bind. A
		// user who wrote a bind we failed to parse has said something about
		// their network boundary, and widening it to every interface on their
		// behalf is not a rescue. Fail closed and let the health report tell
		// them which section to fix.
		if !definesKey(kept, "server", "bind") && !mentionsBind(raw, kept) {
			cfg.Server.Bind = "0.0.0.0"
		}
	}

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
		// Neither key is set. For an explicit --config that stays an error:
		// the operator wrote that file and may be managing it from somewhere
		// else, so we do not add secrets to it behind their back.
		if explicit {
			return nil, errors.New("auth: either psk_passphrase or psk_hex is required")
		}
		// For the default config, exiting here reproduces exactly the failure
		// Bootstrap exists to prevent — the process dies before answering
		// `initialize` and the MCP client silently drops the server. Fall back
		// to a generated key kept in a sidecar file instead. Note this branch
		// is reached only when BOTH keys are absent or exactly empty; a
		// malformed value is handled above and still fails loudly.
		psk, err := fallbackPSK(filepath.Dir(resolved))
		if err != nil {
			return nil, fmt.Errorf("auth: no psk in %s and no usable fallback key: %w", resolved, err)
		}
		cfg.pskBytes = psk
	}
	cfg.Logging.Level = strings.ToUpper(cfg.Logging.Level)
	return cfg, nil
}

// parseConfig turns TOML source into a validated Config. It does everything
// Load does EXCEPT resolve the PSK, so it can be used as the predicate in
// salvageTOML without minting a sidecar key on every trial parse.
func parseConfig(src []byte) (*Config, error) {
	cfg := defaults()
	if err := toml.Unmarshal(src, cfg); err != nil {
		return nil, err
	}

	// Back-compat: a legacy tokenmonitor.toml uses [gemini] / gemini_tmp_path
	// (pre-rename, before the Gemini CLI → Antigravity CLI migration). If the
	// new [antigravity] section was not provided, fold the deprecated values
	// forward so existing installs keep working. We detect "provided" by a
	// non-zero deprecated section against the still-default new one.
	mergeLegacyGemini(cfg, src)

	// Auth is format-checked here but not resolved: a section carrying a
	// malformed key has to fail so salvageTOML drops it, and the caller then
	// falls back to the sidecar.
	//
	// The checks follow the same precedence Load resolves by — passphrase
	// first, hex only when there is no passphrase. A stale malformed psk_hex
	// sitting under a perfectly good psk_passphrase is a value nobody reads;
	// failing on it would drop the whole [auth] section, switch the broker to
	// the sidecar key and desync every device that knows the real one.
	switch {
	case cfg.Auth.Passphrase != "":
		if len(cfg.Auth.Passphrase) < 8 {
			return nil, errors.New("auth.psk_passphrase must be at least 8 characters")
		}
	case cfg.Auth.PSKHex != "":
		if len(cfg.Auth.PSKHex) != 64 {
			return nil, errors.New("auth.psk_hex must be exactly 64 hex characters")
		}
		if _, err := hex.DecodeString(cfg.Auth.PSKHex); err != nil {
			return nil, fmt.Errorf("auth.psk_hex is not valid hex: %w", err)
		}
	}
	return cfg, nil
}

// salvageTOML rebuilds the largest run of top-level sections that still loads,
// and returns both that source and the config it produced.
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
//	[auth] # """
//	psk_passphrase = "…"
//
// — string content that reads as a perfectly good section the user never
// wrote, complete with a PSK. It cannot happen here: the text before such a
// boundary ends inside an unterminated string, so it never parses, so the
// boundary is never trusted. The cost is that a *syntax* error truncates the
// salvage at that point (past it we no longer know where sections begin),
// while a merely invalid value costs only its own section.
func salvageTOML(src []byte) ([]byte, *Config) {
	var kept, prefix []byte
	cfg := defaults()
	for _, chunk := range splitTOMLSections(src) {
		// prefix is the raw text preceding this chunk — every earlier chunk,
		// kept or dropped. If it doesn't parse we are not at a known lexical
		// state, so this chunk's header is not known to be a header.
		trusted := toml.Unmarshal(prefix, &struct{}{}) == nil
		prefix = append(prefix, chunk...)
		if !trusted {
			continue
		}
		candidate := append(append([]byte{}, kept...), chunk...)
		got, err := parseConfig(candidate)
		if err != nil {
			continue
		}
		kept, cfg = candidate, got
	}
	return kept, cfg
}

// splitTOMLSections cuts src before every line whose first non-blank character
// is '[' (a table or array-of-tables header). The leading chunk holds any
// root-level keys written before the first header.
func splitTOMLSections(src []byte) [][]byte {
	lines := strings.SplitAfter(string(src), "\n")
	var out [][]byte
	var cur []byte
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "[") && len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, line...)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// describeSalvage names what was lost, for the log line and the health report.
//
// Labels are counted, not set-tested: a header can legitimately repeat
// ([[ota.keys]] is one entry per signing key), and matching by presence would
// let a dropped second entry hide behind the first one that survived — the one
// case where the salvage really would lose data silently.
func describeSalvage(src, kept []byte, cause error) []string {
	keptCount := map[string]int{}
	for _, chunk := range splitTOMLSections(kept) {
		keptCount[sectionLabel(chunk)]++
	}
	var dropped []string
	for _, chunk := range splitTOMLSections(src) {
		label := sectionLabel(chunk)
		if keptCount[label] > 0 {
			keptCount[label]--
			continue
		}
		dropped = append(dropped, label)
	}
	if len(dropped) == 0 {
		// The whole file failed as a unit (e.g. an unterminated string that
		// swallows every later header).
		dropped = []string{"<whole file>"}
	}
	return append(dropped, "cause: "+cause.Error())
}

// sectionLabel is a chunk's header line, or "<root>" for the leading keys.
func sectionLabel(chunk []byte) string {
	line := strings.TrimSpace(strings.SplitN(string(chunk), "\n", 2)[0])
	if !strings.HasPrefix(line, "[") {
		return "<root>"
	}
	return line
}

// bindAssignment matches a line that assigns the bind key. Deliberately
// textual: this runs over source the TOML parser has already rejected, where
// there is nothing to query. It is only ever used to decline to widen the
// bind, so a false positive costs reachability (recoverable, and reported)
// while a false negative would cost network exposure.
var bindAssignment = regexp.MustCompile(`(?m)^[ \t]*bind[ \t]*=`)

// mentionsBind reports whether the part of src the salvage could NOT keep
// assigns a bind.
func mentionsBind(src, kept []byte) bool {
	keptCount := map[string]int{}
	for _, chunk := range splitTOMLSections(kept) {
		keptCount[sectionLabel(chunk)]++
	}
	for _, chunk := range splitTOMLSections(src) {
		label := sectionLabel(chunk)
		if keptCount[label] > 0 {
			keptCount[label]--
			continue
		}
		if bindAssignment.Match(chunk) {
			return true
		}
	}
	return false
}

// definesKey reports whether src actually sets the given key path, as opposed
// to the value coming from defaults().
func definesKey(src []byte, path ...string) bool {
	var probe Config
	md, err := toml.Decode(string(src), &probe)
	if err != nil {
		return false
	}
	return md.IsDefined(path...)
}

// Salvaged lists the config sections that had to be dropped to get a loadable
// config, plus the parse error that caused it. Empty for a clean load.
func (c *Config) Salvaged() []string { return c.salvaged }

// Unusable returns a config built purely from defaults, with an ephemeral
// random PSK, for the degraded start the MCP entrypoint performs when Load()
// fails.
//
// It exists so a broken config can't take the MCP server down with it: exiting
// makes the client drop the server and the user sees nothing at all, whereas a
// live server can be asked what is wrong (tokenmonitor_health reports the load
// error). The caller MUST NOT serve the device broker with this — the PSK is
// invented and changes every start, so no device can authenticate against it.
// It is only here to keep the cfg-dependent tools from working on nil.
func Unusable() *Config {
	cfg := defaults()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		// A CSPRNG failure is not survivable, but this key is never used to
		// authenticate anything — a zero key is fine for a broker we are
		// deliberately not starting.
		psk = make([]byte, 32)
	}
	cfg.pskBytes = psk
	return cfg
}

// FallbackPSKName is the sidecar holding the generated key used when the
// config carries no psk_passphrase / psk_hex. It lives next to the config as
// 64 lowercase hex chars.
//
// A sidecar rather than an edit to the TOML on purpose: patching a commented,
// user-owned config by hand means re-implementing a TOML-aware source scanner
// three times (quoted/dotted keys, inline tables, multi-line strings, a
// `psk_hex` under some other table, CRLF…), and any external editor open on
// the file would race the rewrite. A whole separate file has none of that, and
// the config always wins when it does carry a key.
const FallbackPSKName = "psk"

// fallbackPSK returns the generated fallback key from dir, creating it on
// first use. Publishing goes through publishAtomic, so concurrent starts
// converge on one key: whoever loses the race adopts the winner's file rather
// than continuing with a second key nobody else knows.
func fallbackPSK(dir string) ([]byte, error) {
	path := filepath.Join(dir, FallbackPSKName)

	if raw, err := os.ReadFile(path); err == nil {
		return decodeFallbackPSK(raw, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	published, created, err := publishAtomic(path, []byte(hex.EncodeToString(key)+"\n"))
	if err != nil {
		return nil, err
	}
	if created {
		// stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
		fmt.Fprintf(os.Stderr, "tokenmonitor-mcp: config has no psk_passphrase/psk_hex, generated a fallback key at %s\n", path)
	}
	return decodeFallbackPSK(published, path)
}

// decodeFallbackPSK parses the sidecar. A file that exists but does not hold a
// 32-byte key is an error, never something to overwrite: the user may have put
// a specific key there, and silently replacing it would desync every device
// that already knows it.
func decodeFallbackPSK(raw []byte, path string) ([]byte, error) {
	text := strings.TrimSpace(string(raw))
	if len(text) != 64 {
		return nil, fmt.Errorf("%s must hold exactly 64 hex characters, has %d", path, len(text))
	}
	key, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", path, err)
	}
	return key, nil
}

// bootstrapPassphrasePlaceholder is the token BootstrapTOML carries where the
// generated passphrase goes. Kept as a distinct constant so the substitution
// can never silently no-op if the template is reworded.
const bootstrapPassphrasePlaceholder = "@@PSK_PASSPHRASE@@"

// BootstrapTOML is the minimal first-run config. It is deliberately much
// shorter than SampleTOML: every key here is one a fresh install genuinely
// needs, and the three runtimes (go / py / js) carry it verbatim, so a short
// template is a small drift surface. Everything else falls back to defaults().
//
// Keep byte-identical with tmon_mcp.config.BOOTSTRAP_TOML (py) and
// BOOTSTRAP_TOML in js/src/config.js.
const BootstrapTOML = `# TokenMonitor broker configuration.
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
psk_passphrase = "` + bootstrapPassphrasePlaceholder + `"

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
`

// Bootstrap writes a first-run config at path and returns its bytes. The
// config dir is tightened to 0700 (it also holds the device registry, i.e. the
// per-device PSKs) and the file is 0600 — it holds a shared secret.
//
// Several tokenmonitor-mcp processes can start at once (leader election
// happens later, on the port), so the publish has to be atomic in BOTH
// directions: the loser of the race must adopt the winner's file rather than
// overwrite it with a second, wholly different passphrase, AND it must never
// observe a half-written one. An O_EXCL create alone only makes the create
// atomic, not the create-then-write: the loser could open the winner's
// still-empty file and parse it as a config with no passphrase. So we write a
// private temp file first and link(2) it into place — under the final name the
// file either does not exist or is complete.
func Bootstrap(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	// Only the leaf is tightened: creating ~/.config itself 0700 would be a
	// surprising side effect on a home directory we are only a guest in. 0777
	// (i.e. let the umask decide) is what the py/js runtimes' mkdir defaults
	// to, so all three land on the same parent mode.
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	pass, err := randomPassphrase()
	if err != nil {
		return nil, err
	}
	body := []byte(strings.Replace(BootstrapTOML, bootstrapPassphrasePlaceholder, pass, 1))

	published, created, err := publishAtomic(path, body)
	if err != nil {
		return nil, err
	}
	if created {
		// stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
		fmt.Fprintf(os.Stderr, "tokenmonitor-mcp: no config found, wrote a default one at %s (psk_passphrase generated)\n", path)
	}
	return published, nil
}

// publishAtomic writes body to path and returns the bytes that ended up
// there, plus whether this caller is the one that created it.
//
// Several tokenmonitor-mcp processes can start at once (leader election
// happens later, on the port), so the publish has to be atomic in BOTH
// directions: the loser of the race must adopt the winner's file rather than
// overwrite it with different content, AND it must never observe a
// half-written one. An O_EXCL create alone only makes the create atomic, not
// the create-then-write: the loser could open the winner's still-empty file
// and use it. So write a private temp file first and link(2) it into place —
// under the final name the file either does not exist or is complete.
//
// Mirrors publish_atomic() in py/src/tmon_mcp/config.py and publishAtomic()
// in js/src/config.js.
func publishAtomic(path string, body []byte) ([]byte, bool, error) {
	// CreateTemp makes the file 0600, which is the mode we want to publish.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmon-publish.*")
	if err != nil {
		return nil, false, err
	}
	// Runs on every path: after a successful link the temp name is a stale
	// second link, and on failure it is a partial file nobody must inherit.
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return nil, false, err
	}
	if err := tmp.Close(); err != nil {
		return nil, false, err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			adopted, readErr := os.ReadFile(path)
			return adopted, false, readErr
		}
		return nil, false, err
	}
	return body, true, nil
}

// randomPassphrase returns 32 hex chars of CSPRNG output. Hex rather than
// something memorable because nobody is meant to type it: it is the broker's
// fallback key, and devices get their own PSK at pairing time.
func randomPassphrase() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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
			// Default configuration tracks all three providers; a provider with
			// no local creds just serves "creds missing" until its CLI logs in.
			Enabled:  true,
			AuthPath: "~/.codex/auth.json",
		},
		Antigravity: Antigravity{
			Enabled: true,
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
# On by default (the default config tracks all three providers). Set to
# false to hide it. auth.json contains the ChatGPT bearer token plus
# account_id required by /backend-api/wham/usage.
enabled = true
auth_path = "~/.codex/auth.json"

[antigravity]
# Enable if you also use the Antigravity CLI (agy, the successor to the
# retired Gemini CLI). The broker reads agy's consumer OAuth token from the
# OS keyring (READ-ONLY — agy keeps it fresh while it runs) and asks the
# canary cloudcode-pa host for the grouped weekly quota (Gemini Models /
# Claude+GPT). (A legacy [gemini] section is still accepted and merged here.)
# On by default; shows "creds missing" until you log in with agy. Set to
# false to hide it.
enabled = true
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
#
# By default the command is expected to loop forever (the broker only restarts
# it if it dies). If your generator samples once and exits, give it a cadence
# with command_interval_s and the broker re-runs it every N seconds instead.
# A bare number is the "default" entry; it must sit HERE, under [panel] and
# BEFORE the [panel.command] header — a key written after a sub-table header
# belongs to that sub-table, and TOML rejects it there. (Or spell it as its
# own [panel.command_interval_s] table, keyed like [panel.command].)
# command_interval_s = 900
#
# [panel.command]
# default     = ["python3", "~/bin/gen_panel.py", "--once"]
# "tmon-ab12" = ["python3", "~/bin/gen_special.py", "--once"]
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
