"""TOML config loader. Schema-compatible with tokenmonitor-mcp Go impl."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import sys
import tempfile
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PATH = "~/.config/tokenmonitor/tokenmonitor.toml"
LEGACY_PATH = "~/.config/tokenmonitor/service.toml"
DEVICES_DIR = "~/.config/tokenmonitor/devices"
FIRMWARE_DIR = "~/.config/tokenmonitor/firmware"


def devices_path() -> str:
    return str(Path(DEVICES_DIR).expanduser())


def firmware_path() -> str:
    return str(Path(FIRMWARE_DIR).expanduser())


# The token BOOTSTRAP_TOML carries where the generated passphrase goes. Kept as
# a distinct constant so the substitution can never silently no-op if the
# template is reworded.
_BOOTSTRAP_PASSPHRASE_PLACEHOLDER = "@@PSK_PASSPHRASE@@"

# Minimal first-run config. Deliberately much shorter than the Go SampleTOML:
# every key here is one a fresh install genuinely needs, and the three runtimes
# (go / py / js) carry it verbatim, so a short template is a small drift
# surface. Everything else falls back to the dataclass defaults.
#
# Keep byte-identical with config.BootstrapTOML (go) and BOOTSTRAP_TOML in
# js/src/config.js.
BOOTSTRAP_TOML = f"""# TokenMonitor broker configuration.
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
psk_passphrase = "{_BOOTSTRAP_PASSPHRASE_PLACEHOLDER}"

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
"""


def bootstrap(target: Path) -> str:
    """Write a first-run config at *target* and return its text.

    The config dir is tightened to 0700 (it also holds the device registry, i.e.
    the per-device PSKs) and the file is 0600 — it holds a shared secret.

    Several tokenmonitor-mcp processes can start at once (leader election
    happens later, on the port), so the publish has to be atomic in BOTH
    directions: the loser of the race must adopt the winner's file rather than
    overwrite it with a second, wholly different passphrase, AND it must never
    observe a half-written one. An O_EXCL create alone only makes the create
    atomic, not the create-then-write: the loser could open the winner's
    still-empty file and parse it as a config with no passphrase. So we write a
    private temp file first and os.link() it into place — under the final name
    the file either does not exist or is complete.

    The passphrase is 32 hex chars rather than something memorable because
    nobody is meant to type it: it is the broker's fallback key, and devices get
    their own PSK at pairing time.
    """
    # Only the leaf is tightened: creating ~/.config itself 0700 would be a
    # surprising side effect on a home directory we are only a guest in.
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    body = BOOTSTRAP_TOML.replace(_BOOTSTRAP_PASSPHRASE_PLACEHOLDER, secrets.token_hex(16))

    published, created = publish_atomic(target, body)
    if created:
        # stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
        print(
            f"tokenmonitor-mcp: no config found, wrote a default one at {target} "
            "(psk_passphrase generated)",
            file=sys.stderr,
        )
    return published


def publish_atomic(target: Path, body: str) -> tuple[str, bool]:
    """Write *body* to *target*; return (text now at target, did we create it).

    Several tokenmonitor-mcp processes can start at once (leader election
    happens later, on the port), so the publish has to be atomic in BOTH
    directions: the loser of the race must adopt the winner's file rather than
    overwrite it with different content, AND it must never observe a
    half-written one. An O_EXCL create alone only makes the create atomic, not
    the create-then-write: the loser could open the winner's still-empty file
    and use it. So write a private temp file first and os.link() it into place —
    under the final name the file either does not exist or is complete.

    Mirrors publishAtomic() in go/internal/config/config.go and js/src/config.js.
    """
    # mkstemp creates 0600, which is the mode we want to publish. Explicit
    # UTF-8: the template is not ASCII, and the file has to stay readable by the
    # Go and JS runtimes (and by this one under any locale).
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmon-publish.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        try:
            os.link(tmp, target)
        except FileExistsError:
            # Another process published first; its file is as good as ours.
            return target.read_text(encoding="utf-8"), False
    finally:
        # Runs on every path: after a successful link the temp name is a stale
        # second link, and on failure it is a partial file nobody must inherit.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    return body, True


def unusable_config() -> Config:
    """A config built purely from defaults, with an ephemeral random PSK, for
    the degraded start the MCP entrypoint performs when load() fails.

    It exists so a broken config can't take the MCP server down with it:
    exiting makes the client drop the server and the user sees nothing at all,
    whereas a live server can be asked what is wrong (tokenmonitor_health
    reports the load error). The caller MUST NOT serve the device broker with
    this — the PSK is invented and changes every start, so no device can
    authenticate against it. It is only here to keep the cfg-dependent tools
    from working on None.
    """
    cfg = Config()
    cfg.psk_bytes = secrets.token_bytes(32)
    return cfg


# The sidecar holding the generated key used when the config carries no
# psk_passphrase / psk_hex. It lives next to the config as 64 lowercase hex
# chars.
#
# A sidecar rather than an edit to the TOML on purpose: patching a commented,
# user-owned config by hand means re-implementing a TOML-aware source scanner
# three times (quoted/dotted keys, inline tables, multi-line strings, a
# `psk_hex` under some other table, CRLF…), and any external editor open on the
# file would race the rewrite. A whole separate file has none of that, and the
# config always wins when it does carry a key.
FALLBACK_PSK_NAME = "psk"


def fallback_psk(directory: Path) -> bytes:
    """Return the generated fallback key from *directory*, creating it on first
    use. Publishing goes through publish_atomic, so concurrent starts converge
    on one key: whoever loses the race adopts the winner's file rather than
    continuing with a second key nobody else knows."""
    path = directory / FALLBACK_PSK_NAME
    try:
        return _decode_fallback_psk(path.read_text(encoding="utf-8"), path)
    except FileNotFoundError:
        pass

    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    published, created = publish_atomic(path, secrets.token_hex(32) + "\n")
    if created:
        # stdio MCP reserves stdout for JSON-RPC; notices go to stderr.
        print(
            "tokenmonitor-mcp: config has no psk_passphrase/psk_hex, "
            f"generated a fallback key at {path}",
            file=sys.stderr,
        )
    return _decode_fallback_psk(published, path)


def _decode_fallback_psk(raw: str, path: Path) -> bytes:
    """Parse the sidecar. A file that exists but does not hold a 32-byte key is
    an error, never something to overwrite: the user may have put a specific key
    there, and silently replacing it would desync every device that knows it."""
    text = raw.strip()
    if len(text) != 64:
        raise ValueError(f"{path} must hold exactly 64 hex characters, has {len(text)}")
    try:
        return bytes.fromhex(text)
    except ValueError as e:
        raise ValueError(f"{path} is not valid hex") from e


@dataclass
class Server:
    bind: str = "127.0.0.1"
    port: int = 8765


@dataclass
class Auth:
    psk_passphrase: str = ""
    psk_hex: str = ""


@dataclass
class Credentials:
    oauth_path: str = "~/.claude/.credentials.json"


@dataclass
class Codex:
    # Default config tracks all three providers; one with no local creds
    # just serves "creds missing" until its CLI logs in.
    enabled: bool = True
    auth_path: str = "~/.codex/auth.json"


# Default ordered list of model IDs the broker exposes as `slots` on
# /usage/antigravity when [antigravity].models is unset. The Antigravity CLI
# (`agy`, the successor to the retired Gemini CLI) keys its quota buckets by
# model ID (e.g. gemini-3.5-flash-low); we surface the Flash and Pro families
# — prefix matching tolerates the effort suffix (-low/-medium/-high) Google
# appends. Verified model IDs (agy 1.0.13, 2026-06-30):
# gemini-3.5-flash-{low,medium,high}, gemini-3.1-pro-{low,high}.
DEFAULT_ANTIGRAVITY_MODELS = ["gemini-3.5-flash", "gemini-3.1-pro"]

# The firmware dashboard has 3 fixed card slots (large/large/small).
# Slots beyond this index are ignored on device.
MAX_ANTIGRAVITY_MODELS = 3


@dataclass
class Antigravity:
    """Config for the loadCodeAssist usage probe of the Antigravity CLI
    (`agy`, the successor to the retired Gemini CLI). creds_path points at
    the CLI's oauth_creds.json (still under ~/.gemini/, shared with the
    legacy layout); projects_path at its projects.json. Both optional."""

    enabled: bool = True
    creds_path: str = "~/.gemini/oauth_creds.json"
    projects_path: str = "~/.gemini/projects.json"
    # OS keyring service holding agy's consumer OAuth token (the quota RPC
    # requires it; the oauth_creds.json token is rejected there). Read via
    # `secret-tool lookup service <name>`. Verified via live capture 2026-06-30.
    keyring_service: str = "gemini"
    models: list[str] = field(default_factory=list)


# Gemini is the DEPRECATED pre-rename alias for Antigravity, kept structurally
# identical so a legacy [gemini] section unmarshals and can be merged into the
# canonical Antigravity fields in load().
Gemini = Antigravity


@dataclass
class Usage:
    cache_ttl_seconds: int = 30


@dataclass
class Spend:
    """Locally-computed token cost from the CLI logs on this host (see
    compat/SPEND_WIRE.md). No admin key. Longer TTL than Usage because
    spend changes slowly and parsing is heavier."""

    enabled: bool = True
    cache_ttl_seconds: int = 300
    claude_projects_path: str = "~/.claude/projects"
    claude_stats_cache_path: str = "~/.claude/stats-cache.json"
    codex_sessions_path: str = "~/.codex/sessions"
    # antigravity_conversations_path is the Antigravity CLI's per-conversation
    # SQLite trajectory store. gemini_tmp_path is the DEPRECATED pre-rename key,
    # merged into it in load() so a legacy tokenmonitor.toml keeps working.
    antigravity_conversations_path: str = "~/.gemini/antigravity/conversations"
    gemini_tmp_path: str = ""


@dataclass
class Pricing:
    """Model price table used to turn tokens into USD. Source of truth is
    LiteLLM's machine-readable table; cached on disk with an embedded
    fallback so $ works offline."""

    url: str = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
    cache_path: str = "~/.config/tokenmonitor/pricing-cache.json"
    ttl_hours: int = 24


@dataclass
class Panel:
    """Optional custom-panel screen source. The user's own program writes a
    self-describing JSON document (charts / tables) that the broker serves
    verbatim from GET /device/<id>/panel. Everything empty ⇒ feature off (404).

    file: which document to serve, per device. Either a bare string (shorthand
          for the "default" entry) or a [panel.file] table keyed by device id
          with a "default" fallback — tomllib yields str or dict respectively.
    dir:  a directory of per-device docs (<dir>/<id>.json wins, then
          <dir>/default.json); slots between the explicit file entry and the
          file "default".
    command: optional per-device generator the broker launches itself
          (leader-scoped — see panel_generator). A [panel.command] table keyed
          by device id with a "default" fallback; each value is an argv list
          run without a shell.
    command_interval_s: optional pacing for those generators. Absent (or 0)
          keeps the default contract — the command is a long-lived process the
          broker keeps alive. Set, it makes the command a periodic one-shot,
          re-run every N seconds. Same two spellings as `file`: a bare number
          (the "default" entry) or a table keyed by device id."""

    file: str | dict = ""
    dir: str = ""
    command: dict = field(default_factory=dict)
    command_interval_s: int | float | dict = 0


@dataclass
class Security:
    max_timestamp_skew_seconds: int = 60
    nonce_cache_ttl_seconds: int = 300


@dataclass
class Logging:
    level: str = "INFO"


@dataclass
class Serial:
    device: str = ""
    baud: int = 115200
    lines: int = 2000


@dataclass
class OTAKey:
    """One entry in the OTA verification keyring: a key_id matching the
    manifest's key_id field, and the 32-byte raw Ed25519 public key,
    base64-std encoded. Mirror of Go config.OTAKey."""

    key_id: str = ""
    pubkey_b64: str = ""


@dataclass
class OTA:
    """Broker-driven OTA config. Mirror of Go config.OTAConfig.

    The loop runs only on the leader and is inert (does nothing) unless
    enabled, a repo is set, and at least one key is present — without a
    pubkey the broker cannot verify a manifest and refuses to stage one
    it can't authenticate."""

    enabled: bool = True
    releases_repo: str = "https://github.com/fractal-manifold/tokenmonitor-ota-releases"
    poll_interval_minutes: int = 60
    # dev_tag is the rolling GitHub release tag the broker fetches the
    # per-SKU asset from for devices on the "dev" channel. Stable devices
    # ride the latest/download redirect instead.
    dev_tag: str = "dev"
    keys: list[OTAKey] = field(default_factory=list)

    def configured(self) -> bool:
        return self.enabled and bool(self.releases_repo) and len(self.keys) > 0

    def pubkey(self, key_id: str) -> bytes | None:
        """Return the 32-byte raw Ed25519 public key for key_id, or None
        when the keyring has no matching, well-formed entry."""
        for k in self.keys:
            if k.key_id != key_id:
                continue
            try:
                b = base64.b64decode(k.pubkey_b64.strip(), validate=True)
            except (binascii.Error, ValueError):
                return None
            return b if len(b) == 32 else None
        return None


@dataclass
class Config:
    server: Server = field(default_factory=Server)
    auth: Auth = field(default_factory=Auth)
    credentials: Credentials = field(default_factory=Credentials)
    codex: Codex = field(default_factory=Codex)
    antigravity: Antigravity = field(default_factory=Antigravity)
    # gemini is the DEPRECATED pre-rename alias for [antigravity]. A legacy
    # tokenmonitor.toml with a [gemini] section is still honoured — load()
    # merges it into antigravity when the new section is absent.
    gemini: Gemini = field(default_factory=Gemini)
    usage: Usage = field(default_factory=Usage)
    spend: Spend = field(default_factory=Spend)
    pricing: Pricing = field(default_factory=Pricing)
    panel: Panel = field(default_factory=Panel)
    security: Security = field(default_factory=Security)
    logging: Logging = field(default_factory=Logging)
    serial: Serial = field(default_factory=Serial)
    ota: OTA = field(default_factory=OTA)
    psk_bytes: bytes = b""
    # Sections dropped to get a loadable config, plus the parse error that
    # caused it. Empty for a clean load. See _salvage_toml.
    salvaged: list[str] = field(default_factory=list)

    def psk(self) -> bytes:
        return self.psk_bytes

    def oauth_path_abs(self) -> str:
        return str(Path(self.credentials.oauth_path).expanduser())

    def codex_auth_path_abs(self) -> str:
        return str(Path(self.codex.auth_path).expanduser())

    def antigravity_creds_path_abs(self) -> str:
        return str(Path(self.antigravity.creds_path).expanduser())

    def antigravity_projects_path_abs(self) -> str:
        return str(Path(self.antigravity.projects_path).expanduser())

    def claude_projects_path_abs(self) -> str:
        return str(Path(self.spend.claude_projects_path).expanduser())

    def claude_stats_cache_path_abs(self) -> str:
        return str(Path(self.spend.claude_stats_cache_path).expanduser())

    def codex_sessions_path_abs(self) -> str:
        return str(Path(self.spend.codex_sessions_path).expanduser())

    def antigravity_conversations_path_abs(self) -> str:
        return str(Path(self.spend.antigravity_conversations_path).expanduser())

    def pricing_cache_path_abs(self) -> str:
        return str(Path(self.pricing.cache_path).expanduser())

    def _panel_file_map(self) -> dict[str, str]:
        """Normalise panel.file (str shorthand or table) to an id -> path map."""
        f = self.panel.file
        if isinstance(f, dict):
            return f
        if isinstance(f, str) and f:
            return {"default": f}
        return {}

    def panel_file_explicit_abs(self, device_id: str) -> str:
        """The document path configured specifically for device_id (no
        "default" fallback), expanded. "" when it has no explicit entry."""
        if not device_id:
            return ""
        v = self._panel_file_map().get(device_id)
        return str(Path(v).expanduser()) if v else ""

    def panel_file_default_abs(self) -> str:
        """The [panel.file] "default" entry (or the legacy bare file), expanded."""
        v = self._panel_file_map().get("default")
        return str(Path(v).expanduser()) if v else ""

    def panel_dir_abs(self) -> str:
        return str(Path(self.panel.dir).expanduser()) if self.panel.dir else ""

    def panel_command_map(self) -> dict[str, list[str]]:
        """Generator commands keyed by device id (plus a possible "default"),
        with every argv element tilde-expanded (there is no shell). Empty when
        no [panel.command] is configured — panel_generator treats that as
        "feature off"."""
        cmds = self.panel.command or {}
        out: dict[str, list[str]] = {}
        for key, argv in cmds.items():
            # Only a non-empty list of strings is a valid argv. Skip anything
            # else (e.g. a bare string, which would otherwise iterate into
            # individual characters). Go rejects it at TOML parse time.
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                continue
            out[key] = [_expand_argv_elem(a) for a in argv]
        return out

    def panel_command_interval_for(self, device_id: str) -> float:
        """How often (seconds) to re-run device_id's generator: its own
        [panel.command_interval_s] entry, else "default", else 0.

        Zero means unset — panel_generator keeps that generator as a long-lived
        process, which is what every config did before this key existed.

        load() already rejects a negative, fractional or non-numeric entry (as
        Go does at TOML parse time), so those never reach here from a real
        config file; the coercion below only guards a Config built by hand in
        a test."""
        iv = self.panel.command_interval_s
        raw = iv.get(device_id, iv.get("default", 0)) if isinstance(iv, dict) else iv
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return 0.0
        return float(raw) if raw > 0 else 0.0

    def antigravity_models(self) -> list[str]:
        """Return the configured model list, clamped to MAX_ANTIGRAVITY_MODELS.

        Empty config falls back to DEFAULT_ANTIGRAVITY_MODELS so the device
        always sees at least Flash + Pro."""
        src = self.antigravity.models or DEFAULT_ANTIGRAVITY_MODELS
        return list(src[:MAX_ANTIGRAVITY_MODELS])


def _expand_argv_elem(a: str) -> str:
    """Expand a leading ~/ in an argv element, matching Go's expandUser (only
    the ~/ prefix, not bare ~user)."""
    return str(Path(a).expanduser()) if a.startswith("~/") else a


def _section(raw: dict, name: str, target: object) -> None:
    sect = raw.get(name) or {}
    for key, value in sect.items():
        if hasattr(target, key):
            setattr(target, key, value)


def _validate_panel_command_interval(cfg: Config) -> None:
    """Reject a [panel.command_interval_s] the user clearly did not mean.

    Go refuses to start on these, so we do too — the three impls are supposed
    to behave identically on the same toml, and a broker that silently ignores
    the key leaves the user wondering why their pacing never took effect.
    Whole seconds only: rounding 0.5 to 0 would quietly turn "twice a second"
    into "long-lived process", the opposite contract."""
    iv = cfg.panel.command_interval_s
    entries = iv.items() if isinstance(iv, dict) else [("default", iv)]
    for key, raw in entries:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(
                f"panel.command_interval_s[{key!r}]: expected integer, got {type(raw).__name__}"
            )
        if raw < 0:
            raise ValueError(f"panel.command_interval_s[{key!r}]: must be >= 0, got {raw}")
        if float(raw) != int(raw):
            raise ValueError(
                f"panel.command_interval_s[{key!r}]: whole seconds only, got {raw}"
            )


def _merge_legacy_gemini(cfg: Config, raw: dict) -> None:
    """Fold a deprecated pre-rename [gemini] section / gemini_tmp_path forward
    into the canonical Antigravity fields when the new keys are absent.

    Mirrors Go config.mergeLegacyGemini: a legacy tokenmonitor.toml (written
    before the Gemini CLI -> Antigravity CLI migration) used [gemini] and
    spend.gemini_tmp_path. If the new [antigravity] section was not provided,
    adopt the deprecated values so existing installs keep working. Detection
    uses key presence in the raw TOML so "not provided" is not confused with
    "set to a zero value"."""
    if "antigravity" not in raw and "gemini" in raw:
        # Read `enabled` from the raw [gemini] section (default False when the
        # key is absent) rather than cfg.gemini.enabled, whose dataclass default
        # is now True — matching Go (`cfg.Gemini.Enabled`, zero-value false) and
        # JS (`!!g.enabled`) so a legacy [gemini] with no `enabled` behaves
        # identically across all three impls.
        gem = raw.get("gemini") or {}
        cfg.antigravity.enabled = bool(gem.get("enabled", False))
        if cfg.gemini.creds_path:
            cfg.antigravity.creds_path = cfg.gemini.creds_path
        if cfg.gemini.projects_path:
            cfg.antigravity.projects_path = cfg.gemini.projects_path
        if cfg.gemini.models:
            cfg.antigravity.models = cfg.gemini.models
    spend_raw = raw.get("spend") or {}
    if (
        "antigravity_conversations_path" not in spend_raw
        and "gemini_tmp_path" in spend_raw
        and cfg.spend.gemini_tmp_path
    ):
        cfg.spend.antigravity_conversations_path = cfg.spend.gemini_tmp_path


# Fields whose TOML type must be enforced by hand, because unlike Go's typed
# unmarshal `_section` copies whatever the file said straight onto the
# dataclass. Not the whole schema — these are the ones where a wrong type is
# not merely ignored but changes behaviour: the listener address and port, and
# the two replay-window bounds, where a non-number would make every comparison
# against it meaningless rather than strict.
_TYPED_FIELDS: tuple[tuple[str, str, type | tuple[type, ...], str], ...] = (
    ("auth", "psk_passphrase", str, "a string"),
    ("auth", "psk_hex", str, "a string"),
    ("server", "bind", str, "a string"),
    ("server", "port", int, "an integer"),
    ("security", "max_timestamp_skew_seconds", int, "an integer"),
    ("security", "nonce_cache_ttl_seconds", int, "an integer"),
)


def _require_types(cfg: Config) -> None:
    for section, key, want, label in _TYPED_FIELDS:
        value = getattr(getattr(cfg, section), key)
        # bool is an int subclass in Python but a distinct TOML type; Go rejects
        # `port = true`, so we do too.
        if isinstance(value, bool) or not isinstance(value, want):
            raise ValueError(f"{section}.{key} must be {label}")


def _parse_config(text: str) -> Config:
    """Turn TOML source into a validated Config.

    Mirror of Go config.parseConfig: everything load() does EXCEPT resolving the
    PSK, so it can be the predicate in _salvage_toml without minting a sidecar
    key on every trial parse."""
    raw = tomllib.loads(text)
    cfg = Config()
    _section(raw, "server", cfg.server)
    _section(raw, "auth", cfg.auth)
    _section(raw, "credentials", cfg.credentials)
    _section(raw, "codex", cfg.codex)
    _section(raw, "antigravity", cfg.antigravity)
    _section(raw, "gemini", cfg.gemini)
    _section(raw, "usage", cfg.usage)
    _section(raw, "spend", cfg.spend)
    _section(raw, "pricing", cfg.pricing)
    _section(raw, "panel", cfg.panel)
    _section(raw, "security", cfg.security)
    _section(raw, "logging", cfg.logging)
    _section(raw, "serial", cfg.serial)

    # [ota] needs bespoke parsing: the nested [[ota.keys]] array of tables
    # doesn't map through _section's flat setattr loop.
    ota_raw = raw.get("ota") or {}
    if "enabled" in ota_raw:
        cfg.ota.enabled = bool(ota_raw["enabled"])
    if "releases_repo" in ota_raw:
        cfg.ota.releases_repo = str(ota_raw["releases_repo"])
    if "poll_interval_minutes" in ota_raw:
        cfg.ota.poll_interval_minutes = int(ota_raw["poll_interval_minutes"])
    if "dev_tag" in ota_raw:
        cfg.ota.dev_tag = str(ota_raw["dev_tag"])
    cfg.ota.keys = [
        OTAKey(key_id=str(k.get("key_id", "")), pubkey_b64=str(k.get("pubkey_b64", "")))
        for k in (ota_raw.get("keys") or [])
    ]

    _merge_legacy_gemini(cfg, raw)
    _validate_panel_command_interval(cfg)

    # _section copies TOML values through without type enforcement, while Go's
    # typed unmarshal rejects a wrong type outright — so without this the three
    # runtimes disagree about which sections survive salvage, and worse, about
    # what a value means. `psk_hex = []` would read as "unset" here and as an
    # error in Go; `max_timestamp_skew_seconds = "off"` would make every
    # comparison against it false in JS, silently disabling timestamp expiry.
    _require_types(cfg)

    # Auth is format-checked here but not resolved: a section carrying a
    # malformed key has to fail so _salvage_toml drops it, and the caller then
    # falls back to the sidecar.
    #
    # The checks follow the same precedence load() resolves by — passphrase
    # first, hex only when there is no passphrase. A stale malformed psk_hex
    # sitting under a perfectly good psk_passphrase is a value nobody reads;
    # failing on it would drop the whole [auth] section, switch the broker to
    # the sidecar key and desync every device that knows the real one.
    if cfg.auth.psk_passphrase != "":
        # Bytes, not code points: Go measures the UTF-8 encoding and the PSK is
        # derived from those same bytes in all three runtimes.
        if len(cfg.auth.psk_passphrase.encode("utf-8")) < 8:
            raise ValueError("auth.psk_passphrase must be at least 8 characters")
    elif cfg.auth.psk_hex != "":
        if len(cfg.auth.psk_hex) != 64:
            raise ValueError("auth.psk_hex must be exactly 64 hex characters")
        try:
            bytes.fromhex(cfg.auth.psk_hex)
        except ValueError as e:
            raise ValueError("auth.psk_hex is not valid hex") from e
    return cfg


def _split_toml_sections(src: str) -> list[str]:
    """Cut src before every line whose first non-blank character is '[' (a table
    or array-of-tables header). The leading chunk holds any root-level keys
    written before the first header."""
    out: list[str] = []
    cur = ""
    for line in src.splitlines(keepends=True):
        if line.lstrip(" \t").startswith("[") and cur:
            out.append(cur)
            cur = ""
        cur += line
    if cur:
        out.append(cur)
    return out


def _salvage_toml(src: str) -> tuple[str, Config]:
    """Rebuild the largest run of top-level sections that still loads, and
    return both that source and the config it produced.

    Mirror of Go config.salvageTOML. The file is split at top-level table
    headers, so a section is the unit that survives or dies as a whole — never
    an individual line. Dropping a lone line would be worse than useless: lose a
    `[server]` header and every key under it silently joins the PREVIOUS table,
    which is a config that parses and means something the user never wrote.

    Sections are then re-accumulated in order, keeping each one only if the text
    so far still parses AND validates. That covers both a syntax error and a
    merely invalid value (a 4-character passphrase, a fractional
    command_interval_s) with the same mechanism, and the survivors are re-parsed
    as one document — so [[ota.keys]] arrays merge with normal TOML semantics
    instead of some hand-rolled deep merge.

    A chunk is only considered at all when everything BEFORE it parses as TOML.
    That test is what makes the split safe rather than merely plausible. A line
    starting with `[` inside a multi-line string is not a header, and splitting
    there would hand us a chunk like

        [auth] # \"\"\"
        psk_passphrase = "…"

    — string content that reads as a perfectly good section the user never
    wrote, complete with a PSK. It cannot happen here: the text before such a
    boundary ends inside an unterminated string, so it never parses, so the
    boundary is never trusted. The cost is that a *syntax* error truncates the
    salvage at that point (past it we no longer know where sections begin),
    while a merely invalid value costs only its own section."""
    kept = ""
    prefix = ""
    cfg = Config()
    for chunk in _split_toml_sections(src):
        # prefix is the raw text preceding this chunk — every earlier chunk,
        # kept or dropped. If it doesn't parse we are not at a known lexical
        # state, so this chunk's header is not known to be a header.
        try:
            tomllib.loads(prefix)
            trusted = True
        except Exception:
            trusted = False
        prefix += chunk
        if not trusted:
            continue
        candidate = kept + chunk
        try:
            got = _parse_config(candidate)
        except Exception:
            continue
        kept, cfg = candidate, got
    return kept, cfg


def _section_label(chunk: str) -> str:
    """A chunk's header line, or "<root>" for the leading keys."""
    line = chunk.split("\n", 1)[0].strip()
    return line if line.startswith("[") else "<root>"


def _describe_salvage(src: str, kept: str, cause: Exception) -> list[str]:
    """Name what was lost, for the log line and the health report.

    Labels are counted, not set-tested: a header can legitimately repeat
    ([[ota.keys]] is one entry per signing key), and matching by presence would
    let a dropped second entry hide behind the first one that survived — the one
    case where the salvage really would lose data silently."""
    kept_count = Counter(_section_label(c) for c in _split_toml_sections(kept))
    dropped: list[str] = []
    for chunk in _split_toml_sections(src):
        label = _section_label(chunk)
        if kept_count[label] > 0:
            kept_count[label] -= 1
            continue
        dropped.append(label)
    if not dropped:
        # The whole file failed as a unit (e.g. an unterminated string that
        # swallows every later header).
        dropped = ["<whole file>"]
    return dropped + [f"cause: {cause}"]


# Matches a line that assigns the bind key. Deliberately textual: this runs
# over source the TOML parser has already rejected, where there is nothing to
# query. It is only ever used to decline to widen the bind, so a false positive
# costs reachability (recoverable, and reported) while a false negative would
# cost network exposure.
_BIND_ASSIGNMENT = re.compile(r"^[ \t]*bind[ \t]*=", re.MULTILINE)


def _mentions_bind(src: str, kept: str) -> bool:
    """Whether the part of src the salvage could NOT keep assigns a bind."""
    kept_count = Counter(_section_label(c) for c in _split_toml_sections(kept))
    for chunk in _split_toml_sections(src):
        label = _section_label(chunk)
        if kept_count[label] > 0:
            kept_count[label] -= 1
            continue
        if _BIND_ASSIGNMENT.search(chunk):
            return True
    return False


def _defines_key(src: str, *path: str) -> bool:
    """Whether src actually sets the given key path, as opposed to the value
    coming from the dataclass defaults."""
    try:
        node: object = tomllib.loads(src)
    except Exception:
        return False
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def load(path: str | None = None) -> Config:
    """Mirror of Go Load: explicit path errors; default falls back to service.toml."""
    explicit = bool(path)
    target = Path(path).expanduser() if path else Path(DEFAULT_PATH).expanduser()
    text: str | None = None
    # exists(), not is_file(): Go and JS decide on the read errno / a bare
    # existence check, so a path that exists but is not a regular file (someone
    # mkdir'd a service.toml/) must fail loudly here too rather than be treated
    # as absent and quietly bootstrapped past.
    if not target.exists() and not explicit:
        legacy = Path(LEGACY_PATH).expanduser()
        if legacy.exists():
            target = legacy
        else:
            # First run on this machine: neither the canonical file nor the
            # legacy one exists. Write a working default instead of raising —
            # an MCP client that never sees the server reach "ready" simply
            # drops the server from the session, which reads as "the plugin is
            # broken" rather than "you have not configured it yet".
            text = bootstrap(target)
    if text is None:
        if not target.exists():
            raise FileNotFoundError(f"read {target}: file not found")
        # Explicit UTF-8: a config written by the Go or JS runtime (or by our own
        # bootstrap) contains non-ASCII, and must not depend on the locale.
        text = target.read_text(encoding="utf-8")

    try:
        cfg = _parse_config(text)
    except Exception as parse_err:
        # An explicit --config is the operator's file: report the error and let
        # them fix it rather than second-guessing what they meant.
        if explicit:
            raise ValueError(f"parse {target}: {parse_err}") from parse_err
        # Otherwise come up on whatever the file got right. Refusing to start
        # helps nobody: the broker is how the device gets configured in the
        # first place, so a typo in [panel] must not cost you the ability to set
        # up a device. See _salvage_toml for what "got right" means.
        kept, cfg = _salvage_toml(text)
        cfg.salvaged = _describe_salvage(text, kept, parse_err)
        # A rescued file may have lost [server] with the rest of a bad section.
        # The code default binds loopback, which the device cannot reach — use
        # the same bind a fresh bootstrap would have written, so "it came up"
        # also means "you can provision against it".
        #
        # Unless the part we could not read was itself talking about bind. A
        # user who wrote a bind we failed to parse has said something about
        # their network boundary, and widening it to every interface on their
        # behalf is not a rescue. Fail closed and let the health report tell
        # them which section to fix.
        if not _defines_key(kept, "server", "bind") and not _mentions_bind(text, kept):
            cfg.server.bind = "0.0.0.0"

    # Absent or exactly empty means "unset". A malformed value never reaches
    # here: _parse_config rejects it, and for the default config path the
    # section carrying it has already been dropped by the salvage above.
    if cfg.auth.psk_passphrase != "":
        # Bytes, not code points — see _parse_config.
        if len(cfg.auth.psk_passphrase.encode("utf-8")) < 8:
            raise ValueError("auth.psk_passphrase must be at least 8 characters")
        cfg.psk_bytes = hashlib.sha256(cfg.auth.psk_passphrase.encode("utf-8")).digest()
    elif cfg.auth.psk_hex != "":
        if len(cfg.auth.psk_hex) != 64:
            raise ValueError("auth.psk_hex must be exactly 64 hex characters")
        try:
            cfg.psk_bytes = bytes.fromhex(cfg.auth.psk_hex)
        except ValueError as e:
            raise ValueError("auth.psk_hex is not valid hex") from e
        cfg.auth.psk_hex = cfg.auth.psk_hex.lower()
    elif explicit:
        # The operator wrote that file and may be managing it from somewhere
        # else, so we do not add secrets to it behind their back.
        raise ValueError("auth: either psk_passphrase or psk_hex is required")
    else:
        # Raising here would reproduce exactly the failure bootstrap exists to
        # prevent: the process dies before answering `initialize` and the MCP
        # client silently drops the server. Fall back to a generated key kept in
        # a sidecar file instead.
        try:
            cfg.psk_bytes = fallback_psk(target.parent)
        except OSError as e:
            raise ValueError(
                f"auth: no psk in {target} and no usable fallback key: {e}"
            ) from e

    cfg.logging.level = (cfg.logging.level or "INFO").upper()
    return cfg
