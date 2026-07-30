"""TOML config loader. Schema-compatible with tokenmonitor-mcp Go impl."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import tomllib
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


def load(path: str | None = None) -> Config:
    """Mirror of Go Load: explicit path errors; default falls back to service.toml."""
    explicit = bool(path)
    target = Path(path).expanduser() if path else Path(DEFAULT_PATH).expanduser()
    if not target.is_file() and not explicit:
        legacy = Path(LEGACY_PATH).expanduser()
        if legacy.is_file():
            target = legacy
    if not target.is_file():
        raise FileNotFoundError(f"read {target}: file not found")

    raw = tomllib.loads(target.read_text())
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

    if cfg.auth.psk_passphrase:
        if len(cfg.auth.psk_passphrase) < 8:
            raise ValueError("auth.psk_passphrase must be at least 8 characters")
        cfg.psk_bytes = hashlib.sha256(cfg.auth.psk_passphrase.encode("utf-8")).digest()
    elif cfg.auth.psk_hex:
        if len(cfg.auth.psk_hex) != 64:
            raise ValueError("auth.psk_hex must be exactly 64 hex characters")
        try:
            cfg.psk_bytes = bytes.fromhex(cfg.auth.psk_hex)
        except ValueError as e:
            raise ValueError("auth.psk_hex is not valid hex") from e
        cfg.auth.psk_hex = cfg.auth.psk_hex.lower()
    else:
        raise ValueError("auth: either psk_passphrase or psk_hex is required")

    cfg.logging.level = (cfg.logging.level or "INFO").upper()
    return cfg
