"""TOML config loader. Schema-compatible with cwm-mcp Go impl."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_PATH = "~/.config/cwallmonitor/cwm.toml"
LEGACY_PATH = "~/.config/cwallmonitor/service.toml"
DEVICES_DIR = "~/.config/cwallmonitor/devices"
FIRMWARE_DIR = "~/.config/cwallmonitor/firmware"


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
    enabled: bool = False
    auth_path: str = "~/.codex/auth.json"


# Default ordered list of model IDs the broker exposes as `slots` on
# /usage/gemini when [gemini].models is unset. Pro is the headline model
# users care most about; Flash is the high-volume bucket.
DEFAULT_GEMINI_MODELS = ["gemini-2.5-pro", "gemini-2.5-flash"]

# The firmware dashboard has 3 fixed card slots (large/large/small).
# Slots beyond this index are ignored on device.
MAX_GEMINI_MODELS = 3


@dataclass
class Gemini:
    enabled: bool = False
    creds_path: str = "~/.gemini/oauth_creds.json"
    projects_path: str = "~/.gemini/projects.json"
    models: list[str] = field(default_factory=list)


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
    gemini_tmp_path: str = "~/.gemini/tmp"


@dataclass
class Pricing:
    """Model price table used to turn tokens into USD. Source of truth is
    LiteLLM's machine-readable table; cached on disk with an embedded
    fallback so $ works offline."""

    url: str = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
    cache_path: str = "~/.config/cwallmonitor/pricing-cache.json"
    ttl_hours: int = 24


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
    releases_repo: str = "https://github.com/fractal-manifold/cwm-ota-releases"
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
    gemini: Gemini = field(default_factory=Gemini)
    usage: Usage = field(default_factory=Usage)
    spend: Spend = field(default_factory=Spend)
    pricing: Pricing = field(default_factory=Pricing)
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

    def gemini_creds_path_abs(self) -> str:
        return str(Path(self.gemini.creds_path).expanduser())

    def gemini_projects_path_abs(self) -> str:
        return str(Path(self.gemini.projects_path).expanduser())

    def claude_projects_path_abs(self) -> str:
        return str(Path(self.spend.claude_projects_path).expanduser())

    def claude_stats_cache_path_abs(self) -> str:
        return str(Path(self.spend.claude_stats_cache_path).expanduser())

    def codex_sessions_path_abs(self) -> str:
        return str(Path(self.spend.codex_sessions_path).expanduser())

    def gemini_tmp_path_abs(self) -> str:
        return str(Path(self.spend.gemini_tmp_path).expanduser())

    def pricing_cache_path_abs(self) -> str:
        return str(Path(self.pricing.cache_path).expanduser())

    def gemini_models(self) -> list[str]:
        """Return the configured model list, clamped to MAX_GEMINI_MODELS.

        Empty config falls back to DEFAULT_GEMINI_MODELS so the device
        always sees at least Pro + Flash."""
        src = self.gemini.models or DEFAULT_GEMINI_MODELS
        return list(src[:MAX_GEMINI_MODELS])


def _section(raw: dict, name: str, target: object) -> None:
    sect = raw.get(name) or {}
    for key, value in sect.items():
        if hasattr(target, key):
            setattr(target, key, value)


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
    _section(raw, "gemini", cfg.gemini)
    _section(raw, "usage", cfg.usage)
    _section(raw, "spend", cfg.spend)
    _section(raw, "pricing", cfg.pricing)
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
