"""Per-device TOML registry with flock(2) interprocess safety.

Wire-compatible with cwm-mcp/internal/registry/registry.go (BurntSushi/toml).
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import tomli_w
import tomllib

SCHEMA_VERSION = 2  # v2 adds serial_number, hw_sku, firmware_manifest_*, min_secure_version

_DEVICE_ID_RE = re.compile(r"^[0-9a-f]{8}$")


def valid_device_id(device_id: str) -> bool:
    return bool(_DEVICE_ID_RE.fullmatch(device_id))


class RegistryError(Exception):
    pass


class NotFound(RegistryError):
    pass


@dataclass
class ProviderSet:
    claude: bool = False
    codex: bool = False
    gemini: bool = False

    def to_dict(self) -> dict:
        return {"claude": self.claude, "codex": self.codex, "gemini": self.gemini}

    @classmethod
    def from_dict(cls, d: dict | None) -> "ProviderSet | None":
        if d is None:
            return None
        return cls(claude=bool(d.get("claude")), codex=bool(d.get("codex")), gemini=bool(d.get("gemini")))


@dataclass
class ConfigPayload:
    version: int = 0
    broker_url: str = ""
    psk_hex: str = ""
    city: str = ""
    br_day: int | None = None
    br_night: int | None = None
    vol: int | None = None
    providers: ProviderSet | None = None
    autorotate_enabled: bool | None = None
    autorotate_interval_s: int | None = None
    theme_mode: str = ""
    # Per-device override of the Gemini model list surfaced as
    # /usage/gemini slots. None = "no opinion" (use global default);
    # empty list = "clear the override". Max 3 entries.
    gemini_models: list[str] | None = None
    # OTA staging fields. The firmware's config_sync only arms the
    # on-device cwm_ota_* NVS keys when all three are present and
    # well-formed; empty strings mean "no firmware update" and travel
    # alongside any other config change.
    firmware_url: str = ""
    firmware_sha256: str = ""
    firmware_version: str = ""
    # Schema v2: signed manifest envelope. The firmware verifies the
    # Ed25519 signature over the canonical manifest BEFORE downloading
    # the .bin. Both fields travel inside the AES-CTR pending blob.
    firmware_manifest_b64: str = ""
    firmware_manifest_sig_b64: str = ""
    # Schema v2: anti-rollback floor mirrored from the device's
    # cwm_min_sv NVS key. Packed 8.8.16 = major.minor.patch.
    min_secure_version: int = 0

    def to_toml_dict(self) -> dict:
        d: dict = {"version": int(self.version)}
        if self.broker_url:
            d["broker_url"] = self.broker_url
        if self.psk_hex:
            d["psk_hex"] = self.psk_hex
        if self.city:
            d["city"] = self.city
        if self.br_day is not None:
            d["br_day"] = int(self.br_day)
        if self.br_night is not None:
            d["br_night"] = int(self.br_night)
        if self.vol is not None:
            d["vol"] = int(self.vol)
        if self.providers is not None:
            d["providers"] = self.providers.to_dict()
        if self.autorotate_enabled is not None:
            d["autorotate_enabled"] = bool(self.autorotate_enabled)
        if self.autorotate_interval_s is not None:
            d["autorotate_interval_s"] = int(self.autorotate_interval_s)
        if self.theme_mode:
            d["theme_mode"] = str(self.theme_mode)
        if self.gemini_models is not None and len(self.gemini_models) > 0:
            d["gemini_models"] = [str(m) for m in self.gemini_models]
        if self.firmware_url:
            d["firmware_url"] = self.firmware_url
        if self.firmware_sha256:
            d["firmware_sha256"] = self.firmware_sha256
        if self.firmware_version:
            d["firmware_version"] = self.firmware_version
        if self.firmware_manifest_b64:
            d["firmware_manifest_b64"] = self.firmware_manifest_b64
        if self.firmware_manifest_sig_b64:
            d["firmware_manifest_sig_b64"] = self.firmware_manifest_sig_b64
        if self.min_secure_version:
            d["min_secure_version"] = int(self.min_secure_version)
        return d

    @classmethod
    def from_toml_dict(cls, d: dict | None) -> "ConfigPayload":
        d = d or {}
        return cls(
            version=int(d.get("version", 0)),
            broker_url=str(d.get("broker_url", "")),
            psk_hex=str(d.get("psk_hex", "")),
            city=str(d.get("city", "")),
            br_day=int(d["br_day"]) if "br_day" in d else None,
            br_night=int(d["br_night"]) if "br_night" in d else None,
            vol=int(d["vol"]) if "vol" in d else None,
            providers=ProviderSet.from_dict(d.get("providers")),
            autorotate_enabled=d["autorotate_enabled"] if "autorotate_enabled" in d else None,
            autorotate_interval_s=int(d["autorotate_interval_s"]) if "autorotate_interval_s" in d else None,
            theme_mode=str(d.get("theme_mode", "")),
            gemini_models=[str(m) for m in d["gemini_models"]] if "gemini_models" in d else None,
            firmware_url=str(d.get("firmware_url", "")),
            firmware_sha256=str(d.get("firmware_sha256", "")),
            firmware_version=str(d.get("firmware_version", "")),
            firmware_manifest_b64=str(d.get("firmware_manifest_b64", "")),
            firmware_manifest_sig_b64=str(d.get("firmware_manifest_sig_b64", "")),
            min_secure_version=int(d.get("min_secure_version", 0)),
        )


def _iso_now() -> datetime:
    return datetime.now(tz=timezone.utc)


@dataclass
class Active:
    payload: ConfigPayload = field(default_factory=ConfigPayload)
    last_seen: datetime | None = None


@dataclass
class Pending:
    payload: ConfigPayload = field(default_factory=ConfigPayload)
    created_at: datetime = field(default_factory=_iso_now)


@dataclass
class Device:
    device_id: str
    # Schema v2 — factory identity reported by the device via
    # X-Cwm-Serial / X-Cwm-Sku headers on /sync. Empty until the device
    # is seen with a v2 firmware. NEVER authoritative — the eFuse
    # wins.
    serial_number: str = ""
    hw_sku: str = ""
    active: Active = field(default_factory=Active)
    pending: Pending | None = None

    def to_toml(self) -> str:
        doc: dict = {
            "schema_version": SCHEMA_VERSION,
            "device_id": self.device_id,
        }
        if self.serial_number:
            doc["serial_number"] = self.serial_number
        if self.hw_sku:
            doc["hw_sku"] = self.hw_sku
        doc["active"] = self.active.payload.to_toml_dict()
        if self.active.last_seen:
            doc["active"]["last_seen"] = self.active.last_seen
        if self.pending is not None:
            p = self.pending.payload.to_toml_dict()
            p["created_at"] = self.pending.created_at
            doc["pending"] = p
        return tomli_w.dumps(doc)


def _device_from_toml(text: str) -> Device:
    d = tomllib.loads(text)
    schema = int(d.get("schema_version", 0))
    # v0 = freshly-decoded zero value. v1 is the pre-serial schema —
    # migrated transparently: serial / sku stay empty until the next
    # /sync round populates them from headers. Next save bumps to v2.
    if schema not in (0, 1, SCHEMA_VERSION):
        raise RegistryError(f"registry: schema {schema}, expected {SCHEMA_VERSION}")
    device_id = str(d.get("device_id", ""))
    active_d = d.get("active") or {}
    active = Active(payload=ConfigPayload.from_toml_dict(active_d))
    if "last_seen" in active_d:
        ls = active_d["last_seen"]
        active.last_seen = ls if isinstance(ls, datetime) else _parse_iso(str(ls))
    pending = None
    if "pending" in d:
        p_d = d["pending"]
        pending = Pending(
            payload=ConfigPayload.from_toml_dict(p_d),
            created_at=(p_d["created_at"] if isinstance(p_d.get("created_at"), datetime) else _parse_iso(str(p_d.get("created_at", "")))),
        )
    return Device(
        device_id=device_id,
        serial_number=str(d.get("serial_number", "")),
        hw_sku=str(d.get("hw_sku", "")),
        active=active,
        pending=pending,
    )


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class Registry:
    """Per-device TOML store. Locking via flock on sibling .lock file."""

    def __init__(self, devices_dir: str) -> None:
        if not devices_dir:
            raise ValueError("registry: empty directory")
        self._dir = Path(devices_dir)
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._proc_lock = threading.Lock()

    @property
    def dir(self) -> str:
        return str(self._dir)

    def _path(self, device_id: str) -> Path:
        return self._dir / f"{device_id}.toml"

    class _FileLock:
        def __init__(self, path: Path) -> None:
            self._path = path
            self._fd: int | None = None

        def __enter__(self) -> "Registry._FileLock":
            self._fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR, 0o644)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            return self

        def __exit__(self, *_exc) -> None:
            if self._fd is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
                self._fd = None

    def _with_lock(self, device_id: str):
        lock_path = self._dir / f"{device_id}.toml.lock"
        return self._FileLock(lock_path)

    def load(self, device_id: str) -> Device:
        if not valid_device_id(device_id):
            raise RegistryError(f"registry: invalid device_id {device_id!r}")
        with self._with_lock(device_id):
            return self._load_locked(device_id)

    def _load_locked(self, device_id: str) -> Device:
        path = self._path(device_id)
        try:
            text = path.read_text()
        except FileNotFoundError as e:
            raise NotFound(f"registry: device {device_id} not found") from e
        return _device_from_toml(text)

    def _save_locked(self, dev: Device) -> None:
        if not valid_device_id(dev.device_id):
            raise RegistryError(f"registry: invalid device_id {dev.device_id!r}")
        path = self._path(dev.device_id)
        tmp = path.with_suffix(path.suffix + ".tmp")
        # 0o600: device PSKs live here in plaintext. See compat/SECURITY.md.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, dev.to_toml().encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def register(self, device_id: str, active: ConfigPayload) -> Device:
        if not valid_device_id(device_id):
            raise RegistryError(f"registry: invalid device_id {device_id!r}")
        if not active.psk_hex or not active.broker_url:
            raise RegistryError("registry: register requires psk_hex and broker_url")
        if len(active.psk_hex) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", active.psk_hex):
            raise RegistryError("registry: psk_hex must be 64 lowercase hex chars")
        active.psk_hex = active.psk_hex.lower()
        active.version = 1
        with self._with_lock(device_id):
            try:
                self._load_locked(device_id)
                raise RegistryError(f"registry: device {device_id} already exists")
            except NotFound:
                pass
            dev = Device(device_id=device_id, active=Active(payload=active))
            self._save_locked(dev)
            return dev

    def set_pending(self, device_id: str, update: ConfigPayload) -> Device:
        if not valid_device_id(device_id):
            raise RegistryError(f"registry: invalid device_id {device_id!r}")
        if update.psk_hex:
            if len(update.psk_hex) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", update.psk_hex):
                raise RegistryError("registry: psk_hex must be 64 lowercase hex chars")
            update.psk_hex = update.psk_hex.lower()
        with self._with_lock(device_id):
            dev = self._load_locked(device_id)
            base = dev.pending.payload if dev.pending else dev.active.payload
            merged = _merge_payload(base, update)
            next_version = dev.active.payload.version + 1
            if dev.pending and dev.pending.payload.version >= next_version:
                next_version = dev.pending.payload.version + 1
            merged.version = next_version
            if _payload_equivalent(merged, dev.active.payload):
                dev.pending = None
            else:
                dev.pending = Pending(payload=merged, created_at=_iso_now())
            self._save_locked(dev)
            return dev

    def maybe_promote(self, device_id: str, observed_version: int, used_pending_psk: bool) -> bool:
        if not valid_device_id(device_id):
            raise RegistryError(f"registry: invalid device_id {device_id!r}")
        with self._with_lock(device_id):
            try:
                dev = self._load_locked(device_id)
            except NotFound:
                return False
            if dev.pending is None or observed_version != dev.pending.payload.version:
                return False
            # Allow promotion without a pending-PSK signature only when
            # the rotation does not actually change the PSK. Otherwise
            # theme-only / city-only / brightness-only pending updates
            # would never clear from the registry.
            if not used_pending_psk and dev.pending.payload.psk_hex != dev.active.payload.psk_hex:
                return False
            dev.active = Active(payload=dev.pending.payload, last_seen=_iso_now())
            dev.pending = None
            self._save_locked(dev)
            return True

    def touch(self, device_id: str) -> None:
        if not valid_device_id(device_id):
            return
        with self._with_lock(device_id):
            try:
                dev = self._load_locked(device_id)
            except NotFound:
                return
            dev.active.last_seen = _iso_now()
            self._save_locked(dev)

    def set_serial(self, device_id: str, serial: str, sku: str) -> None:
        """Persist X-Cwm-Serial / X-Cwm-Sku reported by the device.

        Non-destructive: empty strings preserve existing values so a v2
        broker rendezvousing with a v1 firmware doesn't lose the
        serial it already knew. Unknown devices are silently ignored
        (the headers arrived alongside an authenticated request).
        """
        if not valid_device_id(device_id):
            return
        with self._with_lock(device_id):
            try:
                dev = self._load_locked(device_id)
            except NotFound:
                return
            changed = False
            if serial and serial != dev.serial_number:
                dev.serial_number = serial
                changed = True
            if sku and sku != dev.hw_sku:
                dev.hw_sku = sku
                changed = True
            if changed:
                self._save_locked(dev)

    def bump_min_sv(self, device_id: str, sv: int) -> None:
        """Monotonic anti-rollback floor. Never lowers."""
        if not valid_device_id(device_id):
            return
        with self._with_lock(device_id):
            try:
                dev = self._load_locked(device_id)
            except NotFound:
                return
            if sv <= dev.active.payload.min_secure_version:
                return
            dev.active.payload.min_secure_version = int(sv)
            self._save_locked(dev)

    def psks_for(self, device_id: str) -> tuple[bytes | None, bytes | None]:
        dev = self.load(device_id)
        active = bytes.fromhex(dev.active.payload.psk_hex) if dev.active.payload.psk_hex else None
        pending = None
        if (
            dev.pending is not None
            and dev.pending.payload.psk_hex
            and dev.pending.payload.psk_hex != dev.active.payload.psk_hex
        ):
            pending = bytes.fromhex(dev.pending.payload.psk_hex)
        return active, pending

    def list_device_ids(self) -> list[str]:
        """Return device_id slugs found on disk, sorted ascending.

        Cheaper than ``list`` for callers that only need IDs (e.g. the
        mDNS advertiser populating the TXT ``devs=`` record). Parse
        failures on individual files don't abort the scan.
        """
        out: list[str] = []
        for entry in sorted(self._dir.iterdir()):
            name = entry.name
            if not entry.is_file() or not name.endswith(".toml"):
                continue
            device_id = name[:-5]
            if not valid_device_id(device_id):
                continue
            out.append(device_id)
        return out

    def list(self) -> list[Device]:
        out: list[Device] = []
        for entry in sorted(self._dir.iterdir()):
            name = entry.name
            if not entry.is_file() or not name.endswith(".toml"):
                continue
            device_id = name[:-5]
            if not valid_device_id(device_id):
                continue
            try:
                out.append(self.load(device_id))
            except Exception:
                continue
        return out


def _merge_payload(base: ConfigPayload, upd: ConfigPayload) -> ConfigPayload:
    out = ConfigPayload(
        version=base.version,
        broker_url=upd.broker_url or base.broker_url,
        psk_hex=upd.psk_hex or base.psk_hex,
        city=upd.city or base.city,
        br_day=upd.br_day if upd.br_day is not None and upd.br_day != 0 else base.br_day,
        br_night=upd.br_night if upd.br_night is not None and upd.br_night != 0 else base.br_night,
        vol=upd.vol if upd.vol is not None else base.vol,
        providers=upd.providers if upd.providers is not None else base.providers,
        autorotate_enabled=upd.autorotate_enabled if upd.autorotate_enabled is not None else base.autorotate_enabled,
        autorotate_interval_s=upd.autorotate_interval_s if upd.autorotate_interval_s is not None else base.autorotate_interval_s,
        theme_mode=upd.theme_mode or base.theme_mode,
        gemini_models=list(upd.gemini_models) if upd.gemini_models is not None else base.gemini_models,
        firmware_url=upd.firmware_url or base.firmware_url,
        firmware_sha256=upd.firmware_sha256 or base.firmware_sha256,
        firmware_version=upd.firmware_version or base.firmware_version,
        firmware_manifest_b64=upd.firmware_manifest_b64 or base.firmware_manifest_b64,
        firmware_manifest_sig_b64=upd.firmware_manifest_sig_b64 or base.firmware_manifest_sig_b64,
        # min_secure_version is monotonic — never lowers.
        min_secure_version=max(upd.min_secure_version, base.min_secure_version),
    )
    return out


def _payload_equivalent(a: ConfigPayload, b: ConfigPayload) -> bool:
    if (
        a.broker_url != b.broker_url
        or a.psk_hex != b.psk_hex
        or a.city != b.city
        or a.br_day != b.br_day
        or a.br_night != b.br_night
        or a.vol != b.vol
    ):
        return False
    if (a.providers is None) != (b.providers is None):
        return False
    if a.providers is not None and (
        a.providers.claude != b.providers.claude or a.providers.codex != b.providers.codex or a.providers.gemini != b.providers.gemini
    ):
        return False
    if (a.autorotate_enabled is None) != (b.autorotate_enabled is None):
        return False
    if a.autorotate_enabled is not None and a.autorotate_enabled != b.autorotate_enabled:
        return False
    if (a.autorotate_interval_s is None) != (b.autorotate_interval_s is None):
        return False
    if a.autorotate_interval_s is not None and a.autorotate_interval_s != b.autorotate_interval_s:
        return False
    if a.theme_mode != b.theme_mode:
        return False
    am = a.gemini_models or []
    bm = b.gemini_models or []
    if am != bm:
        return False
    if (
        a.firmware_url != b.firmware_url
        or a.firmware_sha256 != b.firmware_sha256
        or a.firmware_version != b.firmware_version
        or a.firmware_manifest_b64 != b.firmware_manifest_b64
        or a.firmware_manifest_sig_b64 != b.firmware_manifest_sig_b64
        or a.min_secure_version != b.min_secure_version
    ):
        return False
    return True
