"""tokenmonitor_set_wifi — mirror of Go's internal/mcp/wifi_test.go and JS's
test/mcp_wifi.test.js. The three runtimes must answer the same question the
same way, because the same MCP client talks to whichever one the launcher
picked."""

from __future__ import annotations

from pathlib import Path

from tmon_mcp.config import Config
from tmon_mcp.mcp import server as mcp_server
from tmon_mcp.registry.store import ConfigPayload, Registry

DEV = "02c46d94"


class _Deps:
    def __init__(self, registry=None):
        self.cfg = Config()
        self.registry = registry
        self.state = None
        self.logs = None
        self.version = "test"


def _registry(tmp_path: Path, known: list[dict] | None) -> Registry:
    reg = Registry(str(tmp_path))
    reg.register(DEV, ConfigPayload(broker_url="http://h:8765", psk_hex="ab" * 32))
    if known is not None:
        reg.report_settings(DEV, wifi_known=known)
    return reg


def _call(reg: Registry, **args) -> dict:
    return mcp_server._set_wifi(_Deps(reg), args)


# The headline case, and the reason this is a tool and not two more fields on
# set_device_pending: a network the device already remembers needs no password,
# because the device is holding it.
def test_remembered_network_needs_no_password(tmp_path: Path):
    reg = _registry(tmp_path, [
        {"ssid": "Office", "verified": True, "open": False},
        {"ssid": "HomeNet", "verified": True, "open": False},
    ])
    res = _call(reg, device_id=DEV, ssid="Office")
    assert "error" not in res, res

    dev = reg.load(DEV)
    assert dev.pending is not None
    assert dev.pending.payload.wifi_ssid == "Office"
    assert dev.pending.payload.wifi_pass == ""


# The other half: an unknown network must ASK, and the message has to be
# actionable — the caller needs to know a password is what is missing, and what
# the device does know.
def test_unknown_network_asks_for_password(tmp_path: Path):
    reg = _registry(tmp_path, [{"ssid": "HomeNet", "verified": True, "open": False}])
    res = _call(reg, device_id=DEV, ssid="j2ap")
    assert "needs_password=true" in res["error"]
    assert "HomeNet" in res["error"]
    assert reg.load(DEV).pending is None


def test_unknown_network_with_password_is_staged(tmp_path: Path):
    reg = _registry(tmp_path, [{"ssid": "HomeNet", "verified": True, "open": False}])
    res = _call(reg, device_id=DEV, ssid="j2ap", **{"pass": "j2apj2ap"})
    assert "error" not in res, res
    pending = reg.load(DEV).pending.payload
    assert pending.wifi_ssid == "j2ap"
    assert pending.wifi_pass == "j2apj2ap"


# An open network is remembered but can never be auto-joined, so offering a
# password-free switch to one would stage a change that silently does nothing
# on the device.
def test_remembered_open_network_is_refused(tmp_path: Path):
    reg = _registry(tmp_path, [{"ssid": "CafeWiFi", "verified": False, "open": True}])
    res = _call(reg, device_id=DEV, ssid="CafeWiFi")
    assert "OPEN" in res["error"]
    assert reg.load(DEV).pending is None


# Old firmware reports no list at all. That is NOT the same as "it does not know
# the network", and telling the user to supply a password they may not need
# would be guessing.
def test_no_reported_list_is_distinct_from_unknown(tmp_path: Path):
    reg = _registry(tmp_path, None)
    res = _call(reg, device_id=DEV, ssid="Office")
    assert "error" in res
    assert "needs_password=true" not in res["error"]
    assert "has not reported" in res["error"]


# A WiFi password has one job. Once the device has applied the config it holds
# the credential itself, so the registry must not keep accumulating every
# network password the fleet was ever handed.
def test_password_is_dropped_on_promote(tmp_path: Path):
    reg = _registry(tmp_path, [{"ssid": "HomeNet", "verified": True, "open": False}])
    _call(reg, device_id=DEV, ssid="j2ap", **{"pass": "j2apj2ap"})
    ver = reg.load(DEV).pending.payload.version

    assert reg.maybe_promote(DEV, ver, False) is True
    dev = reg.load(DEV)
    assert dev.active.payload.wifi_pass == ""
    assert dev.active.payload.wifi_ssid == "j2ap"
    # Observed state must not be collateral damage of a config promote.
    assert dev.active.wifi_known == [{"ssid": "HomeNet", "verified": True, "open": False}]


# SSIDs may legally contain leading/trailing spaces, and trimming would target a
# different network than the caller named.
def test_ssid_is_not_trimmed(tmp_path: Path):
    reg = _registry(tmp_path, [{"ssid": " Padded ", "verified": True, "open": False}])
    res = _call(reg, device_id=DEV, ssid=" Padded ")
    assert "error" not in res, res
    assert reg.load(DEV).pending.payload.wifi_ssid == " Padded "


def test_oversize_fields_are_refused(tmp_path: Path):
    reg = _registry(tmp_path, None)
    res = _call(reg, device_id=DEV, ssid="S" * 33, **{"pass": "x"})
    assert "802.11 limit" in res["error"]
    res = _call(reg, device_id=DEV, ssid="ok", **{"pass": "P" * 64})
    assert "WPA2 limit" in res["error"]


# The distinction between "reported none" and "never reported" only earns its
# keep if it survives the disk: every load() re-reads the TOML, so a collapse
# there would make the empty case unreachable in practice.
def test_empty_reported_list_survives_reload(tmp_path: Path):
    reg = _registry(tmp_path, [])
    dev = reg.load(DEV)
    assert dev.active.wifi_known == [], 'an empty reported list must not read back as "never reported"'
    res = _call(reg, device_id=DEV, ssid="Office")
    assert "needs_password=true" in res["error"]
