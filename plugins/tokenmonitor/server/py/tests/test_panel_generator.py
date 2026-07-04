"""Custom-panel generator: config parsing + leader-scoped supervision.

Mirrors the Go internal/panelgen + internal/config panel tests: string-or-table
[panel.file], [panel.command] parsing, per-device target resolution, spawn on
start, restart-on-exit with backoff, and SIGTERM→SIGKILL teardown.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from tmon_mcp.config import Config, load
from tmon_mcp.panel_generator import PanelGenerator

LOG = logging.getLogger("test.panelgen")

AUTH = '[auth]\npsk_passphrase = "passphrase-1234"\n'


def _load(tmp_path: Path, body: str) -> Config:
    p = tmp_path / "tokenmonitor.toml"
    p.write_text(AUTH + body)
    return load(str(p))


# --- config parsing -------------------------------------------------------


def test_panel_file_bare_string(tmp_path):
    cfg = _load(tmp_path, '[panel]\nfile = "~/panel.json"\n')
    assert cfg.panel_file_default_abs().endswith("/panel.json")
    assert "~" not in cfg.panel_file_default_abs()
    assert cfg.panel_file_explicit_abs("dev1") == ""


def test_panel_file_table(tmp_path):
    cfg = _load(
        tmp_path,
        '[panel.file]\ndefault = "/panels/default.json"\n"tmon-ab12" = "/panels/ab12.json"\n',
    )
    assert cfg.panel_file_default_abs() == "/panels/default.json"
    assert cfg.panel_file_explicit_abs("tmon-ab12") == "/panels/ab12.json"
    assert cfg.panel_file_explicit_abs("other") == ""


def test_panel_command_table(tmp_path):
    cfg = _load(
        tmp_path,
        '[panel.command]\ndefault = ["python3", "~/bin/gen.py"]\n'
        '"tmon-ab12" = ["/usr/bin/special", "--fast"]\n',
    )
    cmds = cfg.panel_command_map()
    assert cmds["default"][0] == "python3"
    assert cmds["default"][1].endswith("/bin/gen.py") and "~" not in cmds["default"][1]
    assert cmds["tmon-ab12"] == ["/usr/bin/special", "--fast"]


def test_panel_unconfigured(tmp_path):
    cfg = _load(tmp_path, "")
    assert cfg.panel_command_map() == {}
    assert cfg.panel_file_default_abs() == ""
    assert cfg.panel_dir_abs() == ""


# --- target resolution ----------------------------------------------------


class _FakeReg:
    def __init__(self, ids):
        self._ids = ids

    def list_device_ids(self):
        return self._ids


def _gen(cfg, reg=None) -> PanelGenerator:
    return PanelGenerator(
        cfg,
        reg,
        LOG,
        reconcile_interval=0.05,
        term_grace=0.3,
        backoff_initial=0.02,
        backoff_max=0.04,
        backoff_reset=0.5,
    )


def _cfg_command(cmd: dict) -> Config:
    c = Config()
    c.panel.command = cmd
    return c


def test_targets_per_device_resolution():
    default = ["gen", "default"]
    special = ["gen", "special"]
    gen = _gen(_cfg_command({"default": default, "dev1": special}), _FakeReg(["dev1", "dev2"]))
    got = gen._targets()
    assert got["dev1"] == special
    assert got["dev2"] == default  # falls back to default
    assert "" not in got  # no global default when devices present


def test_targets_explicit_key_for_unregistered_device():
    special = ["gen", "special"]
    gen = _gen(_cfg_command({"tmon-ab12": special}), None)
    got = gen._targets()
    assert got["tmon-ab12"] == special
    assert "" not in got


def test_targets_global_default_when_no_devices():
    default = ["gen"]
    gen = _gen(_cfg_command({"default": default}), None)
    got = gen._targets()
    assert got == {"": default}


def test_target_path():
    c = Config()
    c.panel.file = {"default": "/panels/default.json", "dev1": "/panels/dev1.json"}
    c.panel.dir = "/panels/dir"
    gen = _gen(c)
    assert gen._target_path("dev1") == "/panels/dev1.json"
    assert gen._target_path("dev2") == "/panels/dir/dev2.json"
    assert gen._target_path("") == "/panels/dir/default.json"

    c2 = Config()
    c2.panel.file = {"default": "/panels/default.json"}
    assert _gen(c2)._target_path("dev9") == "/panels/default.json"


# --- supervision (async) --------------------------------------------------


async def _wait_for(timeout, cond):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        await asyncio.sleep(0.01)
    return cond()


async def test_supervisor_spawn_and_stop(tmp_path):
    f = tmp_path / "count"
    argv = ["sh", "-c", f"while true; do printf x >> '{f}'; sleep 0.02; done"]
    gen = _gen(_cfg_command({"default": argv}))
    gen.start()
    try:
        assert await _wait_for(2.0, lambda: f.exists() and f.stat().st_size > 0), "generator never wrote its file"
    finally:
        await gen.stop()
    settled = f.stat().st_size
    await asyncio.sleep(0.2)
    assert f.stat().st_size == settled, "child kept writing after stop — not killed"


async def test_supervisor_restarts_on_exit(tmp_path):
    f = tmp_path / "runs"
    argv = ["sh", "-c", f"printf x >> '{f}'"]  # one byte, then exit 0
    gen = _gen(_cfg_command({"default": argv}))
    gen.start()
    try:
        assert await _wait_for(2.0, lambda: f.exists() and f.stat().st_size >= 3), "expected >=3 restarts"
    finally:
        await gen.stop()


async def test_terminate_kills_stubborn_child(tmp_path):
    f = tmp_path / "alive"
    # Ignore SIGTERM; only SIGKILL (after term_grace) stops it.
    argv = ["sh", "-c", f"trap '' TERM; while true; do printf x >> '{f}'; sleep 0.02; done"]
    gen = _gen(_cfg_command({"default": argv}))
    gen.start()
    assert await _wait_for(2.0, lambda: f.exists() and f.stat().st_size > 0), "stubborn child never started"
    start = time.monotonic()
    await gen.stop()  # blocks until SIGKILL takes effect
    assert time.monotonic() - start >= gen.term_grace, "stop returned before SIGTERM grace — no SIGKILL escalation?"
    settled = f.stat().st_size
    await asyncio.sleep(0.2)
    assert f.stat().st_size == settled, "stubborn child survived stop"
