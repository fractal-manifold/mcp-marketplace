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

import pytest

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


def test_panel_command_interval_bare_number(tmp_path):
    cfg = _load(tmp_path, "[panel]\ncommand_interval_s = 900\n")
    assert cfg.panel_command_interval_for("anything") == 900


def test_panel_command_interval_table(tmp_path):
    cfg = _load(tmp_path, '[panel.command_interval_s]\ndefault = 900\n"tmon-ab12" = 60\n')
    assert cfg.panel_command_interval_for("tmon-ab12") == 60
    assert cfg.panel_command_interval_for("other") == 900


def test_panel_command_interval_absent_is_zero(tmp_path):
    cfg = _load(tmp_path, '[panel.command]\ndefault = ["gen"]\n')
    # 0 = unset = the long-lived-process contract every config had before.
    assert cfg.panel_command_interval_for("dev1") == 0


@pytest.mark.parametrize(
    "body",
    [
        "[panel]\ncommand_interval_s = -5\n",
        # 0.5 s truncated to 0 would mean "long-lived process" — the opposite
        # contract to what was asked for, so it is an error, not a rounding.
        "[panel]\ncommand_interval_s = 0.5\n",
        '[panel]\ncommand_interval_s = "900"\n',
    ],
)
def test_panel_command_interval_rejects_bad_values(tmp_path, body):
    """Must fail loudly, exactly as the Go broker does on the same toml."""
    with pytest.raises(ValueError):
        _load(tmp_path, body)


def test_panel_command_interval_accepts_integral_float(tmp_path):
    cfg = _load(tmp_path, "[panel]\ncommand_interval_s = 900.0\n")
    assert cfg.panel_command_interval_for("dev1") == 900


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
    assert got["dev1"].argv == tuple(special)
    assert got["dev2"].argv == tuple(default)  # falls back to default
    assert "" not in got  # no global default when devices present


def test_targets_explicit_key_for_unregistered_device():
    special = ["gen", "special"]
    gen = _gen(_cfg_command({"tmon-ab12": special}), None)
    got = gen._targets()
    assert got["tmon-ab12"].argv == tuple(special)
    assert "" not in got


def test_targets_global_default_when_no_devices():
    default = ["gen"]
    gen = _gen(_cfg_command({"default": default}), None)
    got = gen._targets()
    assert list(got) == [""]
    assert got[""].argv == tuple(default)
    assert got[""].interval == 0  # absent [panel.command_interval_s] = long-lived


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


async def test_interval_mode_reruns_one_shot(tmp_path):
    """The point of the feature: a command that samples once and exits gets
    re-run on its own period instead of being treated as a crash."""
    f = tmp_path / "runs"
    argv = ["sh", "-c", f"printf x >> '{f}'"]
    cfg = _cfg_command({"default": argv})
    cfg.panel.command_interval_s = 0.06  # sub-second so the test stays quick
    gen = _gen(cfg)
    gen.start()
    try:
        assert await _wait_for(2.0, lambda: f.exists() and f.stat().st_size >= 3), (
            "expected >=3 paced runs"
        )
    finally:
        await gen.stop()


async def test_interval_mode_does_not_overlap_runs(tmp_path):
    """A run that outlasts its period must delay the next one, not overlap it."""
    f = tmp_path / "runs"
    # 's' on entry, 'e' on exit: overlapping runs would show up as "ss"/"ee".
    argv = ["sh", "-c", f"printf s >> '{f}'; sleep 0.2; printf e >> '{f}'"]
    cfg = _cfg_command({"default": argv})
    cfg.panel.command_interval_s = 0.02
    gen = _gen(cfg)
    gen.start()
    try:
        # Assert the wait, or a generator that never ran would make the marker
        # loop below iterate over nothing and pass vacuously.
        assert await _wait_for(3.0, lambda: f.exists() and f.stat().st_size >= 4), (
            "expected at least two complete runs"
        )
    finally:
        await gen.stop()
    got = f.read_text()
    if got.endswith("s"):  # the run the stop interrupted
        got = got[:-1]
    assert all(got[i : i + 2] == "se" for i in range(0, len(got) - 1, 2)), f"runs overlapped: {got!r}"


async def test_interval_change_restarts_child(tmp_path):
    """Re-pacing has to restart the child, or the new interval would only land
    whenever the old one happened to die."""
    argv = ["sh", "-c", "sleep 5"]
    cfg = _cfg_command({"default": argv})
    cfg.panel.command_interval_s = 60
    gen = _gen(cfg)
    gen.start()
    try:
        assert await _wait_for(2.0, lambda: bool(gen._children)), "child never started"
        first = gen._children[""]
        cfg.panel.command_interval_s = 30
        # Wait for the REPLACEMENT, not merely for the old entry to go:
        # _reconcile deletes before it re-adds, so `is not first` is briefly
        # true with no child at all.
        assert await _wait_for(
            2.0, lambda: (c := gen._children.get("")) is not None and c is not first
        ), "reconcile kept the old child after the interval changed"
        assert gen._children[""].interval == 30
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
