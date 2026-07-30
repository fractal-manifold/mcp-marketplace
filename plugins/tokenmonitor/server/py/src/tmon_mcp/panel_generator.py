"""Leader-scoped supervisor for the user's custom-panel generator processes.

Mirror of the Go internal/panelgen package. It is started inside the leader's
lifecycle (and in --daemon mode, which is the leader by construction) and
stopped when this process loses the bound port or shuts down. A follower never
starts it, so each device's panel file has exactly one writer even when several
tokenmonitor-mcp processes run at once.

The commands come ONLY from the local, already-trusted tokenmonitor.toml
([panel.command], keyed by device id with a "default" fallback). They run as
the broker's user with a shell-free argv. The control plane / config_sync can
never populate them — that path writes device NVS, not the broker toml.

Each generator is supervised: if it exits (cleanly or by crashing) while we are
still the leader, it is respawned with exponential backoff. On teardown the
whole process group is sent SIGTERM, then SIGKILL after a grace period, so
nothing is orphaned.

A command that samples once and exits rather than looping can say so with
[panel.command_interval_s]: then it is re-run on that period instead, and
exiting is the normal case rather than a failure.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from contextlib import suppress
from pathlib import Path
from typing import NamedTuple


class _Target(NamedTuple):
    """One device's desired generator: what to run, and how to pace it.
    interval == 0 means "long-lived process" (the default contract); anything
    else means "one-shot, re-run on that period"."""

    argv: tuple[str, ...]
    interval: float


class _Child:
    """One supervised generator process (its target + a per-child stop event)."""

    def __init__(self, device_id: str, target: _Target) -> None:
        self.id = device_id
        self.target = target
        self.stop = asyncio.Event()
        self.task: asyncio.Task | None = None

    @property
    def argv(self) -> list[str]:
        return list(self.target.argv)

    @property
    def interval(self) -> float:
        return self.target.interval

    @property
    def label(self) -> str:
        return self.id or "default"


class PanelGenerator:
    def __init__(
        self,
        cfg,
        registry,
        logger: logging.Logger,
        *,
        reconcile_interval: float = 20.0,
        term_grace: float = 5.0,
        backoff_initial: float = 1.0,
        backoff_max: float = 30.0,
        backoff_reset: float = 60.0,
    ) -> None:
        self.cfg = cfg
        self.registry = registry
        self.logger = logger
        self.reconcile_interval = reconcile_interval
        self.term_grace = term_grace
        self.backoff_initial = backoff_initial
        self.backoff_max = backoff_max
        self.backoff_reset = backoff_reset
        self._children: dict[str, _Child] = {}
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    def enabled(self) -> bool:
        return bool(self.cfg.panel_command_map())

    def start(self) -> None:
        """Launch the reconcile loop. No-op when [panel.command] is empty."""
        if not self.enabled() or self._task is not None:
            return
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop the loop and every child, blocking until all have exited."""
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _run(self) -> None:
        try:
            await self._reconcile()
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.reconcile_interval)
                except asyncio.TimeoutError:
                    await self._reconcile()
        finally:
            await self._stop_all()

    async def _reconcile(self) -> None:
        if self._stop.is_set():
            return
        targets = self._targets()
        for device_id, child in list(self._children.items()):
            # The interval is part of the identity: re-pacing a generator has
            # to restart it, or the change would only land whenever the child
            # happened to die.
            target = targets.get(device_id)
            if target is None or target != child.target:
                await self._stop_child(child)
                del self._children[device_id]
        for device_id, target in targets.items():
            if device_id in self._children:
                continue
            child = _Child(device_id, target)
            child.task = asyncio.create_task(self._supervise(child))
            self._children[device_id] = child

    async def _stop_child(self, child: _Child) -> None:
        child.stop.set()
        if child.task is not None:
            with suppress(asyncio.CancelledError):
                await child.task

    async def _stop_all(self) -> None:
        for child in self._children.values():
            child.stop.set()
        for child in self._children.values():
            if child.task is not None:
                with suppress(asyncio.CancelledError):
                    await child.task
        self._children.clear()

    def _targets(self) -> dict[str, _Target]:
        """Desired {device_id: target}. Per device: its own command, else
        "default"; the interval resolves the same way, so a device can be paced
        differently from the default one. Every registered device is a
        candidate; explicit non-default keys run even for unregistered devices.
        With no devices at all, a lone "default" runs one global generator
        (empty id → feeds file.default)."""
        cmds = self.cfg.panel_command_map()
        if not cmds:
            return {}
        out: dict[str, _Target] = {}

        def make(device_id: str, argv: list[str]) -> _Target:
            return _Target(tuple(argv), self.cfg.panel_command_interval_for(device_id))

        ids: list[str] = []
        if self.registry is not None:
            try:
                ids = self.registry.list_device_ids()
            except Exception as e:  # noqa: BLE001
                self.logger.warning("panelgen: list devices: %s", e)
        for device_id in ids:
            argv = cmds.get(device_id) or cmds.get("default")
            if argv:
                out[device_id] = make(device_id, argv)
        for key, argv in cmds.items():
            if key == "default":
                continue
            if key not in out:
                out[key] = make(key, argv)
        if not out and "default" in cmds:
            out[""] = make("", cmds["default"])
        return out

    def _child_env(self, device_id: str) -> dict[str, str]:
        env = dict(os.environ)
        env["TMON_DEVICE_ID"] = device_id
        env["TMON_PANEL_PATH"] = self._target_path(device_id)
        return env

    def _target_path(self, device_id: str) -> str:
        """Where a generator for device_id should write — same place
        _resolve_panel_path serves from, computed without stat'ing (the file
        may not exist yet; the generator is what creates it)."""
        explicit = self.cfg.panel_file_explicit_abs(device_id)
        if explicit:
            return explicit
        d = self.cfg.panel_dir_abs()
        if d:
            if device_id:
                return str(Path(d) / f"{device_id}.json")
            return str(Path(d) / "default.json")
        return self.cfg.panel_file_default_abs()

    async def _supervise(self, child: _Child) -> None:
        """Run one generator until the child is stopped. Which of the two
        contracts applies is the target's interval:

        - 0 (the default): the command is expected to loop forever. Exiting is
          a failure, so it restarts with exponential backoff.
        - >0: the command is expected to sample once and exit, and we re-run it
          on that period. Exiting is the normal case, so there is no backoff —
          the interval is already the rate limit."""
        if child.interval > 0:
            await self._supervise_interval(child)
            return
        loop = asyncio.get_event_loop()
        backoff = self.backoff_initial
        while not child.stop.is_set():
            start = loop.time()
            started = await self._run_once(child)
            if child.stop.is_set():
                return
            if started:
                ran = loop.time() - start
                self.logger.info("panelgen[%s]: exited after %.1fs; restarting", child.label, ran)
                # A generator that stayed up a good while is not crash-looping.
                if ran >= self.backoff_reset:
                    backoff = self.backoff_initial
            if not await self._sleep_unless_stopped(child, backoff):
                return
            backoff = min(backoff * 2, self.backoff_max)

    async def _supervise_interval(self, child: _Child) -> None:
        """Re-run a one-shot generator every child.interval, measured
        start-to-start so the cadence does not drift with how long a run takes.

        Runs never overlap: a run that overruns its period simply delays the
        next one, which then starts immediately. We do not kill a slow
        generator — it may be mid-write, and half a document served to the
        device is worse than a late one. A run that fails waits the same
        interval as one that succeeds; a generator that cannot reach its source
        is expected to write its own "no data" document
        (docs/custom-panel.md), not to be retried harder."""
        loop = asyncio.get_event_loop()
        self.logger.info("panelgen[%s]: every %.0fs %s", child.label, child.interval, child.argv)
        while not child.stop.is_set():
            start = loop.time()
            started = await self._run_once(child)
            if child.stop.is_set():
                return
            if started:
                self.logger.info(
                    "panelgen[%s]: run finished in %.1fs", child.label, loop.time() - start
                )
            wait = child.interval - (loop.time() - start)
            if wait <= 0:
                self.logger.info(
                    "panelgen[%s]: run outlasted its %.0fs interval; starting the next one now",
                    child.label,
                    child.interval,
                )
                continue
            if not await self._sleep_unless_stopped(child, wait):
                return

    async def _run_once(self, child: _Child) -> bool:
        """Start the generator and wait for it to exit (or for a stop, which
        tears the process group down). False when it could not be started at
        all — already logged."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *child.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=self._child_env(child.id),
                start_new_session=True,  # own process group for group-kill
            )
        except Exception as e:  # noqa: BLE001
            self.logger.error("panelgen[%s]: %s", child.label, e)
            return False

        self.logger.info("panelgen[%s]: started pid=%d %s", child.label, proc.pid, child.argv)
        log_task = asyncio.create_task(self._pump_logs(child.label, proc.stdout))
        stop_wait = asyncio.create_task(child.stop.wait())
        exited = asyncio.create_task(proc.wait())
        done, _ = await asyncio.wait({stop_wait, exited}, return_when=asyncio.FIRST_COMPLETED)

        if stop_wait in done:
            await self._terminate(proc, exited)
        else:
            stop_wait.cancel()
            with suppress(asyncio.CancelledError):
                await stop_wait
        await log_task
        return True

    async def _terminate(self, proc, exited: asyncio.Task) -> None:
        """SIGTERM the child's process group, then SIGKILL after term_grace.

        The final SIGKILL runs even when the direct child exited promptly, to
        reap any grandchildren it spawned that ignored the SIGTERM. The process
        group stays alive as long as any member is, so killpg reaches them;
        once the group is empty it is a harmless ESRCH."""
        if proc.returncode is None:
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(asyncio.shield(exited), timeout=self.term_grace)
            except asyncio.TimeoutError:
                pass
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        with suppress(asyncio.CancelledError):
            await exited

    async def _sleep_unless_stopped(self, child: _Child, delay: float) -> bool:
        """Sleep `delay` unless the child is stopped first. Returns False if a
        stop was requested (caller should exit), True if the delay elapsed."""
        if delay <= 0:
            return not child.stop.is_set()
        try:
            await asyncio.wait_for(child.stop.wait(), timeout=delay)
            return False
        except asyncio.TimeoutError:
            return True

    async def _pump_logs(self, label: str, stream) -> None:
        if stream is None:
            return
        with suppress(Exception):
            while True:
                line = await stream.readline()
                if not line:
                    return
                self.logger.info("panelgen[%s]: %s", label, line.decode(errors="replace").rstrip())
