"""USB-CDC serial tailer for ESP-IDF logs. Runs only in the leader.

Implements usbprov.SerialController (suspend_port / resume_port) and holds the
cross-runtime port flock while reading, so a follower that leases the port
(compat/PROVISION_WIRE.md §6) can open it: the lease manager calls suspend_port
→ the tailer closes its handle, releases the flock, and blocks until
resume_port. Mirrors go/internal/serial/tailer.go's suspend/resume gate.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from .logbuf import Buffer
from .usbprov.serial_port import PortBusy, acquire_port_lock, canonical_port

log = logging.getLogger("tmon_mcp.serial")


class Tailer:
    """Best-effort, non-blocking line tail. Skipped silently if pyserial fails.

    Also the leader's SerialController for the USB-provisioning lease: it holds
    the port flock while connected, and yields it (closing the handle) on
    suspend_port so a lessee's open_exclusive can succeed."""

    def __init__(self, device: str, buf: Buffer, baud: int = 115200) -> None:
        self.device = device
        self.buf = buf
        self.baud = baud
        self._connected = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Suspend/resume gate for the leader-mediated USB lease. The acquire-and
        # -open in the run loop re-checks `_suspended` under the SAME condition
        # so a suspend cannot slip in between the gate check and the open.
        self._cond = threading.Condition()
        self._suspended = False
        self._ser = None  # current pyserial handle, for interrupting a read
        self._lock_release: Optional[Callable[[], None]] = None
        self._holding = False  # True exactly while the fd + port lock are held

    def connected(self) -> bool:
        return self._connected

    def start(self) -> None:
        if not self.device:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="tmon-serial-tail")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._cond:
            # Wake the run loop out of a gate/suspend wait, and interrupt a read.
            if self._ser is not None:
                try:
                    self._ser.close()
                except Exception:  # noqa: BLE001
                    pass
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    # --- usbprov.SerialController ----------------------------------------

    def _canonical(self) -> Optional[str]:
        try:
            return canonical_port(self.device)
        except Exception:  # noqa: BLE001
            return None  # device gone → nothing to free

    def suspend_port(self, canonical: str) -> None:
        """Release canonical so a lessee can open it, blocking until the fd and
        port lock are freed. A no-op for a port this tailer does not own."""
        if not self.device:
            return
        mine = self._canonical()
        if mine is None or mine != canonical:
            return
        with self._cond:
            self._suspended = True
            if self._ser is not None:
                try:
                    self._ser.close()  # interrupt the current read
                except Exception:  # noqa: BLE001
                    pass
            while self._holding:  # wait until the fd + port lock are released
                self._cond.wait()

    def resume_port(self, canonical: str) -> None:
        """Let the tailer reacquire canonical after a lease ends. A no-op for a
        port it does not own."""
        if not self.device:
            return
        mine = self._canonical()
        if mine is None or mine != canonical:
            return
        with self._cond:
            self._suspended = False
            self._cond.notify_all()

    # --- reconnect loop ---------------------------------------------------

    def _run(self) -> None:
        try:
            import serial  # type: ignore
        except Exception as e:  # noqa: BLE001
            log.info("serial: pyserial unavailable (%s); tailing disabled", e)
            return
        while not self._stop.is_set():
            # Acquire the flock AND open the device AND commit _holding all under
            # _cond, gated on !_suspended — so the whole lock→open→commit is
            # atomic w.r.t. suspend_port. This is stronger than a post-open
            # re-check: suspend_port can never observe _holding==False while an
            # in-flight open still holds the flock, so a lessee's open_exclusive
            # is never transiently fenced out. Mirrors Go tailOnce, which takes
            # the lock + opens under the gate mutex. Failing closed is MANDATORY:
            # if the path can't be canonicalised or the lock can't be taken, back
            # off and retry rather than opening unfenced.
            ser = None
            release: Optional[Callable[[], None]] = None
            opened = False
            backoff = 0.0
            with self._cond:
                while self._suspended and not self._stop.is_set():
                    self._cond.wait()
                if self._stop.is_set():
                    return
                canonical = self._canonical()
                if canonical is None:
                    backoff = 2.0  # device not present yet; wait for it
                else:
                    try:
                        release = acquire_port_lock(canonical)
                    except PortBusy:
                        backoff = 0.5  # a lessee/foreign tool holds it; retry
                    except Exception as e:  # noqa: BLE001
                        # Lock dir unwritable, platform unsupported, etc. Do NOT
                        # open without the fence — back off and retry.
                        log.info("serial: lock %s failed: %s (retrying)", self.device, e)
                        backoff = 2.0
                    else:
                        try:
                            ser = serial.Serial(self.device, self.baud, timeout=0.5)
                        except Exception as e:  # noqa: BLE001
                            log.info("serial: %s open failed: %s", self.device, e)
                            try:
                                release()
                            except Exception:  # noqa: BLE001
                                pass
                            release = None
                            backoff = 2.0
                        else:
                            self._ser = ser
                            self._lock_release = release
                            self._holding = True
                            release = None  # ownership transferred to holder state
                            opened = True

            if not opened:
                self._stop.wait(backoff if backoff else 0.2)
                continue

            try:
                self._connected = True
                log.info("serial: opened %s", self.device)
                self._read_lines(ser)
            except Exception as e:  # noqa: BLE001
                log.info("serial: %s read error: %s", self.device, e)
            finally:
                # Teardown order matters for suspend_port's wait(_holding):
                # close the fd, RELEASE the flock, and only THEN clear _holding
                # and notify. A waiter must never wake while the lock is still
                # held, or its open_exclusive would race our flock. Mirrors Go's
                # tailer (fd close → flock release → clear holding → signal).
                try:
                    ser.close()
                except Exception:  # noqa: BLE001
                    pass
                with self._cond:
                    self._ser = None
                    lr = self._lock_release
                    self._lock_release = None
                # Release the fence BEFORE announcing we're no longer holding.
                if lr is not None:
                    try:
                        lr()
                    except Exception:  # noqa: BLE001
                        pass
                with self._cond:
                    self._holding = False
                    self._cond.notify_all()
                self._connected = False
            self._stop.wait(2.0)

    def _read_lines(self, ser) -> None:
        pending = b""
        while not self._stop.is_set():
            with self._cond:
                if self._suspended:
                    return
            try:
                chunk = ser.read(256)
            except Exception:  # noqa: BLE001
                return
            if not chunk:
                continue
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                try:
                    self.buf.write_line(line.decode("utf-8", errors="replace").rstrip("\r"))
                except Exception:  # noqa: BLE001
                    pass
