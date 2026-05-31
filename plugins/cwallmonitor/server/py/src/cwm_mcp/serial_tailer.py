"""USB-CDC serial tailer for ESP-IDF logs. Runs only when configured."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

from .logbuf import Buffer

log = logging.getLogger("cwm_mcp.serial")


class Tailer:
    """Best-effort, non-blocking line tail. Skipped silently if pyserial fails."""

    def __init__(self, device: str, buf: Buffer, baud: int = 115200) -> None:
        self.device = device
        self.buf = buf
        self.baud = baud
        self._connected = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def connected(self) -> bool:
        return self._connected

    def start(self) -> None:
        if not self.device:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="cwm-serial-tail")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        try:
            import serial  # type: ignore
        except Exception as e:
            log.info("serial: pyserial unavailable (%s); tailing disabled", e)
            return
        while not self._stop.is_set():
            try:
                with serial.Serial(self.device, self.baud, timeout=0.5) as ser:
                    self._connected = True
                    log.info("serial: opened %s", self.device)
                    pending = b""
                    while not self._stop.is_set():
                        try:
                            chunk = ser.read(256)
                        except Exception:
                            break
                        if not chunk:
                            continue
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            try:
                                self.buf.write_line(line.decode("utf-8", errors="replace").rstrip("\r"))
                            except Exception:
                                pass
            except Exception as e:
                log.info("serial: %s open failed: %s", self.device, e)
            self._connected = False
            self._stop.wait(2.0)
