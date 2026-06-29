"""Tiny thread-safe ring buffer of log lines, also usable as a stream sink."""

from __future__ import annotations

import logging
import threading
from collections import deque


class Buffer:
    def __init__(self, maxlen: int = 200) -> None:
        if maxlen <= 0:
            maxlen = 200
        self._lines: deque[str] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._partial = ""

    def write_line(self, line: str) -> None:
        with self._lock:
            self._lines.append(line)

    def write_stream(self, chunk: str) -> None:
        with self._lock:
            self._partial += chunk
            while "\n" in self._partial:
                line, self._partial = self._partial.split("\n", 1)
                self._lines.append(line)

    def tail(self, n: int) -> list[str]:
        with self._lock:
            if n <= 0 or n >= len(self._lines):
                return list(self._lines)
            return list(self._lines)[-n:]

    def __len__(self) -> int:
        with self._lock:
            return len(self._lines)


class LogbufHandler(logging.Handler):
    """Logging handler that tees formatted records into a logbuf.Buffer."""

    def __init__(self, buf: Buffer) -> None:
        super().__init__()
        self._buf = buf

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._buf.write_line(self.format(record))
        except Exception:
            self.handleError(record)
