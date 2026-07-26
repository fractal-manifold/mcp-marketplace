"""OS-exclusive serial open + canonical port identity + cross-process flock.

Port of tokenmonitor-mcp/internal/usbprov/serial.go + serial_linux.go. The
lock-file identity is byte-identical to Go's (this is the cross-runtime
contract): SHA-256(canonical_path_utf8) rendered full-64-lowercase-hex, filename
`serial-<hex>.lock`, in `/run/user/<euid>/tokenmonitor/` when `/run/user/<euid>`
exists else `/tmp/tokenmonitor-<euid>/` (0700). Linux only; other platforms
raise OpenUnsupported like Go.

See compat/PROVISION_WIRE.md §6 "OS-exclusive serial open".
"""

from __future__ import annotations

import errno
import hashlib
import os
import select
import stat
import sys
import threading
from dataclasses import dataclass
from typing import Callable

_IS_LINUX = sys.platform.startswith("linux")

if _IS_LINUX:
    import fcntl
    import termios


class PortBusy(Exception):
    """Another cooperating process already holds the OS-exclusive lock on the
    port (a leader tailer, or a second provisioning session). Distinct from a
    raw open failure so callers can surface "in use" not "broken"."""


class OpenUnsupported(Exception):
    """OpenExclusive is not supported on this platform (macOS/Windows deferred,
    matching the enumerate stubs)."""


def canonical_port(path: str) -> str:
    """Resolve a serial-port path to the stable identity used as both the lease
    key and the OS-exclusive lock key. On POSIX it makes the path absolute and
    resolves symlinks, preserving case (device paths are case-sensitive); the
    device must exist."""
    abs_path = os.path.abspath(path)
    resolved = os.path.realpath(abs_path)
    # realpath does not error on a missing final component; require existence to
    # match Go's EvalSymlinks (which fails on a nonexistent path).
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"usbprov: resolve {path!r}: no such device")
    return resolved


def _lock_dir() -> str:
    """The fixed directory holding serial lock-files. Keys on a filesystem fact
    (does /run/user/<euid> exist?), NOT on $XDG_RUNTIME_DIR, so a daemon without
    that env var and an interactive follower that has it agree on one lock
    path."""
    euid = os.geteuid()
    run = f"/run/user/{euid}"
    if os.path.isdir(run):
        return os.path.join(run, "tokenmonitor")
    return f"/tmp/tokenmonitor-{euid}"


def _secure_lock_dir(d: str) -> None:
    """Create d (single level; its parent already exists) as 0700, or verify an
    existing one is a real directory owned by the effective user with no
    group/other access and not a symlink."""
    try:
        os.mkdir(d, 0o700)
        return
    except FileExistsError:
        pass
    except OSError as e:
        raise OSError(f"usbprov: create lock dir {d!r}: {e}") from e
    st = os.lstat(d)
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"usbprov: lock dir {d!r} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"usbprov: lock path {d!r} is not a directory")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise OSError(f"usbprov: lock dir {d!r} has unsafe permissions {stat.S_IMODE(st.st_mode):#o}")
    if st.st_uid != os.geteuid():
        raise OSError(f"usbprov: lock dir {d!r} is not owned by the current user")


class _PortLock:
    """A held cross-runtime flock on a canonical serial port lock-file."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._once = threading.Lock()
        self._released = False

    def release(self) -> None:
        with self._once:
            if self._released:
                return
            self._released = True
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._fd)
            except OSError:
                pass


def _acquire_lock_in(d: str, abs_path: str) -> _PortLock:
    """Take a non-blocking exclusive flock on a lock-file whose name is derived
    from the canonical device path. A held lock yields PortBusy rather than
    blocking. The lock-file identity is the cross-runtime contract."""
    _secure_lock_dir(d)
    digest = hashlib.sha256(abs_path.encode("utf-8")).hexdigest()  # full 64-hex
    lp = os.path.join(d, f"serial-{digest}.lock")
    # O_NOFOLLOW: refuse to open a symlink planted at the lock-file path.
    try:
        fd = os.open(lp, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise OSError(f"usbprov: open lock file: {e}") from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
            raise PortBusy(f"usbprov: serial port is held by another process: {abs_path}") from e
        raise OSError(f"usbprov: flock: {e}") from e
    return _PortLock(fd)


def acquire_port_lock(canonical: str) -> Callable[[], None]:
    """Take the cross-runtime exclusive lock for canonical (already
    canonicalised via canonical_port) — for owners that manage their own open()
    and termios, i.e. the firmware-log tailer. Same lock OpenExclusive uses.
    Raises PortBusy (retryable) if held. Returns a release callable to run on
    every exit path."""
    if not _IS_LINUX:
        raise OpenUnsupported("usbprov: port lock is not supported on this platform")
    lock = _acquire_lock_in(_lock_dir(), canonical)
    return lock.release


class SerialTransport:
    """A raw byte transport over an OS-exclusive serial fd. read() uses select
    with a short poll so the reader thread stays responsive to stop() without
    relying on close-unblocks-a-blocked-read semantics. Idempotent close."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._mu = threading.Lock()
        self._closed = False

    def read(self, timeout: float) -> bytes:
        """Return up to 512 bytes, or b"" on timeout. Raises EOFError on a closed
        device.

        The fd stays non-blocking (like Go's O_NONBLOCK + poller). select() (which
        may block up to `timeout`) runs WITHOUT the mutex, but the actual os.read
        runs UNDER it with a fresh _closed check — and because the fd is
        non-blocking, os.read returns immediately (data or EAGAIN), so holding the
        mutex across it can't stall close(). This makes read and close mutually
        exclusive: close() sets _closed before os.close(fd), so a concurrent
        close can never let os.read touch a closed (or fd-number-reused) fd."""
        with self._mu:
            if self._closed:
                raise EOFError("serial transport closed")
            fd = self._fd
        try:
            r, _, _ = select.select([fd], [], [], timeout)
        except OSError as e:
            raise EOFError(str(e)) from e
        if not r:
            return b""
        with self._mu:
            # Re-check under the lock: a close() may have fired during select().
            if self._closed:
                raise EOFError("serial transport closed")
            try:
                chunk = os.read(self._fd, 512)
            except BlockingIOError:
                return b""  # spurious readiness / EAGAIN on the non-blocking fd
            except OSError as e:
                raise EOFError(str(e)) from e
        if chunk == b"":
            raise EOFError("serial EOF")
        return chunk

    def write(self, data: bytes) -> None:
        """Write every byte. The fd is non-blocking; on a full tx buffer we wait
        for writability via select (without the mutex), then retry the os.write
        UNDER the mutex with a fresh _closed check — same close-race safety as
        read(): the non-blocking os.write returns immediately, so the lock never
        stalls close()."""
        off = 0
        while off < len(data):
            with self._mu:
                if self._closed:
                    raise EOFError("serial transport closed")
                try:
                    off += os.write(self._fd, data[off:])
                    continue
                except BlockingIOError:
                    fd = self._fd  # tx buffer full; wait writable below
                except OSError as e:
                    raise EOFError(str(e)) from e
            # Wait for writability outside the lock (may block briefly), then loop
            # to retry the write under the lock.
            try:
                select.select([], [fd], [], 0.2)
            except OSError as e:
                raise EOFError(str(e)) from e

    def close(self) -> None:
        with self._mu:
            if self._closed:
                return
            self._closed = True
            fd = self._fd
        try:
            os.close(fd)
        except OSError:
            pass


@dataclass
class Handle:
    """An OS-exclusive hold on a serial port. conn is the raw byte transport
    handed to run_provision, which CONSUMES and closes it. The filesystem lock
    that guarantees exclusivity lives on a SEPARATE fd owned by this Handle; the
    caller must release() it AFTER the session (which also best-effort closes
    conn)."""

    conn: SerialTransport
    _release: Callable[[], None]
    _once: threading.Lock = None  # type: ignore[assignment]
    _released: bool = False

    def __post_init__(self) -> None:
        self._once = threading.Lock()

    def release(self) -> None:
        """Drop the exclusive lock (and best-effort close conn). Idempotent."""
        with self._once:
            if self._released:
                return
            self._released = True
        try:
            self.conn.close()
        finally:
            self._release()


def open_exclusive(path: str) -> Handle:
    """Acquire an OS-exclusive hold on the serial port at path and open it in
    raw mode with DTR/RTS cleared. The flock is taken on a separate lock-file
    BEFORE the device is opened, closing the race where two cooperating runtimes
    both open the port in the leader-election gap. Raises PortBusy if held."""
    if not _IS_LINUX:
        raise OpenUnsupported("usbprov: exclusive serial open is not supported on this platform")
    canonical = canonical_port(path)
    lock = _acquire_lock_in(_lock_dir(), canonical)
    try:
        fd = _open_raw_serial(canonical)
    except Exception:
        lock.release()
        raise
    return Handle(conn=SerialTransport(fd), _release=lock.release)


def _open_raw_serial(path: str) -> int:
    """Open the tty raw (USB-CDC ignores baud), mark it exclusive-open
    (TIOCEXCL), set raw termios, and clear DTR/RTS."""
    # O_NOCTTY: don't adopt the tty as controlling terminal. O_NONBLOCK: open
    # returns without waiting on modem status (a CDC gadget never asserts DCD).
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        # TIOCEXCL: further open()s by cooperating processes get EBUSY. The
        # flock above is the real arbitration; this is defence in depth.
        fcntl.ioctl(fd, termios.TIOCEXCL, 0)
        _set_raw_serial(fd)
        # Best-effort: clear DTR and RTS so opening the port does not toggle the
        # esptool download-mode reset signal.
        _clear_dtr_rts(fd)
        # Keep the fd non-blocking (matching Go's O_NONBLOCK + runtime poller):
        # SerialTransport.read/write are select-gated and handle EAGAIN, and a
        # close() from another thread reliably unblocks them. Flipping to blocking
        # mode would let a concurrent close race a raw os.read/os.write and wedge.
    except Exception:
        os.close(fd)
        raise
    return fd


def _set_raw_serial(fd: int) -> None:
    """Put the tty in non-canonical, no-echo, 8N1 mode (cfmakeraw equivalent).
    Baud is left untouched because USB-CDC ignores it."""
    # [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
    iflag &= ~(
        termios.IGNBRK
        | termios.BRKINT
        | termios.PARMRK
        | termios.ISTRIP
        | termios.INLCR
        | termios.IGNCR
        | termios.ICRNL
        | termios.IXON
    )
    oflag &= ~termios.OPOST
    lflag &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
    cflag &= ~(termios.CSIZE | termios.PARENB)
    cflag |= termios.CS8 | termios.CREAD | termios.CLOCAL
    cc = list(cc)
    cc[termios.VMIN] = 1
    cc[termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])


def _clear_dtr_rts(fd: int) -> None:
    import struct

    try:
        TIOCMBIC = getattr(termios, "TIOCMBIC", 0x5417)
        TIOCM_DTR = getattr(termios, "TIOCM_DTR", 0x002)
        TIOCM_RTS = getattr(termios, "TIOCM_RTS", 0x004)
        fcntl.ioctl(fd, TIOCMBIC, struct.pack("I", TIOCM_DTR | TIOCM_RTS))
    except OSError:
        pass  # best-effort
