"""USB provisioning session state machine + framed transport.

Port of tokenmonitor-mcp/internal/usbprov/conn.go + session.go. Synchronous /
thread-based (the serial fd is blocking); the MCP handler runs it in a worker
thread. Cancellation is a threading.Event mirroring Go's context.

Critical invariants (compat/PROVISION_WIRE.md §3):
  - device emits HELLO_RESP only in reply to HELLO;
  - re-HELLO recovery is host-initiated and safe ONLY pre-SESSION_ACK;
  - post-PROVISION stall/cancel = OUTCOME_UNKNOWN, NEVER auto-retried
    (double-apply guard);
  - nonce+seq binding on SESSION_ACK/RESULT;
  - monotonic HELLO seq across the whole session;
  - expect_device_id re-checked every handshake;
  - proto_ver check.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .frame import (
    MSG_BYE,
    MSG_HELLO,
    MSG_HELLO_RESP,
    MSG_PROVISION,
    MSG_RESULT,
    MSG_SESSION_ACK,
    MSG_SESSION_BEGIN,
    Decoder,
    Frame,
    encode,
)

# Protocol version this host speaks (frame header ver + HELLO_RESP proto_ver).
WIRE_PROTO_VER = 1

# One recovery ⇒ at most two handshakes total; more would just prolong a
# genuinely dead port.
MAX_RESET_RECOVERIES = 1

# Sequence numbers for the one-shot exchange. The device echoes seq in its
# reply, and retransmission identity is the exact (seq, payload) pair.
SEQ_HELLO = 0
SEQ_SESSION_BEGIN = 1
SEQ_PROVISION = 2
SEQ_BYE = 3


class Transport(Protocol):
    """The byte transport a FrameConn drives. read(timeout) returns up to a
    chunk of bytes or b"" on timeout, and raises EOFError/OSError when the
    device is gone; close() is idempotent."""

    def read(self, timeout: float) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


# --- session errors -------------------------------------------------------


class DeviceMismatch(Exception):
    """expect_device_id did not match the HELLO_RESP — nothing was written."""


class Handshake(Exception):
    """The device never completed the handshake."""


class UnsupportedProto(Exception):
    """The device announced a proto_ver this host does not speak — nothing
    was written."""


class OutcomeUnknown(Exception):
    """PROVISION was transmitted but no RESULT came back even after in-session
    retransmits: the device MAY have applied it. Deliberately NOT auto-recovered
    — re-sending across a fresh HELLO would clear the device's retransmit cache
    and risk a double-apply / a second charged pairing attempt. The caller
    decides: reconnect and read device status, or re-run as a fresh user
    action."""


class SessionCancelled(Exception):
    """The session's cancel event fired (the lease was lost, or the caller
    aborted)."""


class SessionIO(Exception):
    """The transport reached EOF / errored mid-session."""


class _Timeout(Exception):
    """Internal: an await() deadline elapsed with no matching frame."""


# --- data types -----------------------------------------------------------


@dataclass
class Timeouts:
    """Bounds for each step. *_tries is the number of (re)transmissions of an
    idempotent request before the step is declared stalled. Seconds."""

    hello_resp: float = 0.0
    session_ack: float = 0.0
    result: float = 0.0
    hello_tries: int = 0
    session_tries: int = 0
    result_tries: int = 0

    def with_defaults(self) -> "Timeouts":
        d = default_timeouts()
        return Timeouts(
            hello_resp=self.hello_resp or d.hello_resp,
            session_ack=self.session_ack or d.session_ack,
            result=self.result or d.result,
            hello_tries=self.hello_tries or d.hello_tries,
            session_tries=self.session_tries or d.session_tries,
            result_tries=self.result_tries or d.result_tries,
        )


def default_timeouts() -> Timeouts:
    return Timeouts(
        hello_resp=1.5,
        session_ack=2.0,
        result=6.0,
        hello_tries=5,
        session_tries=3,
        result_tries=4,
    )


@dataclass
class DeviceInfo:
    """What a HELLO_RESP reveals. The session nonce is carried in the frame
    HEADER (fresh, non-zero), NOT in the JSON."""

    nonce: int = 0
    device_id: str = ""
    sku: str = ""
    fw: str = ""
    state: str = ""
    proto_ver: int = 0


@dataclass
class ProvisionOpts:
    """Drives a full provisioning session."""

    provision_json: bytes = b""
    # If non-empty, must equal the HELLO_RESP device_id or the session aborts
    # before any PROVISION write. Re-checked after every (re)handshake.
    expect_device_id: str = ""
    timeouts: Timeouts = field(default_factory=Timeouts)


@dataclass
class ProvisionResult:
    device: DeviceInfo
    result_json: bytes  # the device's RESULT payload verbatim (validated JSON)


# --- framed connection ----------------------------------------------------


_EOF = object()  # queue sentinel for terminal read error/EOF


class FrameConn:
    """Wraps a Transport with a background reader that feeds every byte through
    a resynchronising Decoder and delivers complete frames on a queue."""

    # Bounded like Go's buffered-8 frames channel: a stalled consumer applies
    # backpressure to the reader instead of letting an unbounded queue grow.
    _QUEUE_MAX = 8

    def __init__(self, transport: Transport) -> None:
        self._t = transport
        self._frames: "queue.Queue[object]" = queue.Queue(maxsize=self._QUEUE_MAX)
        self._err: str = ""
        self._stop = threading.Event()
        self._stop_once = threading.Lock()
        self._stopped = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True, name="usbprov-reader")
        self._reader.start()

    def _put(self, item: object) -> None:
        """Enqueue, blocking on a full queue until there's room or stop() fires
        (mirrors Go's `select { case frames<-f: case <-done: }`)."""
        while not self._stop.is_set():
            try:
                self._frames.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def _read_loop(self) -> None:
        dec = Decoder()
        while not self._stop.is_set():
            try:
                chunk = self._t.read(0.2)
            except (EOFError, OSError) as e:
                self._err = str(e)
                self._put(_EOF)
                return
            for b in chunk:
                f = dec.decode_byte(b)
                if f is not None:
                    self._put(f)

    def send(self, typ: int, seq: int, nonce: int, payload: bytes | None) -> None:
        """Encode and write one frame in full. Raises on a transport error."""
        self._t.write(encode(typ, seq, nonce, payload))

    def await_frame(
        self, timeout: float, pred: Callable[[Frame], bool], cancel: threading.Event | None
    ) -> Frame:
        """Return the next frame matching pred within `timeout`, or raise
        _Timeout / SessionCancelled / SessionIO. Non-matching frames are skipped
        within the same deadline."""
        deadline = time.monotonic() + timeout
        while True:
            if cancel is not None and cancel.is_set():
                raise SessionCancelled("usbprov: session cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Timeout()
            try:
                item = self._frames.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if item is _EOF:
                raise SessionIO(self._err or "usbprov: unexpected EOF")
            assert isinstance(item, Frame)
            if pred(item):
                return item

    def stop(self) -> None:
        """End the reader and close the transport. Idempotent."""
        with self._stop_once:
            if self._stopped:
                return
            self._stopped = True
        self._stop.set()
        try:
            self._t.close()
        except Exception:  # noqa: BLE001
            pass


# --- session driver -------------------------------------------------------


def run_provision(
    transport: Transport, opts: ProvisionOpts, cancel: threading.Event | None = None
) -> ProvisionResult:
    """Execute the full HELLO → SESSION_BEGIN → PROVISION → BYE exchange over
    transport (an already-opened, OS-exclusively-held serial fd). Tolerates
    console-log interleaving and a mid-session device reset (bounded by
    MAX_RESET_RECOVERIES). CONSUMES transport (closes it before returning)."""
    to = opts.timeouts.with_defaults()
    fc = FrameConn(transport)
    watch_stop = _start_cancel_watch(fc, cancel)
    try:
        # A HELLO seq counter monotonic across the WHOLE session (not reset per
        # handshake), so a delayed HELLO_RESP from an earlier attempt carries a
        # different seq and is ignored. uint8 wrap.
        seq_ref = [0]
        for _ in range(MAX_RESET_RECOVERIES + 1):
            dev = _do_handshake(fc, to, seq_ref, cancel)
            _accept_device(dev, opts)
            result, retry = _run_exchange(fc, dev, opts.provision_json, to, cancel)
            if retry:
                # Stalled BEFORE any pairing code was transmitted (no
                # SESSION_ACK). Safe to re-HELLO and retry.
                continue
            return ProvisionResult(device=dev, result_json=result)
        raise Handshake(
            f"usbprov: device did not complete the handshake: never got a SESSION_ACK "
            f"across {MAX_RESET_RECOVERIES + 1} re-HELLO attempts"
        )
    finally:
        if watch_stop is not None:
            watch_stop.set()
        fc.stop()


def identify(
    transport: Transport, to: Timeouts, cancel: threading.Event | None = None
) -> DeviceInfo:
    """Perform ONLY the HELLO handshake and return the device's self-report —
    the bounded identification write the scan's `probe` tier permits. NEVER
    opens a session or writes config. CONSUMES transport."""
    to = to.with_defaults()
    fc = FrameConn(transport)
    watch_stop = _start_cancel_watch(fc, cancel)
    try:
        seq_ref = [0]
        return _do_handshake(fc, to, seq_ref, cancel)
    finally:
        if watch_stop is not None:
            watch_stop.set()
        fc.stop()


def _start_cancel_watch(fc: FrameConn, cancel: threading.Event | None) -> threading.Event | None:
    """A blocked write can only be unblocked by closing the fd; watch cancel and
    stop() the conn when it fires. Returns a done-event to tear the watcher
    down. None when there is nothing to watch."""
    if cancel is None:
        return None
    done = threading.Event()

    def _watch() -> None:
        while not done.wait(0.05):
            if cancel.is_set():
                fc.stop()
                return

    threading.Thread(target=_watch, daemon=True, name="usbprov-cancel").start()
    return done


def _accept_device(dev: DeviceInfo, opts: ProvisionOpts) -> None:
    """Enforce the invariants that must hold before ANY configuration write, on
    both the initial handshake and every reset recovery."""
    if dev.proto_ver != WIRE_PROTO_VER:
        raise UnsupportedProto(
            f"usbprov: device speaks an unsupported protocol version: device announced "
            f"proto_ver {dev.proto_ver}, host speaks {WIRE_PROTO_VER}"
        )
    if opts.expect_device_id and dev.device_id != opts.expect_device_id:
        raise DeviceMismatch(
            f"usbprov: connected device_id does not match the requested device: "
            f"got {dev.device_id!r}, want {opts.expect_device_id!r}"
        )


def _do_handshake(
    fc: FrameConn, to: Timeouts, seq_ref: list[int], cancel: threading.Event | None
) -> DeviceInfo:
    """Send HELLO and wait for a structurally valid HELLO_RESP, retried. A
    malformed/junk HELLO_RESP is ignored within the timeout rather than treated
    as fatal, so one CRC-valid noise frame cannot abort discovery."""
    for _ in range(to.hello_tries):
        hs = seq_ref[0]
        seq_ref[0] = (seq_ref[0] + 1) & 0xFF
        try:
            fc.send(MSG_HELLO, hs, 0, None)
        except Exception as e:  # noqa: BLE001 — transport gone before any session
            raise SessionIO(f"usbprov: HELLO send failed: {e}") from e
        holder: dict[str, DeviceInfo] = {}

        def _pred(f: Frame) -> bool:
            d = _parse_hello_resp(f, hs)
            if d is not None:
                holder["dev"] = d
                return True
            return False

        try:
            fc.await_frame(to.hello_resp, _pred, cancel)
        except _Timeout:
            continue  # resend HELLO
        return holder["dev"]
    raise Handshake(
        f"usbprov: device did not complete the handshake: no valid HELLO_RESP after "
        f"{to.hello_tries} tries"
    )


def _run_exchange(
    fc: FrameConn,
    dev: DeviceInfo,
    provision_json: bytes,
    to: Timeouts,
    cancel: threading.Event | None,
) -> tuple[bytes | None, bool]:
    """SESSION_BEGIN → SESSION_ACK → PROVISION → RESULT → BYE. Replies are bound
    to the session by matching the header nonce AND the echoed seq.

    Returns:
      (result_json, False) — success.
      (None, True)         — stalled BEFORE PROVISION (no SESSION_ACK). No config
                             was transmitted, so the caller may safely re-HELLO.
    Raises OutcomeUnknown when PROVISION was transmitted but no RESULT arrived —
    the caller must NOT blindly re-apply.
    """
    nonce = dev.nonce

    # SESSION_BEGIN → SESSION_ACK, retransmitted (idempotent). Any non-timeout
    # error here propagates plainly: nothing sensitive is on the wire yet.
    acked = False
    for _ in range(to.session_tries):
        try:
            fc.send(MSG_SESSION_BEGIN, SEQ_SESSION_BEGIN, nonce, None)
        except Exception as e:  # noqa: BLE001 — no pairing code on the wire yet
            raise SessionIO(f"usbprov: SESSION_BEGIN send failed: {e}") from e
        try:
            fc.await_frame(
                to.session_ack,
                lambda f: f.type == MSG_SESSION_ACK and f.nonce == nonce and f.seq == SEQ_SESSION_BEGIN,
                cancel,
            )
        except _Timeout:
            continue
        acked = True
        break
    if not acked:
        return None, True

    # PROVISION → RESULT, resent with an identical (seq, payload). From the first
    # PROVISION send onward the pairing code is (or may be) on the wire, so EVERY
    # failure that is not a clean RESULT is classified outcome-unknown.
    for _ in range(to.result_tries):
        try:
            fc.send(MSG_PROVISION, SEQ_PROVISION, nonce, provision_json)
        except Exception as e:  # noqa: BLE001
            raise OutcomeUnknown(f"usbprov: PROVISION send failed: {e}") from e
        try:
            f = fc.await_frame(
                to.result,
                lambda f: f.type == MSG_RESULT
                and f.nonce == nonce
                and f.seq == SEQ_PROVISION
                and _json_valid(f.payload),
                cancel,
            )
        except _Timeout:
            continue  # resend PROVISION with identical (seq, payload)
        except (SessionCancelled, SessionIO, Exception) as e:
            raise OutcomeUnknown(f"usbprov: awaiting RESULT after PROVISION: {e}") from e
        # RESULT received. Best-effort BYE to restore the console; a lost BYE is
        # harmless and must NOT turn a committed provision into a failure.
        try:
            fc.send(MSG_BYE, SEQ_BYE, nonce, None)
        except Exception:  # noqa: BLE001
            pass
        return f.payload, False

    raise OutcomeUnknown(
        f"usbprov: provisioning outcome unknown — PROVISION was sent but no RESULT was "
        f"received (after {to.result_tries} PROVISION sends)"
    )


def _parse_hello_resp(f: Frame, want_seq: int) -> DeviceInfo | None:
    """Validate a frame as the HELLO_RESP for the HELLO that carried want_seq,
    and extract DeviceInfo. Returns None for anything to be ignored as noise."""
    if f.type != MSG_HELLO_RESP or f.seq != want_seq or f.nonce == 0 or len(f.payload) == 0:
        return None
    try:
        d = _strict_json_loads(f.payload)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(d, dict):
        return None
    device_id = d.get("device_id", "")
    if not device_id or not isinstance(device_id, str):
        return None
    # Type-strict like Go's json.Unmarshal into a typed struct: a field present
    # with the WRONG type makes Go reject the whole frame as noise (and keep
    # waiting within the timeout). Coercing instead — e.g. a numeric/string
    # proto_ver silently becoming 0 — could turn noise into a spurious
    # UnsupportedProto abort. So a wrong-typed field returns None here.
    sku = d.get("sku", "")
    fw = d.get("fw", "")
    state = d.get("state", "")
    if not all(isinstance(v, str) for v in (sku, fw, state)):
        return None
    proto_ver = d.get("proto_ver", 0)
    if isinstance(proto_ver, bool) or not isinstance(proto_ver, int):
        return None
    return DeviceInfo(
        nonce=f.nonce,
        device_id=device_id,
        sku=sku,
        fw=fw,
        state=state,
        proto_ver=proto_ver,
    )


def _reject_constant(_name: str):  # pragma: no cover - trivial
    """parse_constant hook: reject NaN/Infinity/-Infinity so _strict_json_loads
    matches Go's encoding/json (json.Valid / Unmarshal reject those tokens; the
    Python default silently accepts them)."""
    raise ValueError("usbprov: non-finite JSON constant")


def _strict_json_loads(payload: bytes):
    """json.loads with Go-parity strictness (no NaN/Infinity)."""
    return json.loads(payload, parse_constant=_reject_constant)


def _json_valid(payload: bytes) -> bool:
    try:
        _strict_json_loads(payload)
        return True
    except (ValueError, UnicodeDecodeError):
        return False
