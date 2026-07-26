"""Session state-machine parity with go/internal/usbprov/session_test.go, driven
by an in-memory fake device. Covers: happy path, proto_ver / device_id gates
(nothing written), the re-HELLO handshake recovery, the retransmission cache
(applied once), and the OUTCOME_UNKNOWN double-apply guard (never auto-retried
across a fresh HELLO)."""

from __future__ import annotations

import json
import threading

import pytest

from tmon_mcp.usbprov import session as ses
from tmon_mcp.usbprov.frame import (
    MSG_BYE,
    MSG_HELLO,
    MSG_HELLO_RESP,
    MSG_PROVISION,
    MSG_RESULT,
    MSG_SESSION_ACK,
    MSG_SESSION_BEGIN,
    Decoder,
    encode,
)


class FakeDevice:
    """A minimal device that speaks the wire protocol over an in-memory pipe.
    All host→device bytes are fed through write(); device→host bytes surface via
    read()."""

    def __init__(
        self,
        *,
        device_id: str = "03abcdef",
        proto_ver: int = 1,
        nonce: int = 0x12345678,
        send_ack: bool = True,
        result_mode: str = "normal",  # normal | drop_all | drop_first
        drop_hello_resp: int = 0,
    ) -> None:
        self.device_id = device_id
        self.proto_ver = proto_ver
        self.nonce = nonce
        self.send_ack = send_ack
        self.result_mode = result_mode
        self.drop_hello_resp = drop_hello_resp

        self.hello_count = 0
        self.provision_recv = 0
        self.apply_count = 0
        self._result_cache: dict[int, bytes] = {}  # seq → RESULT frame bytes

        self._dec = Decoder()
        self._to_host = bytearray()
        self._cond = threading.Condition()
        self._closed = False

    # transport surface -----------------------------------------------------

    def write(self, data: bytes) -> None:
        for b in data:
            f = self._dec.decode_byte(b)
            if f is not None:
                self._handle(f)

    def read(self, timeout: float) -> bytes:
        with self._cond:
            if not self._to_host and not self._closed:
                self._cond.wait(timeout)
            if self._closed and not self._to_host:
                raise EOFError("closed")
            chunk = bytes(self._to_host[:512])
            del self._to_host[:512]
            return chunk

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    # internals -------------------------------------------------------------

    def _emit(self, data: bytes) -> None:
        with self._cond:
            self._to_host += data
            self._cond.notify_all()

    def _handle(self, f) -> None:
        if f.type == MSG_HELLO:
            self.hello_count += 1
            # A fresh HELLO abandons any half-finished session (new nonce would
            # be minted on a real device); the cache is per (nonce,seq) so we
            # reset it to model a fresh session.
            self._result_cache.clear()
            if self.drop_hello_resp > 0:
                self.drop_hello_resp -= 1
                return
            desc = json.dumps(
                {
                    "device_id": self.device_id,
                    "sku": "S1",
                    "fw": "1.2.3",
                    "state": "BOOT_NEEDS_CONFIG",
                    "proto_ver": self.proto_ver,
                }
            ).encode("utf-8")
            self._emit(encode(MSG_HELLO_RESP, f.seq, self.nonce, desc))
        elif f.type == MSG_SESSION_BEGIN:
            if f.nonce == self.nonce and self.send_ack:
                self._emit(encode(MSG_SESSION_ACK, f.seq, self.nonce, None))
        elif f.type == MSG_PROVISION:
            if f.nonce != self.nonce:
                return
            self.provision_recv += 1
            cached = self._result_cache.get(f.seq)
            if cached is not None:
                # Retransmission: replay cache, do NOT re-apply. drop_all models a
                # device whose RESULT never survives the wire, so even the replay
                # is lost — the host stays in outcome-unknown.
                if self.result_mode != "drop_all":
                    self._emit(cached)
                return
            # First time this seq is seen → apply exactly once, then cache the
            # RESULT (the device's retransmit cache).
            self.apply_count += 1
            result = json.dumps({"ok": True, "next": "reboot"}).encode("utf-8")
            frame = encode(MSG_RESULT, f.seq, self.nonce, result)
            self._result_cache[f.seq] = frame
            if self.result_mode in ("drop_all", "drop_first"):
                return  # first RESULT lost on the wire
            self._emit(frame)
        elif f.type == MSG_BYE:
            pass


def _fast_timeouts(**kw) -> ses.Timeouts:
    base = dict(hello_resp=0.3, session_ack=0.3, result=0.3, hello_tries=3, session_tries=2, result_tries=2)
    base.update(kw)
    return ses.Timeouts(**base)


def test_happy_path():
    dev = FakeDevice()
    res = ses.run_provision(
        dev,
        ses.ProvisionOpts(provision_json=b'{"pairing_code":"123456"}', timeouts=_fast_timeouts()),
    )
    assert res.device.device_id == "03abcdef"
    assert json.loads(res.result_json) == {"ok": True, "next": "reboot"}
    assert dev.apply_count == 1


def test_proto_ver_mismatch_writes_nothing():
    dev = FakeDevice(proto_ver=2)
    with pytest.raises(ses.UnsupportedProto):
        ses.run_provision(dev, ses.ProvisionOpts(provision_json=b"{}", timeouts=_fast_timeouts()))
    assert dev.provision_recv == 0 and dev.apply_count == 0


def test_device_id_mismatch_writes_nothing():
    dev = FakeDevice(device_id="03abcdef")
    with pytest.raises(ses.DeviceMismatch):
        ses.run_provision(
            dev,
            ses.ProvisionOpts(
                provision_json=b"{}", expect_device_id="deadbeef", timeouts=_fast_timeouts()
            ),
        )
    assert dev.provision_recv == 0 and dev.apply_count == 0


def test_hello_retry_recovers():
    # Device drops the first HELLO_RESP; the host retries within hello_tries.
    dev = FakeDevice(drop_hello_resp=1)
    res = ses.run_provision(dev, ses.ProvisionOpts(provision_json=b"{}", timeouts=_fast_timeouts()))
    assert res.device.device_id == "03abcdef"
    assert dev.hello_count >= 2


def test_no_session_ack_raises_handshake():
    # Device answers HELLO but never SESSION_ACK → re-HELLO recovery, then give up.
    dev = FakeDevice(send_ack=False)
    with pytest.raises(ses.Handshake):
        ses.run_provision(dev, ses.ProvisionOpts(provision_json=b"{}", timeouts=_fast_timeouts()))
    # No pairing code was ever transmitted.
    assert dev.provision_recv == 0 and dev.apply_count == 0


def test_outcome_unknown_not_auto_retried():
    # Device applies but the RESULT is always lost → OUTCOME_UNKNOWN. The host
    # must NOT re-drive a fresh HELLO (double-apply guard): apply_count stays 1
    # and there is exactly one handshake.
    dev = FakeDevice(result_mode="drop_all")
    with pytest.raises(ses.OutcomeUnknown):
        ses.run_provision(dev, ses.ProvisionOpts(provision_json=b"{}", timeouts=_fast_timeouts()))
    assert dev.apply_count == 1
    assert dev.hello_count == 1  # never re-HELLO'd after the pairing code went out
    assert dev.provision_recv == 2  # result_tries in-session retransmits, same seq


def test_retransmit_applies_once():
    # First RESULT is dropped; the in-session resend replays the cache. The
    # device applies exactly once.
    dev = FakeDevice(result_mode="drop_first")
    res = ses.run_provision(dev, ses.ProvisionOpts(provision_json=b"{}", timeouts=_fast_timeouts()))
    assert json.loads(res.result_json)["ok"] is True
    assert dev.apply_count == 1 and dev.provision_recv == 2


def test_identify_only_hello():
    dev = FakeDevice()
    info = ses.identify(dev, _fast_timeouts())
    assert info.device_id == "03abcdef" and info.proto_ver == 1
    assert dev.provision_recv == 0 and dev.apply_count == 0


# --- HELLO_RESP type-strictness (M1: match Go's typed json.Unmarshal) --------


def _hello_resp_frame(nonce: int, seq: int, payload: dict) -> object:
    from tmon_mcp.usbprov.frame import Frame

    return Frame(
        ver=1,
        type=MSG_HELLO_RESP,
        seq=seq,
        nonce=nonce,
        payload=json.dumps(payload).encode("utf-8"),
    )


def test_hello_resp_well_typed_parses():
    f = _hello_resp_frame(0x1111, 0, {"device_id": "03abcdef", "proto_ver": 1, "sku": "S1"})
    d = ses._parse_hello_resp(f, 0)
    assert d is not None and d.device_id == "03abcdef" and d.proto_ver == 1 and d.sku == "S1"


def test_hello_resp_wrong_typed_proto_ver_is_noise_not_abort():
    # A string proto_ver must be IGNORED as noise (return None), NOT coerced to 0
    # (which would spuriously trip UnsupportedProto). Matches Go rejecting the
    # frame on a type mismatch and continuing to wait.
    f = _hello_resp_frame(0x1111, 0, {"device_id": "03abcdef", "proto_ver": "1"})
    assert ses._parse_hello_resp(f, 0) is None


def test_hello_resp_wrong_typed_sku_is_noise():
    f = _hello_resp_frame(0x1111, 0, {"device_id": "03abcdef", "proto_ver": 1, "sku": 5})
    assert ses._parse_hello_resp(f, 0) is None


def test_hello_resp_bool_proto_ver_is_noise():
    # bool is an int subclass in Python; Go would reject `true` for an int field.
    f = _hello_resp_frame(0x1111, 0, {"device_id": "03abcdef", "proto_ver": True})
    assert ses._parse_hello_resp(f, 0) is None
