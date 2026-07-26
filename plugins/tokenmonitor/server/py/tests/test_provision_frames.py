"""Validate the SLIP+CRC32 frame codec against the cross-runtime authority
compat/vectors/provision_frames.json (generated from the firmware codec, the
reference). Mirrors go/internal/usbprov/frame_test.go: CRC32, encode and — the
load-bearing one — decode (interleaved logs, split frame, bad CRC, lying
length, END-in-payload, back-to-back frames)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tmon_mcp.usbprov import frame as fr


def _find_compat(rel: str) -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


COMPAT = _find_compat("vectors/provision_frames.json")


def _doc() -> dict:
    return json.loads(COMPAT.read_text())


def test_crc32_match_vectors():
    doc = _doc()
    vecs = doc["crc32_vectors"]
    assert vecs, "no crc32 vectors"
    for v in vecs:
        got = fr.crc32(bytes.fromhex(v["data_hex"]))
        # crc_hex is printed big-endian ("%08x") in the generator.
        want = int(v["crc_hex"], 16)
        assert got == want, f"CRC32({v['name']}) = {got:08x}, want {want:08x}"


def test_encode_match_vectors():
    doc = _doc()
    vecs = doc["encode_vectors"]
    assert vecs, "no encode vectors"
    for v in vecs:
        got = fr.encode(v["type"], v["seq"], v["nonce"], bytes.fromhex(v["payload_hex"]))
        want = bytes.fromhex(v["frame_hex"])
        assert got == want, f"encode({v['name']}): got {got.hex()} want {want.hex()}"


def test_decode_match_vectors():
    doc = _doc()
    vecs = doc["decode_vectors"]
    assert vecs, "no decode vectors"
    for v in vecs:
        data = bytes.fromhex(v["input_hex"])
        got: list[fr.Frame] = []
        dec = fr.Decoder()

        def feed(bs: bytes) -> None:
            for b in bs:
                f = dec.decode_byte(b)
                if f is not None:
                    got.append(f)

        split_at = v.get("split_at")
        if split_at is not None:
            assert 0 <= split_at <= len(data), f"split_at {split_at} out of range"
            feed(data[:split_at])
            feed(data[split_at:])
        else:
            feed(data)

        exp = v["expected"]
        assert len(got) == len(exp), f"{v['name']}: frame count got {len(got)} want {len(exp)}"
        for i, e in enumerate(exp):
            assert got[i].type == e["type"] and got[i].seq == e["seq"] and got[i].nonce == e["nonce"], (
                f"{v['name']} frame {i} header mismatch"
            )
            assert got[i].payload == bytes.fromhex(e["payload_hex"]), f"{v['name']} frame {i} payload"


def test_encode_decode_round_trip():
    cases = [
        (fr.MSG_HELLO, 0, 0, b""),
        (fr.MSG_PROVISION, 42, 0x01020304, b'{"pairing_code":"123456"}'),
        (
            fr.MSG_PROVISION,
            1,
            0xA5A5A5A5,
            bytes((0x01, fr.SLIP_END, 0x02, fr.SLIP_ESC, 0x03, fr.SLIP_ESC_END, fr.SLIP_ESC_ESC)),
        ),
    ]
    for typ, seq, nonce, payload in cases:
        got = fr.decode_all(fr.encode(typ, seq, nonce, payload))
        assert len(got) == 1
        f = got[0]
        assert (f.type, f.seq, f.nonce, f.payload) == (typ, seq, nonce, payload)


def test_encode_payload_too_long():
    with pytest.raises(fr.PayloadTooLong):
        fr.encode(fr.MSG_PROVISION, 0, 0, b"\x00" * (fr.PAYLOAD_MAX + 1))
    # PAYLOAD_MAX itself encodes fine.
    fr.encode(fr.MSG_PROVISION, 0, 0, b"\x00" * fr.PAYLOAD_MAX)


def test_max_payload_round_trip():
    payload = bytes(i & 0xFF for i in range(fr.PAYLOAD_MAX))
    got = fr.decode_all(fr.encode(fr.MSG_PROVISION, 7, 0xCAFEBABE, payload))
    assert len(got) == 1 and got[0].payload == payload


def test_overflow_boundary_recovers_next_frame():
    good = fr.encode(fr.MSG_HELLO, 1, 0, b"")
    for n in (fr.FRAME_MAX, fr.FRAME_MAX + 1):
        dec = fr.Decoder()
        for _ in range(n):
            assert dec.decode_byte(0x41) is None
        assert dec.decode_byte(fr.SLIP_END) is None
        got = [f for b in good if (f := dec.decode_byte(b)) is not None]
        assert len(got) == 1 and got[0].type == fr.MSG_HELLO


def test_dangling_escape_before_end_recovers():
    good = fr.encode(fr.MSG_BYE, 3, 0x11223344, b"")
    dec = fr.Decoder()
    for b in (fr.MAGIC0, fr.MAGIC1, fr.WIRE_VER, fr.SLIP_ESC):
        assert dec.decode_byte(b) is None
    assert dec.decode_byte(fr.SLIP_END) is None
    got = [f for b in good if (f := dec.decode_byte(b)) is not None]
    assert len(got) == 1 and got[0].type == fr.MSG_BYE


def test_raw_esc_bytes_are_literal():
    payload = bytes((fr.SLIP_ESC_END, fr.SLIP_ESC_ESC, fr.SLIP_ESC_END, 0x00, fr.SLIP_ESC_ESC))
    got = fr.decode_all(fr.encode(fr.MSG_PROVISION, 2, 0x01020304, payload))
    assert len(got) == 1 and got[0].payload == payload


def test_payload_ownership_no_aliasing():
    f1 = fr.encode(fr.MSG_PROVISION, 1, 1, b"first-payload")
    f2 = fr.encode(fr.MSG_PROVISION, 2, 2, b"second-xxxxxx")
    got = fr.decode_all(f1 + f2)
    assert len(got) == 2
    assert got[0].payload == b"first-payload"
