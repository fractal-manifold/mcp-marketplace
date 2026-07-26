"""SLIP + CRC-32/ISO-HDLC frame codec for USB serial provisioning.

A byte-for-byte port of tokenmonitor-mcp/internal/usbprov/frame.go, which is
itself a port of the firmware reference codec
(firmware/components/provision/src/provision_frame.c). The firmware DECODER is
the authority: test_provision_frames.py asserts this reproduces
compat/vectors/provision_frames.json. Do not "improve" the decode behaviour
without regenerating the vectors from firmware first.

See compat/PROVISION_WIRE.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Wire constants — must match firmware/components/provision/include/tmon_prov_frame.h.
MAGIC0 = 0x54  # 'T'
MAGIC1 = 0x4D  # 'M'
WIRE_VER = 1
HDR_LEN = 11
CRC_LEN = 4
PAYLOAD_MAX = 1024
FRAME_MAX = HDR_LEN + PAYLOAD_MAX + CRC_LEN

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD

# Message types — must match the TMON_MSG_* enum in the firmware.
MSG_HELLO = 1  # host → device, no nonce yet
MSG_HELLO_RESP = 2  # device → host, carries the session nonce (in the header)
MSG_SESSION_BEGIN = 3  # host → device, mute console
MSG_SESSION_ACK = 4
MSG_PROVISION = 5  # host → device, same JSON as POST /provision
MSG_RESULT = 6  # device → host
MSG_BYE = 7  # host → device, restore console


class PayloadTooLong(ValueError):
    """Raised by encode() when the payload exceeds PAYLOAD_MAX."""


@dataclass
class Frame:
    """A decoded protocol frame. payload is a fresh bytes owned by the caller."""

    ver: int = 0
    type: int = 0
    seq: int = 0
    nonce: int = 0
    payload: bytes = b""


def crc32(data: bytes) -> int:
    """CRC-32/ISO-HDLC (reflected poly 0xEDB88320, init/xorout 0xFFFFFFFF,
    refin/refout true) — the zlib/PNG CRC. Direct translation of
    tmon_prov_crc32(); the "123456789" check value is 0xCBF43926."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def encode(typ: int, seq: int, nonce: int, payload: bytes | None) -> bytes:
    """Build a complete on-wire frame (leading END, SLIP-escaped
    header+payload+CRC, trailing END). The leading END closes off whatever a
    previous writer left dangling so it is discarded as its own malformed frame
    rather than merging with this one."""
    payload = payload or b""
    if len(payload) > PAYLOAD_MAX:
        raise PayloadTooLong("usbprov: payload exceeds PAYLOAD_MAX")
    plen = len(payload)
    body = bytearray()
    body += bytes(
        (
            MAGIC0,
            MAGIC1,
            WIRE_VER,
            typ & 0xFF,
            seq & 0xFF,
            nonce & 0xFF,
            (nonce >> 8) & 0xFF,
            (nonce >> 16) & 0xFF,
            (nonce >> 24) & 0xFF,
            plen & 0xFF,
            (plen >> 8) & 0xFF,
        )
    )
    body += payload
    crc = crc32(bytes(body))
    body += bytes((crc & 0xFF, (crc >> 8) & 0xFF, (crc >> 16) & 0xFF, (crc >> 24) & 0xFF))

    out = bytearray()
    out.append(SLIP_END)
    for b in body:
        if b == SLIP_END:
            out += bytes((SLIP_ESC, SLIP_ESC_END))
        elif b == SLIP_ESC:
            out += bytes((SLIP_ESC, SLIP_ESC_ESC))
        else:
            out.append(b)
    out.append(SLIP_END)
    return bytes(out)


@dataclass
class Decoder:
    """Streaming SLIP+CRC32 decoder. Mirrors tmon_prov_decoder_t /
    tmon_prov_decode_byte exactly, including the resynchronisation behaviour
    that lets a real protocol frame be picked out of a stream also carrying
    console logs, panic output and ROM garbage."""

    _buf: bytearray = field(default_factory=bytearray)
    _escaping: bool = False
    _overflow: bool = False

    def decode_byte(self, b: int) -> Frame | None:
        """Feed one byte. Returns a decoded Frame only when a complete,
        CRC-valid frame of a supported version has just been terminated;
        everything else is consumed and discarded (returns None)."""
        if b == SLIP_END:
            # Frame boundary. Evaluate whatever accumulated, then reset —
            # unconditionally, so a bad candidate cannot poison the next one.
            f: Frame | None = None
            if not self._overflow and len(self._buf) > 0:
                f = self._validate()
            self._buf = bytearray()
            self._escaping = False
            self._overflow = False
            return f

        if self._escaping:
            self._escaping = False
            if b == SLIP_ESC_END:
                b = SLIP_END
            elif b == SLIP_ESC_ESC:
                b = SLIP_ESC
            else:
                # Invalid escape sequence: drop the candidate but keep scanning;
                # the next END re-syncs us.
                self._overflow = True
                return None
        elif b == SLIP_ESC:
            self._escaping = True
            return None

        if self._overflow:  # already doomed, wait for END
            return None
        if len(self._buf) >= FRAME_MAX:
            # Console text between two ENDs can be arbitrarily long. Mark and
            # wait for the boundary rather than truncating into a candidate that
            # might accidentally validate.
            self._overflow = True
            return None
        self._buf.append(b)
        return None

    def _validate(self) -> Frame | None:
        """Check an unescaped candidate and, if it is a real frame, unpack it.
        A mirror of the firmware validate(): magic, version, length-EQUALITY
        (not "fits"), then CRC."""
        buf = self._buf
        if len(buf) < HDR_LEN + CRC_LEN:
            return None
        if buf[0] != MAGIC0 or buf[1] != MAGIC1:
            return None
        if buf[2] != WIRE_VER:
            return None
        plen = buf[9] | (buf[10] << 8)
        if plen > PAYLOAD_MAX:
            return None
        # The declared length must account for EXACTLY the bytes received.
        if len(buf) != HDR_LEN + plen + CRC_LEN:
            return None
        crc_at = HDR_LEN + plen
        want = buf[crc_at] | (buf[crc_at + 1] << 8) | (buf[crc_at + 2] << 16) | (buf[crc_at + 3] << 24)
        if crc32(bytes(buf[:crc_at])) != want:
            return None
        return Frame(
            ver=buf[2],
            type=buf[3],
            seq=buf[4],
            nonce=buf[5] | (buf[6] << 8) | (buf[7] << 16) | (buf[8] << 24),
            payload=bytes(buf[HDR_LEN : HDR_LEN + plen]),
        )


def decode_all(data: bytes) -> list[Frame]:
    """Feed every byte of data through a fresh Decoder and return all frames it
    yields, in order."""
    dec = Decoder()
    out: list[Frame] = []
    for b in data:
        f = dec.decode_byte(b)
        if f is not None:
            out.append(f)
    return out
