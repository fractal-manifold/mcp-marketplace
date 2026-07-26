// USB serial provisioning wire codec (compat/PROVISION_WIRE.md §2): SLIP
// framing + CRC-32/ISO-HDLC. A byte-for-byte port of the firmware reference
// codec (firmware/components/provision/src/provision_frame.c) and of the Go
// runtime (server/go/internal/usbprov/frame.go). The firmware DECODER is the
// authority: test/provision_frames.test.js asserts this reproduces
// compat/vectors/provision_frames.json. Do not "improve" decode behaviour here
// without regenerating the vectors from firmware first.

// Wire constants — must match tmon_prov_frame.h.
export const MAGIC0 = 0x54; // 'T'
export const MAGIC1 = 0x4d; // 'M'
export const WIRE_VER = 1;
export const HDR_LEN = 11;
export const CRC_LEN = 4;
export const PAYLOAD_MAX = 1024;
const FRAME_MAX = HDR_LEN + PAYLOAD_MAX + CRC_LEN;

const SLIP_END = 0xc0;
const SLIP_ESC = 0xdb;
const SLIP_ESC_END = 0xdc;
const SLIP_ESC_ESC = 0xdd;

// Message types — must match the TMON_MSG_* enum in the firmware.
export const MSG_HELLO = 1; // host → device, no nonce yet
export const MSG_HELLO_RESP = 2; // device → host, carries the session nonce (header)
export const MSG_SESSION_BEGIN = 3; // host → device, mute console
export const MSG_SESSION_ACK = 4;
export const MSG_PROVISION = 5; // host → device, same JSON as POST /provision
export const MSG_RESULT = 6; // device → host
export const MSG_BYE = 7; // host → device, restore console

export class PayloadTooLongError extends Error {
  constructor() {
    super("usbprov: payload exceeds PAYLOAD_MAX");
    this.name = "PayloadTooLongError";
  }
}

// crc32 computes CRC-32/ISO-HDLC (reflected poly 0xEDB88320, init/xorout
// 0xFFFFFFFF, refin/refout true) — the zlib/PNG CRC. Direct translation of
// tmon_prov_crc32(); the "123456789" check value is 0xCBF43926. Returns an
// unsigned 32-bit number.
export function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let k = 0; k < 8; k++) {
      if (crc & 1) crc = (crc >>> 1) ^ 0xedb88320;
      else crc >>>= 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// encode builds a complete on-wire frame (leading END, SLIP-escaped
// header+payload+CRC, trailing END) as a Buffer. The leading END closes off
// whatever a previous writer left dangling.
export function encode(type, seq, nonce, payload) {
  payload = payload ? Buffer.from(payload) : Buffer.alloc(0);
  if (payload.length > PAYLOAD_MAX) throw new PayloadTooLongError();
  const plen = payload.length;
  const n = nonce >>> 0;
  const body = Buffer.alloc(HDR_LEN + plen + CRC_LEN);
  body[0] = MAGIC0;
  body[1] = MAGIC1;
  body[2] = WIRE_VER;
  body[3] = type & 0xff;
  body[4] = seq & 0xff;
  body[5] = n & 0xff;
  body[6] = (n >>> 8) & 0xff;
  body[7] = (n >>> 16) & 0xff;
  body[8] = (n >>> 24) & 0xff;
  body[9] = plen & 0xff;
  body[10] = (plen >>> 8) & 0xff;
  payload.copy(body, HDR_LEN);
  const crc = crc32(body.subarray(0, HDR_LEN + plen));
  const crcAt = HDR_LEN + plen;
  body[crcAt] = crc & 0xff;
  body[crcAt + 1] = (crc >>> 8) & 0xff;
  body[crcAt + 2] = (crc >>> 16) & 0xff;
  body[crcAt + 3] = (crc >>> 24) & 0xff;

  const out = [SLIP_END];
  for (let i = 0; i < body.length; i++) {
    const b = body[i];
    if (b === SLIP_END) out.push(SLIP_ESC, SLIP_ESC_END);
    else if (b === SLIP_ESC) out.push(SLIP_ESC, SLIP_ESC_ESC);
    else out.push(b);
  }
  out.push(SLIP_END);
  return Buffer.from(out);
}

// Decoder is a streaming SLIP+CRC32 decoder. It mirrors
// tmon_prov_decode_byte exactly, including the resynchronisation behaviour that
// lets a real protocol frame be picked out of a stream also carrying console
// logs, panic output and ROM garbage.
export class Decoder {
  constructor() {
    this._buf = [];
    this._escaping = false;
    this._overflow = false;
  }

  // decodeByte feeds one byte. Returns a Frame object only when a complete,
  // CRC-valid frame of a supported version has just been terminated; otherwise
  // null (console text, truncated frames, bad CRC, a lying length, an unknown
  // version are all consumed and discarded).
  decodeByte(b) {
    if (b === SLIP_END) {
      // Frame boundary. Evaluate whatever accumulated, then reset —
      // unconditionally, so a bad candidate cannot poison the next one.
      let frame = null;
      if (!this._overflow && this._buf.length > 0) frame = this._validate();
      this._buf = [];
      this._escaping = false;
      this._overflow = false;
      return frame;
    }

    if (this._escaping) {
      this._escaping = false;
      if (b === SLIP_ESC_END) b = SLIP_END;
      else if (b === SLIP_ESC_ESC) b = SLIP_ESC;
      else {
        // Invalid escape sequence: drop the candidate but keep scanning; the
        // next END re-syncs us.
        this._overflow = true;
        return null;
      }
    } else if (b === SLIP_ESC) {
      this._escaping = true;
      return null;
    }

    if (this._overflow) return null; // already doomed, wait for END
    if (this._buf.length >= FRAME_MAX) {
      // Console text between two ENDs can be arbitrarily long. Mark and wait
      // for the boundary rather than truncating into a candidate that might
      // accidentally validate.
      this._overflow = true;
      return null;
    }
    this._buf.push(b);
    return null;
  }

  // _validate checks an unescaped candidate and, if it is a real frame,
  // unpacks it. A mirror of the firmware validate(): magic, version,
  // length-EQUALITY (not "fits"), then CRC.
  _validate() {
    const buf = this._buf;
    if (buf.length < HDR_LEN + CRC_LEN) return null;
    if (buf[0] !== MAGIC0 || buf[1] !== MAGIC1) return null;
    if (buf[2] !== WIRE_VER) return null;
    const plen = buf[9] | (buf[10] << 8);
    if (plen > PAYLOAD_MAX) return null;
    // The declared length must account for EXACTLY the bytes received.
    if (buf.length !== HDR_LEN + plen + CRC_LEN) return null;
    const crcAt = HDR_LEN + plen;
    const want =
      (buf[crcAt] | (buf[crcAt + 1] << 8) | (buf[crcAt + 2] << 16) | (buf[crcAt + 3] << 24)) >>> 0;
    const b = Buffer.from(buf);
    if (crc32(b.subarray(0, crcAt)) !== want) return null;
    return {
      ver: buf[2],
      type: buf[3],
      seq: buf[4],
      nonce: (buf[5] | (buf[6] << 8) | (buf[7] << 16) | (buf[8] << 24)) >>> 0,
      payload: Buffer.from(buf.slice(HDR_LEN, HDR_LEN + plen)),
    };
  }
}

// decodeAll feeds every byte of data through a fresh Decoder and returns all
// frames it yields, in order.
export function decodeAll(data) {
  const d = new Decoder();
  const frames = [];
  for (let i = 0; i < data.length; i++) {
    const f = d.decodeByte(data[i]);
    if (f) frames.push(f);
  }
  return frames;
}
