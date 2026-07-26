import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  crc32,
  encode,
  Decoder,
  decodeAll,
  PayloadTooLongError,
  PAYLOAD_MAX,
  MSG_HELLO,
  MSG_HELLO_RESP,
  MSG_PROVISION,
  MSG_BYE,
  MSG_SESSION_ACK,
} from "../src/usbprov/frame.js";

const here = dirname(fileURLToPath(import.meta.url));

// Walk up past the partial server/compat/ runtime slice to the authoritative
// monorepo compat/ — the byte-level provision-frame vectors are generated from
// the firmware codec and are the cross-runtime authority.
function findCompat(rel) {
  let dir = here;
  for (let i = 0; i < 12; i++) {
    const c = join(dir, "compat", rel);
    if (existsSync(c)) return c;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

const vecPath = findCompat("vectors/provision_frames.json");
const skip = vecPath ? false : "compat/vectors/provision_frames.json unavailable (standalone checkout)";
const doc = vecPath ? JSON.parse(readFileSync(vecPath, "utf8")) : { crc32_vectors: [], encode_vectors: [], decode_vectors: [] };

function hex(s) {
  return Buffer.from(s, "hex");
}

test("CRC32 matches vectors", { skip }, () => {
  assert.ok(doc.crc32_vectors.length > 0, "no crc32 vectors");
  for (const v of doc.crc32_vectors) {
    const got = crc32(hex(v.data_hex));
    // crc_hex is printed big-endian ("%08x") in the generator.
    const want = parseInt(v.crc_hex, 16) >>> 0;
    assert.equal(got, want, `CRC32(${v.data_hex}) name=${v.name}`);
  }
});

test("encode matches vectors byte-for-byte", { skip }, () => {
  assert.ok(doc.encode_vectors.length > 0, "no encode vectors");
  for (const v of doc.encode_vectors) {
    const got = encode(v.type, v.seq, v.nonce, hex(v.payload_hex));
    assert.equal(got.toString("hex"), v.frame_hex, `encode ${v.name}`);
  }
});

// The load-bearing one: the firmware decoder is the reference, so decode_vectors
// records exactly what it yields for the hard cases (interleaved console logs,
// garbage mid-candidate, back-to-back frames, bad CRC → nothing, END/ESC in
// payload, a lying length that still CRCs → nothing). The JS decoder must agree.
test("decode matches vectors (incl. split_at streaming)", { skip }, () => {
  assert.ok(doc.decode_vectors.length > 0, "no decode vectors");
  for (const v of doc.decode_vectors) {
    const input = hex(v.input_hex);
    const got = [];
    const d = new Decoder();
    const feed = (bs) => {
      for (let i = 0; i < bs.length; i++) {
        const f = d.decodeByte(bs[i]);
        if (f) got.push(f);
      }
    };
    if (v.split_at != null) {
      feed(input.subarray(0, v.split_at));
      feed(input.subarray(v.split_at));
    } else {
      feed(input);
    }
    assert.equal(got.length, v.expected.length, `frame count for ${v.name}`);
    for (let i = 0; i < v.expected.length; i++) {
      const exp = v.expected[i];
      assert.equal(got[i].type, exp.type, `${v.name} frame ${i} type`);
      assert.equal(got[i].seq, exp.seq, `${v.name} frame ${i} seq`);
      assert.equal(got[i].nonce, exp.nonce >>> 0, `${v.name} frame ${i} nonce`);
      assert.equal(got[i].payload.toString("hex"), exp.payload_hex, `${v.name} frame ${i} payload`);
    }
  }
});

test("encode→decode round-trip, incl. END/ESC payload bytes", () => {
  const cases = [
    { typ: MSG_HELLO, seq: 0, nonce: 0, payload: Buffer.alloc(0) },
    { typ: MSG_PROVISION, seq: 42, nonce: 0x01020304, payload: Buffer.from(`{"pairing_code":"123456"}`) },
    { typ: MSG_PROVISION, seq: 1, nonce: 0xa5a5a5a5, payload: Buffer.from([0x01, 0xc0, 0x02, 0xdb, 0x03, 0xdc, 0xdd]) },
  ];
  for (const c of cases) {
    const frames = decodeAll(encode(c.typ, c.seq, c.nonce, c.payload));
    assert.equal(frames.length, 1);
    const f = frames[0];
    assert.equal(f.type, c.typ);
    assert.equal(f.seq, c.seq);
    assert.equal(f.nonce, c.nonce >>> 0);
    assert.deepEqual(f.payload, c.payload);
  }
});

test("payload length cap enforced on encode", () => {
  assert.throws(() => encode(MSG_PROVISION, 0, 0, Buffer.alloc(PAYLOAD_MAX + 1)), PayloadTooLongError);
  assert.doesNotThrow(() => encode(MSG_PROVISION, 0, 0, Buffer.alloc(PAYLOAD_MAX)));
});

test("full 1024-byte payload round-trips (escaping at scale)", () => {
  const payload = Buffer.alloc(PAYLOAD_MAX);
  for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff; // includes 0xC0/0xDB
  const frames = decodeAll(encode(MSG_PROVISION, 7, 0xcafebabe, payload));
  assert.equal(frames.length, 1);
  assert.deepEqual(frames[0].payload, payload);
});

test("overflow candidate resets cleanly and next frame decodes", () => {
  const FRAME_MAX = 11 + PAYLOAD_MAX + 4;
  const good = encode(MSG_HELLO, 1, 0, null);
  for (const n of [FRAME_MAX, FRAME_MAX + 1]) {
    const d = new Decoder();
    for (let i = 0; i < n; i++) assert.equal(d.decodeByte(0x41), null);
    assert.equal(d.decodeByte(0xc0), null, "oversize candidate must not validate");
    const got = [];
    for (const b of good) {
      const f = d.decodeByte(b);
      if (f) got.push(f);
    }
    assert.equal(got.length, 1);
    assert.equal(got[0].type, MSG_HELLO);
  }
});

test("dangling escape before END drops candidate, recovers", () => {
  const good = encode(MSG_BYE, 3, 0x11223344, null);
  const d = new Decoder();
  for (const b of [0x54, 0x4d, 1, 0xdb]) assert.equal(d.decodeByte(b), null);
  assert.equal(d.decodeByte(0xc0), null);
  const got = [];
  for (const b of good) {
    const f = d.decodeByte(b);
    if (f) got.push(f);
  }
  assert.equal(got.length, 1);
  assert.equal(got[0].type, MSG_BYE);
});

test("payloads do not alias across frames", () => {
  const f1 = encode(MSG_PROVISION, 1, 1, Buffer.from("first-payload"));
  const f2 = encode(MSG_PROVISION, 2, 2, Buffer.from("second-xxxxxx"));
  const frames = decodeAll(Buffer.concat([f1, f2]));
  assert.equal(frames.length, 2);
  assert.equal(frames[0].payload.toString(), "first-payload");
});

test("HELLO_RESP round-trips after empty candidates", () => {
  const d = new Decoder();
  for (let i = 0; i < 4; i++) assert.equal(d.decodeByte(0xc0), null);
  const good = encode(MSG_HELLO_RESP, 0, 0x12345678, Buffer.from(`{"proto_ver":1}`));
  const got = [];
  for (const b of good) {
    const f = d.decodeByte(b);
    if (f) got.push(f);
  }
  assert.equal(got.length, 1);
  assert.equal(got[0].nonce, 0x12345678);
  assert.equal(got[0].type, MSG_SESSION_ACK - 2); // HELLO_RESP == 2
});
