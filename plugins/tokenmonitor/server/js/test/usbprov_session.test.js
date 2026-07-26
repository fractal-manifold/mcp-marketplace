import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";

import {
  Decoder,
  encode,
  MSG_HELLO,
  MSG_HELLO_RESP,
  MSG_SESSION_BEGIN,
  MSG_SESSION_ACK,
  MSG_PROVISION,
  MSG_RESULT,
  MSG_BYE,
} from "../src/usbprov/frame.js";
import {
  runProvision,
  identify,
  HandshakeError,
  DeviceMismatchError,
  UnsupportedProtoError,
  OutcomeUnknownError,
} from "../src/usbprov/session.js";

// An in-memory duplex pair. Writes on one end deliver 'data' Buffers on the
// other (async, like a real serial port); closing either end emits 'close' on
// both (net.Pipe semantics: the peer's read returns EOF).
function pipePair() {
  const a = new EventEmitter();
  const b = new EventEmitter();
  a.setMaxListeners(0);
  b.setMaxListeners(0);
  let aClosed = false;
  let bClosed = false;
  a.write = (buf) => {
    if (!bClosed) queueMicrotask(() => b.emit("data", Buffer.from(buf)));
    return true;
  };
  b.write = (buf) => {
    if (!aClosed) queueMicrotask(() => a.emit("data", Buffer.from(buf)));
    return true;
  };
  a.close = () => {
    if (aClosed) return;
    aClosed = true;
    queueMicrotask(() => {
      a.emit("close");
      if (!bClosed) b.emit("close");
    });
  };
  b.close = () => {
    if (bClosed) return;
    bClosed = true;
    queueMicrotask(() => {
      b.emit("close");
      if (!aClosed) a.emit("close");
    });
  };
  return [a, b];
}

function describe(opts) {
  const pv = opts.protoVer ?? 1;
  return Buffer.from(
    `{"device_id":${JSON.stringify(opts.deviceID)},"sku":"S1","fw":"1.0.0","state":"BOOT_NEEDS_CONFIG","proto_ver":${pv}}`,
  );
}

// A faithful in-memory model of the firmware serial session
// (provision_serial_session.c), ported from Go's fakeDevice.
function attachFakeDevice(b, opts) {
  const dec = new Decoder();
  let nonce = 0; // 0 = no open session
  let nextNonce = opts.baseNonce;
  let open = false;
  let haveLast = false;
  let lastSeq;
  let lastType;
  let lastReq;
  let lastBody;
  let seenHello = false;
  let droppedResult = false;
  let didReset = false;
  const write = (typ, seq, n, body) => b.write(encode(typ, seq, n, body));

  b.on("data", (chunk) => {
    for (let i = 0; i < chunk.length; i++) {
      const f = dec.decodeByte(chunk[i]);
      if (!f) continue;

      if (f.type === MSG_HELLO) {
        if (opts.ignoreFirstHello && !seenHello) {
          seenHello = true;
          continue; // force a HELLO retransmit
        }
        seenHello = true;
        nonce = nextNonce;
        if (opts.baseNonce !== 0) {
          nextNonce = (nextNonce + 1) >>> 0;
          if (nextNonce === 0) nextNonce = 1;
        }
        open = false;
        haveLast = false;
        if (opts.injectConsole) b.write(Buffer.from("I (1234) wifi: connected\r\n\xc0junk\xc0", "latin1"));
        write(MSG_HELLO_RESP, f.seq, nonce, describe(opts));
        continue;
      }

      // Nonce gate: a DTR-rebooted device (nonce==0) or a stale-nonce frame is
      // dropped silently.
      if (nonce === 0 || f.nonce !== nonce) continue;

      // Retransmission replay of the cached RESULT.
      if (haveLast && f.seq === lastSeq && f.type === lastType && f.payload.equals(lastReq)) {
        write(MSG_RESULT, f.seq, nonce, lastBody);
        continue;
      }

      switch (f.type) {
        case MSG_SESSION_BEGIN:
          if (opts.resetOnSessionBegin && !didReset) {
            didReset = true;
            nonce = 0;
            open = false;
            haveLast = false;
            continue;
          }
          open = true;
          write(MSG_SESSION_ACK, f.seq, nonce, null);
          break;
        case MSG_PROVISION:
          if (!open) continue;
          if (opts.resetOnProvision && !didReset) {
            didReset = true;
            nonce = 0;
            open = false;
            haveLast = false;
            continue;
          }
          opts.gotProvision.v = true;
          if (opts.silentAfterProvision) continue;
          haveLast = true;
          lastSeq = f.seq;
          lastType = f.type;
          lastReq = Buffer.from(f.payload);
          lastBody = Buffer.from(opts.resultJSON);
          if (opts.injectStaleResult) {
            write(MSG_RESULT, f.seq, (nonce ^ 0xffff) >>> 0, Buffer.from('{"ok":false,"stale":true}'));
          }
          if (opts.dropFirstResult && !droppedResult) {
            droppedResult = true;
            continue; // cached; the host resends and gets the replay
          }
          write(MSG_RESULT, f.seq, nonce, opts.resultJSON);
          break;
        case MSG_BYE:
          nonce = 0;
          open = false;
          haveLast = false;
          break;
      }
    }
  });
}

const FAST = { helloResp: 150, sessionAck: 150, result: 150, helloTries: 6, sessionTries: 4, resultTries: 4 };

function mkDevice(opts) {
  const [host, dev] = pipePair();
  opts.gotProvision = opts.gotProvision || { v: false };
  attachFakeDevice(dev, opts);
  return { host, opts };
}

async function runWithFake(opts, provOpts = {}) {
  const { host } = mkDevice(opts);
  return runProvision(host, {
    provisionJSON: Buffer.from(provOpts.provisionJSON || `{"pairing_code":"123456"}`),
    expectDeviceID: provOpts.expectDeviceID,
    timeouts: FAST,
    signal: provOpts.signal,
  });
}

test("happy path", async () => {
  const res = await runWithFake(
    { deviceID: "03abcdef", baseNonce: 0xdeadbeef, resultJSON: Buffer.from(`{"ok":true,"device_id":"03abcdef","next":"rebooting"}`) },
    { provisionJSON: `{"pairing_code":"123456","wifi_ssid":"Home","wifi_pass":"pw"}` },
  );
  assert.equal(res.device.deviceID, "03abcdef");
  assert.equal(res.device.nonce, 0xdeadbeef);
  assert.equal(res.resultJSON.toString(), `{"ok":true,"device_id":"03abcdef","next":"rebooting"}`);
});

test("retransmit recovers a lost RESULT", async () => {
  const res = await runWithFake({
    deviceID: "aabbccdd",
    baseNonce: 0x11223344,
    resultJSON: Buffer.from(`{"ok":true}`),
    dropFirstResult: true,
  });
  assert.equal(res.resultJSON.toString(), `{"ok":true}`);
});

test("console interleaving does not break the handshake", async () => {
  const res = await runWithFake({
    deviceID: "03abcdef",
    baseNonce: 0xabcdef01,
    resultJSON: Buffer.from(`{"ok":true}`),
    injectConsole: true,
  });
  assert.equal(res.device.deviceID, "03abcdef");
});

test("ignored first HELLO recovered by retransmission", async () => {
  const res = await runWithFake({
    deviceID: "03abcdef",
    baseNonce: 0x55667788,
    resultJSON: Buffer.from(`{"ok":true}`),
    ignoreFirstHello: true,
  });
  assert.equal(res.device.deviceID, "03abcdef");
});

test("pre-PROVISION reset recovered by re-HELLO (adopts new nonce)", async () => {
  const res = await runWithFake({
    deviceID: "03abcdef",
    baseNonce: 0x01000000,
    resultJSON: Buffer.from(`{"ok":true}`),
    resetOnSessionBegin: true,
  });
  assert.equal(res.device.nonce, 0x01000001);
});

test("post-PROVISION reset → OutcomeUnknown, never auto-retried", async () => {
  await assert.rejects(
    () =>
      runWithFake({
        deviceID: "03abcdef",
        baseNonce: 0x02000000,
        resultJSON: Buffer.from(`{"ok":true}`),
        resetOnProvision: true,
      }),
    OutcomeUnknownError,
  );
});

test("stale-nonce RESULT ignored; only the bound RESULT counts", async () => {
  const res = await runWithFake({
    deviceID: "03abcdef",
    baseNonce: 0x22334455,
    resultJSON: Buffer.from(`{"ok":true,"real":true}`),
    injectStaleResult: true,
  });
  assert.equal(res.resultJSON.toString(), `{"ok":true,"real":true}`);
});

test("cancel after PROVISION is OutcomeUnknown (preserves cancel cause)", async () => {
  const opts = {
    deviceID: "03abcdef",
    baseNonce: 0x0badf00d,
    resultJSON: Buffer.from(`{"ok":true}`),
    silentAfterProvision: true,
    gotProvision: { v: false },
  };
  const { host } = mkDevice(opts);
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 60);
  await assert.rejects(
    () =>
      runProvision(host, {
        provisionJSON: Buffer.from(`{"pairing_code":"123456"}`),
        timeouts: { ...FAST, result: 5000 }, // long, so cancel (not timer) ends the wait
        signal: ac.signal,
      }),
    (err) => {
      assert.ok(err instanceof OutcomeUnknownError, "must be OutcomeUnknownError");
      assert.equal(err.canceled, true, "must preserve the cancellation cause");
      return true;
    },
  );
  assert.equal(opts.gotProvision.v, true, "device should have received the PROVISION");
});

test("device_id mismatch aborts before any write", async () => {
  const opts = {
    deviceID: "03abcdef",
    baseNonce: 0xdeadbeef,
    resultJSON: Buffer.from(`{"ok":true}`),
    gotProvision: { v: false },
  };
  const { host } = mkDevice(opts);
  await assert.rejects(
    () => runProvision(host, { provisionJSON: Buffer.from(`{"pairing_code":"123456"}`), expectDeviceID: "99999999", timeouts: FAST }),
    DeviceMismatchError,
  );
  assert.equal(opts.gotProvision.v, false);
});

test("unsupported proto_ver aborts before any write", async () => {
  const opts = {
    deviceID: "03abcdef",
    baseNonce: 0x0a0b0c0d,
    protoVer: 2,
    resultJSON: Buffer.from(`{"ok":true}`),
    gotProvision: { v: false },
  };
  const { host } = mkDevice(opts);
  await assert.rejects(
    () => runProvision(host, { provisionJSON: Buffer.from(`{"pairing_code":"123456"}`), timeouts: FAST }),
    UnsupportedProtoError,
  );
  assert.equal(opts.gotProvision.v, false);
});

test("zero session nonce fails the handshake", async () => {
  await assert.rejects(
    () => runWithFake({ deviceID: "03abcdef", baseNonce: 0, resultJSON: Buffer.from(`{"ok":true}`) }),
    HandshakeError,
  );
});

test("identify performs a HELLO-only handshake", async () => {
  const opts = { deviceID: "03abcdef", baseNonce: 0x12345678, resultJSON: Buffer.from(`{"ok":true}`), gotProvision: { v: false } };
  const { host } = mkDevice(opts);
  const dev = await identify(host, FAST);
  assert.equal(dev.deviceID, "03abcdef");
  assert.equal(dev.nonce, 0x12345678);
  assert.equal(dev.fw, "1.0.0");
  assert.equal(opts.gotProvision.v, false, "identify must not open a session");
});
