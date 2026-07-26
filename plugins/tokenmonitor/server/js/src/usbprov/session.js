// USB provisioning session state machine (compat/PROVISION_WIRE.md §3).
// Mirrors go/internal/usbprov/session.go + conn.go, including the EXACT
// recovery model:
//   - the device emits HELLO_RESP only in reply to HELLO;
//   - re-HELLO recovery is safe ONLY pre-SESSION_ACK (no pairing code on the
//     wire yet);
//   - post-PROVISION stall/cancel = OUTCOME_UNKNOWN and is NEVER auto-retried
//     (double-apply guard);
//   - replies are bound to the session by header nonce AND echoed seq;
//   - the HELLO seq is monotonic across the WHOLE session;
//   - ExpectDeviceID and proto_ver are re-checked on every handshake.

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
} from "./frame.js";

// wireProtoVer is the protocol version this host speaks.
const WIRE_PROTO_VER = 1;

// maxResetRecoveries bounds how many times a stalled exchange is recovered by
// re-saying HELLO. One recovery ⇒ at most two handshakes total.
const MAX_RESET_RECOVERIES = 1;

// Sequence numbers for the one-shot provisioning exchange. A resent PROVISION
// MUST reuse SEQ_PROVISION with an identical payload (retransmission identity).
const SEQ_SESSION_BEGIN = 1;
const SEQ_PROVISION = 2;
const SEQ_BYE = 3;

// Sentinel used internally for an await() deadline elapsing with no match.
const errTimeout = Symbol("usbprov: await timed out");

export class HandshakeError extends Error {
  constructor(msg) {
    super(`usbprov: device did not complete the handshake: ${msg}`);
    this.name = "HandshakeError";
  }
}
export class DeviceMismatchError extends Error {
  constructor(msg) {
    super(`usbprov: connected device_id does not match the requested device: ${msg}`);
    this.name = "DeviceMismatchError";
  }
}
export class UnsupportedProtoError extends Error {
  constructor(msg) {
    super(`usbprov: device speaks an unsupported protocol version: ${msg}`);
    this.name = "UnsupportedProtoError";
  }
}
// OutcomeUnknownError: PROVISION was transmitted but no RESULT came back even
// after in-session retransmits. The device MAY have applied it. This is
// deliberately NOT auto-recovered — the caller decides. `.canceled` is true
// when the cause was a session cancellation (lease lost / abort).
export class OutcomeUnknownError extends Error {
  constructor(msg, cause) {
    super(
      `usbprov: provisioning outcome unknown — PROVISION was sent but no RESULT was received; the device may have applied it${msg ? " " + msg : ""}`,
    );
    this.name = "OutcomeUnknownError";
    this.cause = cause;
    this.canceled = cause instanceof CanceledError;
  }
}
export class CanceledError extends Error {
  constructor() {
    super("usbprov: session canceled");
    this.name = "CanceledError";
  }
}
class EOFError extends Error {
  constructor() {
    super("usbprov: unexpected end of stream");
    this.name = "EOFError";
  }
}

// defaultTimeouts (milliseconds + try counts).
export function defaultTimeouts() {
  return {
    helloResp: 1500,
    sessionAck: 2000,
    result: 6000,
    helloTries: 5,
    sessionTries: 3,
    resultTries: 4,
  };
}

function withDefaults(t) {
  const d = defaultTimeouts();
  t = t || {};
  return {
    helloResp: t.helloResp || d.helloResp,
    sessionAck: t.sessionAck || d.sessionAck,
    result: t.result || d.result,
    helloTries: t.helloTries || d.helloTries,
    sessionTries: t.sessionTries || d.sessionTries,
    resultTries: t.resultTries || d.resultTries,
  };
}

// FrameConn wraps a serial transport (a Duplex stream: on('data'/'close'/
// 'error'), write(buf), close()) with a resynchronising Decoder and delivers
// complete frames to a single sequential awaiter. Non-matching frames that
// arrive while an awaiter is active are discarded (mirroring Go's await which
// consumes and skips them); frames arriving between awaits are queued.
class FrameConn {
  constructor(transport) {
    this.transport = transport;
    this.decoder = new Decoder();
    this.queue = [];
    this.waiter = null;
    this.closed = false;
    this._stopped = false;
    this._onData = (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      for (let i = 0; i < buf.length; i++) {
        const f = this.decoder.decodeByte(buf[i]);
        if (f) this._deliver(f);
      }
    };
    this._onClose = () => this._terminate();
    transport.on("data", this._onData);
    transport.on("close", this._onClose);
    transport.on("error", this._onClose);
  }

  _deliver(frame) {
    if (this.waiter) {
      if (this.waiter.pred(frame)) {
        const w = this.waiter;
        this.waiter = null;
        this._clearWaiter(w);
        w.resolve(frame);
      }
      // else: discard, mirroring Go's await consuming a non-matching frame.
      return;
    }
    this.queue.push(frame);
  }

  _terminate() {
    if (this.closed) return;
    this.closed = true;
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      this._clearWaiter(w);
      w.reject(new EOFError());
    }
  }

  _clearWaiter(w) {
    if (w.timer) clearTimeout(w.timer);
    if (w.onAbort && w.signal) w.signal.removeEventListener("abort", w.onAbort);
  }

  // send encodes and writes one frame. Throws if the transport write throws.
  send(type, seq, nonce, payload) {
    const frame = encode(type, seq, nonce, payload);
    this.transport.write(frame);
  }

  // await returns the next frame matching pred within timeoutMs, or rejects
  // with errTimeout, a CanceledError (signal aborted), or an EOFError (stream
  // closed). Non-matching frames are skipped within the same deadline.
  await(timeoutMs, pred, signal) {
    while (this.queue.length) {
      const f = this.queue.shift();
      if (pred(f)) return Promise.resolve(f);
    }
    if (signal && signal.aborted) return Promise.reject(new CanceledError());
    if (this.closed) return Promise.reject(new EOFError());
    return new Promise((resolve, reject) => {
      const w = { pred, resolve, reject, timer: null, signal, onAbort: null };
      w.timer = setTimeout(() => {
        if (this.waiter === w) this.waiter = null;
        this._clearWaiter(w);
        reject(errTimeout);
      }, timeoutMs);
      if (signal) {
        w.onAbort = () => {
          if (this.waiter === w) this.waiter = null;
          this._clearWaiter(w);
          reject(new CanceledError());
        };
        signal.addEventListener("abort", w.onAbort, { once: true });
      }
      this.waiter = w;
    });
  }

  stop() {
    if (this._stopped) return;
    this._stopped = true;
    try {
      this.transport.close();
    } catch {}
  }
}

// parseHelloResp validates a frame as the HELLO_RESP for the HELLO that carried
// wantSeq, and extracts DeviceInfo, or returns null for anything to ignore as
// noise.
function parseHelloResp(f, wantSeq) {
  if (f.type !== MSG_HELLO_RESP || f.seq !== wantSeq || f.nonce === 0 || f.payload.length === 0) {
    return null;
  }
  let obj;
  try {
    obj = JSON.parse(f.payload.toString("utf8"));
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj) || typeof obj.device_id !== "string" || obj.device_id === "") {
    return null;
  }
  // Mirror Go's typed json.Unmarshal: a present field of the wrong JSON type
  // (e.g. sku:123, proto_ver:1.5) fails the unmarshal there and the frame is
  // ignored — so reject it here too rather than coercing. Absent fields are the
  // zero value ("" / 0), which is fine.
  const strField = (v) => v === undefined || v === null || typeof v === "string";
  if (!strField(obj.sku) || !strField(obj.fw) || !strField(obj.state)) return null;
  if (obj.proto_ver !== undefined && obj.proto_ver !== null && !Number.isInteger(obj.proto_ver)) {
    return null;
  }
  return {
    nonce: f.nonce,
    deviceID: obj.device_id,
    sku: typeof obj.sku === "string" ? obj.sku : "",
    fw: typeof obj.fw === "string" ? obj.fw : "",
    state: typeof obj.state === "string" ? obj.state : "",
    protoVer: Number.isInteger(obj.proto_ver) ? obj.proto_ver : 0,
  };
}

function jsonValid(buf) {
  try {
    JSON.parse(buf.toString("utf8"));
    return true;
  } catch {
    return false;
  }
}

// acceptDevice enforces the invariants that must hold before ANY configuration
// write, on both the initial handshake and every reset recovery.
function acceptDevice(dev, opts) {
  if (dev.protoVer !== WIRE_PROTO_VER) {
    throw new UnsupportedProtoError(`device announced proto_ver ${dev.protoVer}, host speaks ${WIRE_PROTO_VER}`);
  }
  if (opts.expectDeviceID && dev.deviceID !== opts.expectDeviceID) {
    throw new DeviceMismatchError(`got ${JSON.stringify(dev.deviceID)}, want ${JSON.stringify(opts.expectDeviceID)}`);
  }
}

// doHandshake sends HELLO and waits for a structurally valid HELLO_RESP,
// retried. seqRef.v is the session-monotonic HELLO seq.
async function doHandshake(fc, to, seqRef, signal) {
  for (let tryN = 0; tryN < to.helloTries; tryN++) {
    const helloSeq = seqRef.v;
    seqRef.v = (seqRef.v + 1) & 0xff;
    fc.send(MSG_HELLO, helloSeq, 0, null);
    let dev = null;
    try {
      await fc.await(
        to.helloResp,
        (f) => {
          const d = parseHelloResp(f, helloSeq);
          if (d) dev = d;
          return !!d;
        },
        signal,
      );
    } catch (e) {
      if (e === errTimeout) continue; // resend HELLO
      throw e;
    }
    return dev;
  }
  throw new HandshakeError(`no valid HELLO_RESP after ${to.helloTries} tries`);
}

// runExchange runs SESSION_BEGIN → SESSION_ACK → PROVISION → RESULT → BYE.
// Returns { resultJSON } on success, { retryHandshake: true } when it stalled
// BEFORE PROVISION (safe to re-HELLO), or throws OutcomeUnknownError once a
// pairing code may be on the wire.
async function runExchange(fc, dev, provisionJSON, to, signal) {
  const nonce = dev.nonce;

  let acked = false;
  for (let i = 0; i < to.sessionTries; i++) {
    fc.send(MSG_SESSION_BEGIN, SEQ_SESSION_BEGIN, nonce, null);
    try {
      await fc.await(
        to.sessionAck,
        (f) => f.type === MSG_SESSION_ACK && f.nonce === nonce && f.seq === SEQ_SESSION_BEGIN,
        signal,
      );
    } catch (e) {
      if (e === errTimeout) continue;
      throw e; // EOF / cancel before any pairing code — propagate as-is
    }
    acked = true;
    break;
  }
  if (!acked) {
    // Nothing sensitive on the wire yet — safe to re-HELLO and retry.
    return { retryHandshake: true };
  }

  // From the first PROVISION send onward the pairing code is (or may be) on the
  // wire, so EVERY failure that is not a clean RESULT is outcome-unknown.
  for (let i = 0; i < to.resultTries; i++) {
    try {
      fc.send(MSG_PROVISION, SEQ_PROVISION, nonce, provisionJSON);
    } catch (e) {
      throw new OutcomeUnknownError(`(PROVISION send failed: ${e.message})`, e);
    }
    let f;
    try {
      f = await fc.await(
        to.result,
        (fr) => fr.type === MSG_RESULT && fr.nonce === nonce && fr.seq === SEQ_PROVISION && jsonValid(fr.payload),
        signal,
      );
    } catch (e) {
      if (e === errTimeout) continue; // resend PROVISION with identical (seq, payload)
      throw new OutcomeUnknownError(`(awaiting RESULT after PROVISION: ${e.message})`, e);
    }
    // Best-effort BYE to restore the console; a lost BYE is harmless.
    try {
      fc.send(MSG_BYE, SEQ_BYE, nonce, null);
    } catch {}
    return { resultJSON: f.payload };
  }
  throw new OutcomeUnknownError(`(after ${to.resultTries} PROVISION sends)`);
}

// runProvision executes the full HELLO → SESSION_BEGIN → PROVISION → BYE
// exchange over transport (an already-opened, OS-exclusively-held serial
// stream). It CONSUMES transport (closes it before returning).
//
// opts: { provisionJSON: Buffer, expectDeviceID?: string, timeouts?, signal? }.
// Returns { device, resultJSON }.
export async function runProvision(transport, opts) {
  const to = withDefaults(opts.timeouts);
  const fc = new FrameConn(transport);
  const signal = opts.signal;
  const provisionJSON = Buffer.isBuffer(opts.provisionJSON) ? opts.provisionJSON : Buffer.from(opts.provisionJSON || "");
  try {
    // A HELLO seq monotonic across the WHOLE session (not reset per handshake),
    // so a delayed HELLO_RESP from an earlier attempt carries a different seq
    // and is ignored.
    const seqRef = { v: 0 };
    for (let attempt = 0; attempt <= MAX_RESET_RECOVERIES; attempt++) {
      const dev = await doHandshake(fc, to, seqRef, signal);
      acceptDevice(dev, opts); // throws DeviceMismatch / UnsupportedProto before any write
      const { resultJSON, retryHandshake } = await runExchange(fc, dev, provisionJSON, to, signal);
      if (retryHandshake) continue; // pre-PROVISION reset → re-HELLO
      return { device: dev, resultJSON };
    }
    throw new HandshakeError(`never got a SESSION_ACK across ${MAX_RESET_RECOVERIES + 1} re-HELLO attempts`);
  } finally {
    fc.stop();
  }
}

// identify performs ONLY the HELLO handshake and returns the device's
// self-report — the bounded identification write the scan's `probe` tier
// permits. It NEVER opens a session or writes config. It consumes transport.
export async function identify(transport, timeouts, signal) {
  const to = withDefaults(timeouts);
  const fc = new FrameConn(transport);
  try {
    const seqRef = { v: 0 };
    return await doHandshake(fc, to, seqRef, signal);
  } finally {
    fc.stop();
  }
}
