// Follower side of the serial-lease contract (compat/PROVISION_WIRE.md §6).
// Mirrors go/internal/usbprov/leaseclient.go. A follower that wants to
// provision over USB asks the local leader to yield the port, holds the lease
// (renewing before it lapses), then releases it. The lease is the authority
// between cooperating processes; the OS-exclusive open is the second fence, so
// even the "no lease needed" fallbacks still open exclusively.

import { createHash, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { performance } from "node:perf_hooks";

import { computeSignatureBody } from "../auth.js";
import { openExclusive, PortBusyError } from "./serial.js";
import { LEASE_PATH, LEASE_RENEW_PATH, LEASE_RELEASE_PATH } from "./leasewire.js";
import { LeaseBusyError } from "./lease.js";

// DEFAULT_LEASE_TTL is the TTL a follower requests. The leader clamps it; the
// client renews at half this cadence.
const DEFAULT_LEASE_TTL_MS = 20_000;
const MAX_LEASE_RESP_BYTES = 4 << 10;

function freshLeaseNonce() {
  return randomBytes(16).toString("hex");
}

// anySignal returns an AbortSignal that fires when any input signal fires (a
// portable AbortSignal.any). Used to fold the session's own cancellation and
// the lease-lost signal into one.
export function anySignal(signals) {
  const ctrl = new AbortController();
  const onAbort = () => {
    ctrl.abort();
    for (const s of signals) if (s) s.removeEventListener?.("abort", onAbort);
  };
  for (const s of signals) {
    if (!s) continue;
    if (s.aborted) {
      ctrl.abort();
      break;
    }
    s.addEventListener("abort", onAbort, { once: true });
  }
  return ctrl.signal;
}

// LeasedPort is a serial port acquired for exclusive use. `handle` is the open
// port (a usbprov Handle). `lostSignal` is an AbortSignal that fires if the
// lease can no longer be held (leader reaped it / broker unreachable) — the
// caller MUST treat that as the port possibly reclaimed and abort any in-flight
// session. For a direct open, lostSignal never fires. close() is idempotent.
export class LeasedPort {
  constructor(handle, lostController, stop) {
    this.handle = handle;
    this._lostController = lostController; // AbortController or null (direct open)
    this._stop = stop;
    this._closed = false;
  }
  get lostSignal() {
    return this._lostController ? this._lostController.signal : neverAbortSignal();
  }
  close() {
    if (this._closed) return;
    this._closed = true;
    if (this._stop) this._stop();
  }
}

let _neverSignal = null;
function neverAbortSignal() {
  if (!_neverSignal) _neverSignal = new AbortController().signal;
  return _neverSignal;
}

// openWithRetry opens the port exclusively, retrying on PortBusyError for a
// short bounded window (the previous holder may take a moment to fully release
// the flock). Honours the abort signal.
async function openWithRetry(port, signal) {
  const attempts = 20;
  let lastErr = null;
  for (let i = 0; i < attempts; i++) {
    if (signal && signal.aborted) throw new AbortedError();
    try {
      return await openExclusive(port);
    } catch (e) {
      if (!(e instanceof PortBusyError)) throw e; // real open error — don't spin
      lastErr = e;
      await sleep(50, signal);
    }
  }
  throw lastErr;
}

class AbortedError extends Error {
  constructor() {
    super("usbprov: operation aborted");
    this.name = "AbortedError";
  }
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    if (signal) {
      const onAbort = () => {
        clearTimeout(t);
        reject(new AbortedError());
      };
      if (signal.aborted) {
        clearTimeout(t);
        return reject(new AbortedError());
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

export class LeaseClient {
  // opts: { baseURL, psk (Buffer), now?: () => ms }
  constructor({ baseURL, psk, now }) {
    this.baseURL = baseURL; // e.g. http://127.0.0.1:8765 (no trailing slash)
    this.psk = psk;
    this._now = now || (() => performance.now());
    this._clockUnix = () => Math.floor(Date.now() / 1000);
  }

  // openLeased acquires port for exclusive provisioning use. On a 200 grant it
  // opens the yielded port and renews in the background until close(). On 404/
  // 503/dial-error it falls back to a direct OS-exclusive open. Throws
  // LeaseBusyError if another follower holds the lease, PortBusyError if the
  // direct open loses the flock race.
  async openLeased(port, signal) {
    const { id, grantedMs, needLease } = await this._acquire(port, DEFAULT_LEASE_TTL_MS, signal);
    if (!needLease) {
      const h = await openWithRetry(port, signal);
      return new LeasedPort(h, null, () => h.release());
    }
    // Lease held: the leader already suspended the tailer synchronously, so the
    // open should succeed promptly; retry briefly for an election gap.
    let h;
    try {
      h = await openWithRetry(port, signal);
    } catch (e) {
      await this._releaseBounded(id);
      throw e;
    }
    const lostController = new AbortController();
    const stopRenew = { stopped: false, timer: null };
    this._startRenewLoop(id, grantedMs, lostController, stopRenew);
    return new LeasedPort(h, lostController, () => {
      stopRenew.stopped = true;
      if (stopRenew.timer) clearTimeout(stopRenew.timer);
      h.release();
      this._releaseBounded(id);
    });
  }

  // _acquire posts a lease request. needLease is false when no lease is needed
  // (no broker, or a leader without this endpoint / without a serial device).
  async _acquire(port, ttlMs, signal) {
    const body = Buffer.from(JSON.stringify({ port, ttl_ms: ttlMs }), "utf8");
    let resp;
    try {
      resp = await this._do(LEASE_PATH, body, signal);
    } catch (e) {
      // A cancelled caller must surface, NOT silently fall through to a direct
      // open (which would ignore the cancellation).
      if (signal && signal.aborted) throw new AbortedError();
      // No broker reachable → nobody is tailing the port → direct open.
      return { id: "", grantedMs: 0, needLease: false };
    }
    switch (resp.status) {
      case 200: {
        let lr;
        try {
          lr = JSON.parse(resp.body);
        } catch {
          lr = null;
        }
        // "ttl_ms", not "granted_ms" (PROVISION_WIRE §6) — reading the wrong
        // key would make every grant from a conforming leader look malformed.
        // Integer-only, matching Go's unmarshal into int64 and py's check: a
        // leader that answered "5000" or 5000.5 is malformed, not merely odd.
        if (
          !lr ||
          typeof lr.lease_id !== "string" ||
          lr.lease_id === "" ||
          typeof lr.ttl_ms !== "number" ||
          !Number.isInteger(lr.ttl_ms) ||
          lr.ttl_ms <= 0
        ) {
          throw new Error("usbprov: malformed lease response");
        }
        return { id: lr.lease_id, grantedMs: lr.ttl_ms, needLease: true };
      }
      case 409:
        throw new LeaseBusyError();
      case 404:
      case 503:
        // Leader too old to know the endpoint, or no serial device configured:
        // no tailer contends this port → direct open.
        return { id: "", grantedMs: 0, needLease: false };
      default:
        throw new Error(`usbprov: lease request failed: ${resp.status}`);
    }
  }

  // _startRenewLoop renews at half the granted cadence until stopped. On the
  // first renewal failure it aborts lostController and stops.
  _startRenewLoop(id, grantedMs, lostController, stopRenew) {
    let interval = Math.floor(grantedMs / 2);
    if (interval < 250) interval = 250;
    const tick = async () => {
      if (stopRenew.stopped) return;
      try {
        await this._renew(id);
      } catch {
        if (!stopRenew.stopped) {
          stopRenew.stopped = true;
          lostController.abort(); // lease is gone → signal the session to abort
        }
        return;
      }
      if (stopRenew.stopped) return;
      stopRenew.timer = setTimeout(tick, interval);
    };
    stopRenew.timer = setTimeout(tick, interval);
  }

  // The renew body carries ONLY the lease id (PROVISION_WIRE §6): the leader
  // re-applies the TTL it originally granted, so a renew can never shrink the
  // window.
  async _renew(id) {
    const body = Buffer.from(JSON.stringify({ lease_id: id }), "utf8");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    let resp;
    try {
      resp = await this._do(LEASE_RENEW_PATH, body, ctrl.signal);
    } finally {
      clearTimeout(timer);
    }
    if (resp.status !== 200) throw new Error(`usbprov: renew failed: ${resp.status}`);
  }

  // _releaseBounded releases best-effort with its own bounded timeout, so a
  // cleanup path never blocks indefinitely. The leader reaps on TTL expiry.
  async _releaseBounded(id) {
    const body = Buffer.from(JSON.stringify({ lease_id: id }), "utf8");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    try {
      await this._do(LEASE_RELEASE_PATH, body, ctrl.signal);
    } catch {
      // best-effort; the leader reaps the lease on TTL expiry anyway
    } finally {
      clearTimeout(timer);
    }
  }

  // _do signs and sends one POST with a mandatory body digest (v3 canonical).
  _do(path, body, signal) {
    const bodySHA = createHash("sha256").update(body).digest("hex");
    const ts = String(this._clockUnix());
    const nonce = freshLeaseNonce();
    const sig = computeSignatureBody(this.psk, "POST", path, ts, nonce, "", "", bodySHA);
    const u = new URL(this.baseURL + path);
    return new Promise((resolve, reject) => {
      let onAbort = null;
      const cleanup = () => {
        if (onAbort && signal) signal.removeEventListener("abort", onAbort);
        onAbort = null;
      };
      const settle = (fn) => (v) => { cleanup(); fn(v); };
      resolve = settle(resolve);
      reject = settle(reject);
      const req = httpRequest(
        {
          protocol: u.protocol,
          hostname: u.hostname,
          port: u.port || 80,
          path: u.pathname,
          method: "POST",
          timeout: 4000,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": body.length,
            "X-Tmon-Timestamp": ts,
            "X-Tmon-Nonce": nonce,
            "X-Tmon-Signature": sig,
            "X-Tmon-Body-Sha256": bodySHA,
          },
        },
        (res) => {
          let buf = "";
          let n = 0;
          res.on("data", (c) => {
            n += c.length;
            if (n <= MAX_LEASE_RESP_BYTES) buf += c;
          });
          res.on("end", () => resolve({ status: res.statusCode, body: buf }));
        },
      );
      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy(new Error("timeout"));
      });
      if (signal) {
        if (signal.aborted) {
          req.destroy(new Error("aborted"));
        } else {
          onAbort = () => req.destroy(new Error("aborted"));
          signal.addEventListener("abort", onAbort, { once: true });
        }
      }
      req.write(body);
      req.end();
    });
  }
}
