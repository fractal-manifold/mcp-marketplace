// Serial-port lease arbitration, leader side (compat/PROVISION_WIRE.md §6).
// Mirrors go/internal/usbprov/lease.go. The serial tailer runs only in the
// leader, so a follower asks the leader to stop tailing a port. The lease is
// the authority BETWEEN cooperating tokenmonitor-mcp processes; the
// OS-exclusive open (serial.js) is the fence for everything the lease cannot
// see.
//
// Deadlines are MONOTONIC (performance.now, not Date.now): an NTP step must not
// expire a lease early or extend it. `expires_unix_ms` in the response is a
// client-facing wall-clock approximation only.

import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";

const DEFAULT_LEASE_MAX_TTL_MS = 60_000;
const DEFAULT_LEASE_MIN_TTL_MS = 1_000;

export class LeaseBusyError extends Error {
  constructor() {
    super("usbprov: port is already leased");
    this.name = "LeaseBusyError";
  }
}
export class LeaseUnknownError extends Error {
  constructor() {
    super("usbprov: lease is unknown or expired");
    this.name = "LeaseUnknownError";
  }
}

// NopController is a SerialController for a leader that tails no port: every
// port is free, so Grant never has to suspend anything. A SerialController is
// any object with async suspendPort(canonical) and resumePort(canonical).
export class NopController {
  async suspendPort() {}
  resumePort() {}
}

// randomLeaseID returns 16 bytes of crypto entropy as 32 lowercase hex chars.
export function randomLeaseID() {
  return randomBytes(16).toString("hex");
}

// LeaseManager is the leader's per-port lease table. Times are monotonic ms.
export class LeaseManager {
  constructor(ctrl, maxTTLms) {
    this.ctrl = ctrl;
    this.now = () => performance.now(); // monotonic ms; injectable in tests
    this.newID = randomLeaseID;
    this.maxTTL = maxTTLms > 0 ? maxTTLms : DEFAULT_LEASE_MAX_TTL_MS;
    this.minTTL = DEFAULT_LEASE_MIN_TTL_MS;
    this.byPort = new Map(); // canonical -> entry
    this.byID = new Map(); // id -> entry
    // reserving holds ports with an in-flight Grant that has released the
    // logical lock to await the (possibly blocking) suspendPort. JS is
    // single-threaded, so phase 1 / phase 3 run atomically between await points.
    this.reserving = new Set();
  }

  _clampTTL(ttl) {
    if (ttl > this.maxTTL) return this.maxTTL;
    if (ttl < this.minTTL) return this.minTTL;
    return ttl;
  }

  // Grant leases canonical for up to ttlMs. On success it has already suspended
  // the controller's tailer on that port. Returns
  // { id, grantedMs, expiresUnixMs }. Throws LeaseBusyError if the port is
  // already leased or being reserved by a concurrent Grant.
  async Grant(canonical, ttlMs) {
    // Phase 1 (atomic, no await): reap, reject if busy/reserving, reserve.
    this._reap();
    if (this.byPort.has(canonical) || this.reserving.has(canonical)) {
      throw new LeaseBusyError();
    }
    this.reserving.add(canonical);

    // Phase 2 (awaits): hand the port to the lessee. The reserving slot keeps
    // this port exclusive meanwhile without blocking other ports.
    let suspendErr = null;
    try {
      await this.ctrl.suspendPort(canonical);
    } catch (e) {
      suspendErr = e || new Error("suspendPort failed");
    }

    // Phase 3 (atomic): commit, or roll back on suspend failure.
    this.reserving.delete(canonical);
    if (suspendErr) {
      this.ctrl.resumePort(canonical);
      throw suspendErr;
    }
    const granted = this._clampTTL(ttlMs);
    const id = this.newID();
    // `granted` is stored on the entry because Renew re-applies it (see below).
    const e = { id, port: canonical, granted, deadline: this.now() + granted };
    this.byPort.set(canonical, e);
    this.byID.set(id, e);
    return { id, grantedMs: granted, expiresUnixMs: Date.now() + granted };
  }

  // Renew extends an existing lease by RE-APPLYING the TTL it was originally
  // granted. Throws LeaseUnknownError if the lease is gone or already expired
  // (the client must then abort). Returns { grantedMs, expiresUnixMs }.
  //
  // The renew carries no TTL of its own, per PROVISION_WIRE §6: "a renew can
  // never shrink the window". Taking one from the request is a cross-runtime
  // break, not just untidiness — a conforming follower sends only
  // {"lease_id"}, so a leader that read ttl_ms would see 0, clamp to the 1 s
  // FLOOR, and reclaim the port a second later with the follower still
  // mid-session. That is the byte-splitting the lease exists to prevent.
  // Mirror of Go LeaseManager.Renew.
  Renew(id) {
    const e = this.byID.get(id);
    if (!e || !(this.now() < e.deadline)) {
      if (e) this._drop(e);
      throw new LeaseUnknownError();
    }
    e.deadline = this.now() + e.granted;
    return { grantedMs: e.granted, expiresUnixMs: Date.now() + e.granted };
  }

  // Release drops a lease and resumes the owner. Idempotent — an unknown id is
  // a success.
  Release(id) {
    const e = this.byID.get(id);
    if (e) this._drop(e);
  }

  // ReapExpired drops every lapsed lease (resuming the owner for each). Returns
  // how many were reclaimed.
  ReapExpired() {
    return this._reap();
  }

  _reap() {
    const now = this.now();
    let n = 0;
    for (const e of [...this.byID.values()]) {
      if (!(now < e.deadline)) {
        this._drop(e);
        n++;
      }
    }
    return n;
  }

  _drop(e) {
    this.byID.delete(e.id);
    const cur = this.byPort.get(e.port);
    if (cur === e) this.byPort.delete(e.port);
    this.ctrl.resumePort(e.port);
  }
}
