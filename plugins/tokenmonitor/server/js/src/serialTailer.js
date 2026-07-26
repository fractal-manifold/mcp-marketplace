// USB-CDC serial tailer. Optional: loaded lazily so a missing serialport
// dependency only affects the firmware-logs path, not the broker.
//
// The tailer is also the lease manager's SerialController: when a follower
// leases the port, the leader calls suspend() to close the tailer's fd and
// release the cross-runtime flock (freeing the device for the lessee's
// OS-exclusive open), and resume() afterwards. It holds the SAME flock a
// follower's OpenExclusive takes (compat/PROVISION_WIRE.md §6), mirroring the Go
// tailer's AcquirePortLock, so the two are fenced even across runtimes.

import { canonicalPort, acquirePortLock } from "./usbprov/serial.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Tailer {
  constructor(device, buf, { baud = 115200 } = {}) {
    this.device = device;
    this.buf = buf;
    this.baud = baud;
    this._connected = false;
    this._aborted = false;
    this._suspended = false;
    this._port = null;
    this._lockRel = null;
  }
  connected() { return this._connected; }

  async start() {
    if (!this.device) return;
    let SerialPort;
    try { ({ SerialPort } = await import("serialport")); }
    catch (e) { return; /* tailing disabled */ }

    const openOnce = (canonical) => new Promise((resolve) => {
      let port;
      try {
        port = new SerialPort({ path: canonical, baudRate: this.baud }, (err) => {
          if (err) { this._port = null; return resolve(false); }
          // A suspend()/stop() may have raced in while the open was in flight
          // (this._port was set synchronously below, so suspend() can already see
          // and close it — but if it flipped the flag without our port yet, yield
          // now). Close and yield the port immediately rather than tail during a
          // lease.
          if (this._suspended || this._aborted) {
            try { port.close(() => {}); } catch {}
            this._port = null;
            return resolve(true);
          }
          this._connected = true;
          let pending = "";
          port.on("data", (chunk) => {
            pending += chunk.toString("utf8");
            let i;
            while ((i = pending.indexOf("\n")) !== -1) {
              this.buf.writeLine(pending.slice(0, i).replace(/\r$/, ""));
              pending = pending.slice(i + 1);
            }
          });
          port.on("close", () => { this._connected = false; resolve(true); });
          port.on("error", () => { this._connected = false; });
        });
        // Publish the port synchronously (before the open callback fires), so a
        // suspend() arriving on the next event-loop turn can close this in-flight
        // open and the tailer never keeps the port during a lease.
        this._port = port;
      } catch { this._port = null; resolve(false); }
    });

    while (!this._aborted) {
      if (this._suspended) { await sleep(200); continue; }
      // Resolve identity + acquire the cross-runtime flock BEFORE opening, so a
      // follower's OpenExclusive (which takes the same flock) is fenced — the
      // Go tailer does the same via AcquirePortLock.
      let canonical;
      try { canonical = canonicalPort(this.device); }
      catch { await sleep(2000); continue; } // device absent right now
      let lockRel = null;
      try {
        lockRel = acquirePortLock(canonical);
      } catch (e) {
        // Fail CLOSED, like the Go tailer (tailer_unix.go): never open without
        // the cross-runtime flock. PortBusyError = a lessee holds it (short
        // backoff); any other error (fs-ext missing, lock-dir validation) =
        // flock unavailable, so tailing stays disabled and we back off — we do
        // NOT open unlocked, which would defeat inter-runtime arbitration.
        await sleep(e && e.name === "PortBusyError" ? 500 : 2000);
        continue;
      }
      // Re-check suspension after acquiring the lock (a lease may have raced in).
      if (this._suspended) { if (lockRel) try { lockRel(); } catch {} await sleep(200); continue; }
      this._lockRel = lockRel;
      const opened = await openOnce(canonical);
      this._connected = false;
      if (this._lockRel) { try { this._lockRel(); } catch {} this._lockRel = null; }
      if (this._aborted || this._suspended) continue;
      await sleep(opened ? 0 : 2000);
    }
  }

  // suspend closes the currently-open port AND releases the cross-runtime flock,
  // then blocks (bounded) until the fd is actually released so a lessee can open
  // it. Throws if the port cannot be freed in time, so the lease manager's Grant
  // rolls back and the broker returns 503 — mirroring the Go tailer's
  // SuspendPort, which returns only once the port is free.
  async suspend() {
    this._suspended = true;
    const port = this._port;
    this._port = null;
    let freed = true;
    if (port) {
      // Await the actual 'close' event (not just the close() call) so the fd is
      // truly released before we drop the flock. If the port is still mid-open,
      // the open callback observes _suspended and closes it, which also fires
      // 'close'. Bounded — a timeout throws so Grant rolls back and the broker
      // returns 503, mirroring the Go tailer's blocking SuspendPort.
      freed = await new Promise((resolve) => {
        const t = setTimeout(() => resolve(false), 3000);
        port.once("close", () => { clearTimeout(t); resolve(true); });
        try { if (port.isOpen) port.close(() => {}); } catch { /* mid-open: the open cb closes it */ }
      });
    }
    this._connected = false;
    // Release the flock so the lessee's OpenExclusive can take it.
    if (this._lockRel) { try { this._lockRel(); } catch {} this._lockRel = null; }
    if (!freed) throw new Error("tailer: could not release the serial port in time");
  }

  resume() { this._suspended = false; }

  stop() {
    this._aborted = true;
    const port = this._port;
    this._port = null;
    if (port) { try { port.close(); } catch {} }
    if (this._lockRel) { try { this._lockRel(); } catch {} this._lockRel = null; }
  }
}

// TailerController adapts a Tailer to the lease manager's SerialController
// interface (async suspendPort(canonical) / resumePort(canonical)). It no-ops
// for a port this tailer does not own — mirroring the Go Tailer, which keys both
// calls on the canonical path. Identity is resolved PER CALL (not cached), so a
// device absent at startup or a retargeted symlink is handled correctly.
// `getTailer` is a getter so a tailer created lazily is still reachable.
export class TailerController {
  constructor(getTailer) {
    this._getTailer = getTailer;
  }
  _ownedBy(canonical) {
    const t = this._getTailer();
    if (!t || !t.device) return null;
    let c;
    try { c = canonicalPort(t.device); }
    catch { return null; }
    return c === canonical ? t : null;
  }
  async suspendPort(canonical) {
    const t = this._ownedBy(canonical);
    if (t) await t.suspend();
  }
  resumePort(canonical) {
    const t = this._ownedBy(canonical);
    if (t) t.resume();
  }
}
