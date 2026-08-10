// OS-exclusive serial open + cross-runtime advisory lock
// (compat/PROVISION_WIRE.md §6 "OS-exclusive serial open"). Mirrors
// go/internal/usbprov/serial.go + serial_linux.go.
//
// The lock-file identity is the CROSS-RUNTIME CONTRACT and MUST be
// byte-identical to Go/Py: SHA-256(canonical_path_utf8) as 64 lowercase hex,
// filename `serial-<hex>.lock`, in `/run/user/<euid>/tokenmonitor/` (when
// /run/user/<euid> exists) else `/tmp/tokenmonitor-<euid>/`, dir 0700 / file
// 0600, owner-checked, symlink-rejected.
//
// The flock (via fs-ext, taken BEFORE open) is the real arbitration between
// cooperating runtimes and closes the election-gap race. The serialport
// library's `lock: true` open option is the second, kernel-level fence against
// foreign programs (the TIOCEXCL analogue) — see the divergence note at the
// bottom of this file.

import { createHash } from "node:crypto";
import { openSync, closeSync, fstatSync, mkdirSync, lstatSync, realpathSync, statSync, constants as fsConstants } from "node:fs";
import { resolve as pathResolve, join as pathJoin } from "node:path";
import process from "node:process";

let flockSync = null;
let flockLoadError = null;
try {
  ({ flockSync } = await import("fs-ext"));
  if (typeof flockSync !== "function") {
    flockLoadError = new Error("fs-ext loaded but flockSync is not a function");
    flockSync = null;
  }
} catch (e) {
  flockLoadError = e;
}

export class PortBusyError extends Error {
  constructor(msg) {
    super(msg || "usbprov: serial port is held by another process");
    this.name = "PortBusyError";
  }
}

export class OpenUnsupportedError extends Error {
  constructor() {
    super("usbprov: exclusive serial open is not supported on this platform");
    this.name = "OpenUnsupportedError";
  }
}

// canonicalPort resolves a serial-port path to the stable identity used as both
// the lease key and the OS-exclusive lock key. On POSIX it resolves symlinks
// and preserves case (device paths are case-sensitive); the device must exist.
export function canonicalPort(path) {
  const abs = pathResolve(path);
  return realpathSync(abs);
}

// lockDir is the fixed directory holding serial lock-files. It keys on a
// filesystem fact (does /run/user/<euid> exist?), NOT on $XDG_RUNTIME_DIR, so a
// daemon without that env var and an interactive follower that has it still
// agree on the same lock path.
export function lockDir() {
  const euid = typeof process.geteuid === "function" ? process.geteuid() : 0;
  const run = `/run/user/${euid}`;
  if (dirExists(run)) return pathJoin(run, "tokenmonitor");
  return `/tmp/tokenmonitor-${euid}`;
}

function dirExists(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

// secureLockDir creates dir (single level; its parent already exists) as 0700,
// or, if it already exists, verifies it is a real directory owned by the
// effective user with no group/other access and not a symlink. Fail-closed.
export function secureLockDir(dir) {
  try {
    mkdirSync(dir, 0o700);
    return;
  } catch (e) {
    if (!e || e.code !== "EEXIST") {
      throw new Error(`usbprov: create lock dir ${JSON.stringify(dir)}: ${e && e.message}`);
    }
  }
  let fi;
  try {
    fi = lstatSync(dir);
  } catch (e) {
    throw new Error(`usbprov: stat lock dir ${JSON.stringify(dir)}: ${e && e.message}`);
  }
  if (fi.isSymbolicLink()) throw new Error(`usbprov: lock dir ${JSON.stringify(dir)} is a symlink`);
  if (!fi.isDirectory()) throw new Error(`usbprov: lock path ${JSON.stringify(dir)} is not a directory`);
  if ((fi.mode & 0o077) !== 0) {
    throw new Error(`usbprov: lock dir ${JSON.stringify(dir)} has unsafe permissions ${(fi.mode & 0o777).toString(8)}`);
  }
  const euid = typeof process.geteuid === "function" ? process.geteuid() : 0;
  if (fi.uid !== euid) throw new Error(`usbprov: lock dir ${JSON.stringify(dir)} is not owned by the current user`);
}

// acquireLockIn takes a non-blocking exclusive flock on a lock-file whose name
// is `serial-<sha256(absPath) hex>.lock`. A held lock yields PortBusyError
// rather than blocking. Returns an opaque lock handle (an fd number). absPath is
// hashed VERBATIM — callers pass the canonical path.
export function acquireLockIn(dir, absPath) {
  if (!flockSync) {
    const cause = flockLoadError ? `: ${flockLoadError.message}` : "";
    throw new Error(`usbprov: flock(2) unavailable (install 'fs-ext')${cause}`);
  }
  secureLockDir(dir);
  const sum = createHash("sha256").update(Buffer.from(absPath, "utf8")).digest("hex");
  const lp = pathJoin(dir, `serial-${sum}.lock`);
  // O_NOFOLLOW: refuse to open a symlink planted at the lock-file path. Inside a
  // secureLockDir (0700, owned by us) no other user can plant one; cheap
  // defence in depth.
  let fd;
  try {
    fd = openSync(lp, fsConstants.O_CREAT | fsConstants.O_RDWR | fsConstants.O_NOFOLLOW, 0o600);
  } catch (e) {
    throw new Error(`usbprov: open lock file: ${e && e.message}`);
  }
  // Fail-closed validation of the opened object itself (compat/PROVISION_WIRE.md
  // §6): the fd must be a regular file, owned by us, with no group/world bits.
  // O_NOFOLLOW already blocks symlinks; the secureLockDir (0700, ours) makes a
  // planted file unreachable, but validate anyway as defence in depth.
  try {
    const st = fstatSync(fd);
    const euid = typeof process.geteuid === "function" ? process.geteuid() : 0;
    if (!st.isFile() || st.uid !== euid || (st.mode & 0o077) !== 0) {
      closeSync(fd);
      throw new Error(`usbprov: unsafe lock file ${JSON.stringify(lp)}`);
    }
  } catch (e) {
    try { closeSync(fd); } catch {}
    throw e instanceof Error ? e : new Error(`usbprov: stat lock file: ${e}`);
  }
  try {
    flockSync(fd, "exnb");
  } catch (e) {
    try {
      closeSync(fd);
    } catch {}
    if (e && (e.code === "EAGAIN" || e.code === "EWOULDBLOCK")) {
      throw new PortBusyError(`usbprov: serial port is held by another process: ${absPath}`);
    }
    throw new Error(`usbprov: flock: ${e && e.message}`);
  }
  return fd;
}

// releaseLock unlocks and closes a lock handle. Idempotent-ish (a second call
// on a closed fd is swallowed).
export function releaseLock(fd) {
  if (fd == null) return;
  try {
    flockSync(fd, "un");
  } catch {}
  try {
    closeSync(fd);
  } catch {}
}

function acquirePortLockFd(canonical) {
  return acquireLockIn(lockDir(), canonical);
}

// acquirePortLock takes the cross-runtime exclusive lock for a canonical path
// (already canonicalised via canonicalPort) — for owners that manage their own
// open, i.e. the firmware-log tailer. Returns a release function. Throws
// PortBusyError (retryable) if held.
export function acquirePortLock(canonical) {
  const fd = acquirePortLockFd(canonical);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    releaseLock(fd);
  };
}

// Handle is an OS-exclusive hold on a serial port. `conn` is the raw byte
// transport (a serialport Duplex stream) handed to runProvision, which consumes
// and closes it. The flock lives on a SEPARATE fd owned by this Handle; the
// caller must release() it AFTER the session, which also best-effort closes
// conn (idempotent).
export class Handle {
  constructor(conn, release) {
    this.conn = conn;
    this._release = release;
    this._released = false;
  }
  // release() closes the port and drops the flock. Async: it AWAITS the serial
  // close before releasing the flock, so the next opener (which takes the same
  // flock) never races an OS-exclusive fd that is still open (which would surface
  // as a non-retryable EBUSY). Mirrors Go's serial_linux.go: Close() then
  // lock.release(), in that order. Safe to not await from the caller — the
  // close-before-unlock ordering holds regardless.
  release() {
    if (this._released) return;
    this._released = true;
    if (this._release) return this._release();
  }
}

// openExclusive acquires an OS-exclusive hold on the serial port at path and
// opens it raw with DTR/RTS cleared (best-effort, to minimise the esptool-style
// auto-reset). The flock is taken BEFORE the device is opened, closing the race
// where two cooperating runtimes both open the port in the leader-election gap.
export async function openExclusive(path) {
  // POSIX only. Linux + macOS share the whole implementation below: the flock
  // (fs-ext) and the serialport `lock:true` open both work on darwin, and
  // lockDir() falls back to /tmp/tokenmonitor-<euid> when /run/user is absent
  // (as it is on macOS). Windows has no flock/exclusive-open analogue here yet.
  if (process.platform !== "linux" && process.platform !== "darwin") {
    throw new OpenUnsupportedError();
  }
  const canonical = canonicalPort(path);
  // Lock BEFORE opening the device.
  const lockFd = acquirePortLockFd(canonical);
  let port;
  try {
    port = await openRawSerial(canonical);
  } catch (e) {
    releaseLock(lockFd);
    throw e;
  }
  let closed = false;
  const closePromise = new Promise((res) => port.once("close", () => { closed = true; res(); }));
  const conn = wrapPort(port, () => (closed = true));
  return new Handle(conn, async () => {
    // Initiate close if the session did not already, then AWAIT the OS fd being
    // released (bounded) BEFORE dropping the flock.
    try { if (port.isOpen) port.close(() => {}); } catch {}
    if (!closed) {
      await Promise.race([closePromise, new Promise((r) => setTimeout(r, 3000))]);
    }
    releaseLock(lockFd);
  });
}

async function openRawSerial(canonical) {
  const { SerialPort } = await import("serialport");
  return await new Promise((resolve, reject) => {
    // lock: true → serialport opens the tty exclusively (TIOCEXCL analogue),
    // the second fence for foreign programs. USB-CDC ignores baud. A raw byte
    // stream (no line discipline) is what serialport gives by default.
    const port = new SerialPort({ path: canonical, baudRate: 115200, lock: true, autoOpen: false });
    port.open((err) => {
      if (err) return reject(err);
      // Best-effort: clear DTR/RTS so opening the port does not toggle the
      // esptool download-mode reset signal. On Linux open() often asserts DTR
      // before we get here, so this only narrows the window — firmware
      // tolerates an unexpected reset as the real mitigation.
      try {
        port.set({ dtr: false, rts: false }, () => resolve(port));
      } catch {
        resolve(port);
      }
    });
  });
}

// wrapPort adapts a serialport stream to the transport interface runProvision
// expects: on('data'/'close'/'error'), write(buf), close(). close() is
// idempotent.
function wrapPort(port, onClosed) {
  let closed = false;
  return {
    on(ev, cb) {
      port.on(ev, cb);
      return this;
    },
    write(buf) {
      return port.write(buf);
    },
    close() {
      if (closed) return;
      closed = true;
      onClosed();
      try {
        port.close(() => {});
      } catch {}
    },
  };
}

// --- Divergence note (JS ↔ Go) -------------------------------------------
// Go's serial_linux.go layers three fences on POSIX: (1) flock on the sibling
// lock-file (the real arbitration), (2) TIOCEXCL on the serial fd, (3) a UUCP
// LCK.. file. This JS port keeps (1) byte-identically (same lock dir, same
// filename, same hash), which is the cross-runtime contract. For (2) it relies
// on the `serialport` library's `lock: true` open option, which performs the
// exclusive open (TIOCEXCL/flock) natively — the ioctl is not reachable from
// pure JS, and the contract explicitly says flock is the primary fence and
// TIOCEXCL is defence-in-depth. (3) the UUCP LCK.. file is not implemented (it
// is a best-effort compat shim for foreign tools only). termios raw mode is
// implicit: serialport delivers a raw byte stream with no line discipline.
