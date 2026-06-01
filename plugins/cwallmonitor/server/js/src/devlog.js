// Per-device diagnostic log storage. The device uploads its scrubbed log
// ring to POST /device/<id>/logs; this appends it to
// <config>/device-logs/<id>.log, capped to the most recent MAX_LINES. The
// broker (leader) is the sole writer; any cwm-mcp process reads the file
// for the wall_monitor_device_logs MCP tool. Writes flock a sibling .lock
// and rewrite-then-rename so a reader sees a whole file.
//
// Wire-compatible with cwm-mcp/internal/devlog (Go) and ../py devlog.

import { openSync, closeSync, mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";

// Mirror the registry's mandatory flock (compat/SECURITY.md). Best-effort
// here: only the leader process serves the broker port and writes these
// files, so a missing flock can't corrupt across processes in practice.
let flockSync = null;
try {
  ({ flockSync } = await import("fs-ext"));
  if (typeof flockSync !== "function") flockSync = null;
} catch { /* fs-ext unavailable; single-writer reality keeps this safe */ }

export const MAX_LINES = 2000;
// Truncate any single stamped line. The firmware's own lines are <=200
// chars, so this only bites a misbehaving/compromised device; it bounds
// total retention at ~MAX_LINES*MAX_LINE_BYTES regardless of input.
export const MAX_LINE_BYTES = 1024;
const TRUNC_MARKER = " [truncated]";
export const MAX_BODY_BYTES = 128 * 1024;

export function dirFor(devicesDir) {
  return join(dirname(devicesDir), "device-logs");
}

function logPath(dir, deviceID) {
  return join(dir, `${deviceID}.log`);
}

// Split an uploaded body into lines, drop blanks, prefix each with the
// broker's receive time (whole batch shares one stamp), to seconds
// precision so the format matches the Go/Python impls.
export function stampLines(body, recv) {
  const d = recv || new Date();
  const stamp = `[${d.toISOString().replace(/\.\d+Z$/, "Z")}] `;
  const out = [];
  for (let ln of body.split("\n")) {
    ln = ln.replace(/\r$/, "");
    if (ln.trim() === "") continue;
    let line = stamp + ln;
    const buf = Buffer.from(line, "utf8");
    if (buf.byteLength > MAX_LINE_BYTES) {
      // Reserve the marker's bytes inside the cap, then back up over any
      // trailing UTF-8 continuation bytes so a rune is never split (which
      // would otherwise turn into a 3-byte U+FFFD and overflow the cap).
      let end = MAX_LINE_BYTES - Buffer.byteLength(TRUNC_MARKER, "utf8");
      while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
      line = buf.subarray(0, end).toString("utf8") + TRUNC_MARKER;
    }
    out.push(line);
  }
  return out;
}

export function read(devicesDir, deviceID) {
  const path = logPath(dirFor(devicesDir), deviceID);
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l !== "");
}

export function append(devicesDir, deviceID, lines) {
  if (!lines || lines.length === 0) return;
  const dir = dirFor(devicesDir);
  mkdirSync(dir, { recursive: true });
  const lockPath = logPath(dir, deviceID) + ".lock";
  const fd = openSync(lockPath, "a+", 0o600);
  if (flockSync) flockSync(fd, "ex");
  try {
    const existing = read(devicesDir, deviceID);
    let all = existing.concat(lines);
    if (all.length > MAX_LINES) all = all.slice(all.length - MAX_LINES);
    const path = logPath(dir, deviceID);
    const tmp = path + ".tmp";
    writeFileSync(tmp, all.length ? all.join("\n") + "\n" : "", { mode: 0o600 });
    renameSync(tmp, path);
  } finally {
    if (flockSync) { try { flockSync(fd, "un"); } catch {} }
    closeSync(fd);
  }
}
