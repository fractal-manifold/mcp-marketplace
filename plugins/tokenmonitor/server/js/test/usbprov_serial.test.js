import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, chmodSync, symlinkSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { acquireLockIn, releaseLock, secureLockDir, PortBusyError } from "../src/usbprov/serial.js";

test("exclusive flock then busy; re-acquirable after release", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "tmonlk-")), "lk");
  const dev = "/dev/ttyACM0";
  const fd = acquireLockIn(dir, dev);
  assert.throws(() => acquireLockIn(dir, dev), PortBusyError);
  releaseLock(fd);
  const fd2 = acquireLockIn(dir, dev);
  releaseLock(fd2);
});

test("distinct device paths do not collide", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "tmonlk-")), "lk");
  const a = acquireLockIn(dir, "/dev/ttyACM0");
  const b = acquireLockIn(dir, "/dev/ttyACM1");
  releaseLock(a);
  releaseLock(b);
});

test("secureLockDir rejects a symlinked dir", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonlk-"));
  const target = join(root, "real");
  mkdirSync(target, 0o700);
  const link = join(root, "link");
  symlinkSync(target, link);
  assert.throws(() => secureLockDir(link));
});

test("secureLockDir rejects group/world access", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonlk-"));
  const dir = join(root, "loose");
  mkdirSync(dir, 0o777);
  chmodSync(dir, 0o777);
  assert.throws(() => secureLockDir(dir));
});

test("secureLockDir creates a fresh 0700 dir and revalidates it", () => {
  const root = mkdtempSync(join(tmpdir(), "tmonlk-"));
  const dir = join(root, "fresh");
  secureLockDir(dir);
  secureLockDir(dir); // revalidate existing safe dir
});

// The lock-file identity is the cross-runtime contract: serial-<64 hex>.lock,
// where the hex is SHA-256(canonical_path_utf8). Assert both the shape and the
// exact hash so a Go/Py leader and a JS follower target the SAME file.
test("lock file named serial-<sha256(path)>.lock (byte-identical to Go)", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "tmonlk-")), "lk");
  const dev = "/dev/ttyACM0";
  const fd = acquireLockIn(dir, dev);
  const entries = readdirSync(dir);
  assert.equal(entries.length, 1);
  const want = "serial-" + createHash("sha256").update(Buffer.from(dev, "utf8")).digest("hex") + ".lock";
  assert.equal(entries[0], want);
  assert.equal(entries[0].length, "serial-".length + 64 + ".lock".length);
  releaseLock(fd);
});
