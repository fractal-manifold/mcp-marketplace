// Per-device diagnostic log store — stamping, truncation, retention.
// Mirrors the Go (internal/devlog/devlog_test.go) and Python
// (tests/test_devlog.py) behaviour so the three impls stay wire-compatible.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as devlog from "../src/devlog.js";

const EPOCH = new Date(0);

test("stampLines: stamps, drops blanks, trims CR", () => {
  const got = devlog.stampLines("alpha\nbeta\n\n  \ngamma\r\n", EPOCH);
  assert.deepEqual(got, [
    "[1970-01-01T00:00:00Z] alpha",
    "[1970-01-01T00:00:00Z] beta",
    "[1970-01-01T00:00:00Z] gamma",
  ]);
});

test("stampLines: caps each line at MAX_LINE_BYTES, valid UTF-8, marker", () => {
  // A misbehaving device can upload giant single lines.
  for (const unit of ["x", "é", "世", "🙂"]) {
    const got = devlog.stampLines(unit.repeat(5000), EPOCH);
    assert.equal(got.length, 1);
    const line = got[0];
    assert.ok(Buffer.byteLength(line, "utf8") <= devlog.MAX_LINE_BYTES, `${unit}: over cap`);
    assert.ok(!line.includes("�"), `${unit}: split a rune into U+FFFD`);
    assert.ok(line.endsWith(" [truncated]"), `${unit}: missing marker`);
  }
});

test("append: caps retention and round-trips", () => {
  const devices = join(mkdtempSync(join(tmpdir(), "cwm-devlog-")), "devices");
  const dev = "ab12cd34";

  devlog.append(devices, dev, ["one", "two"]);
  assert.deepEqual(devlog.read(devices, dev), ["one", "two"]);

  devlog.append(devices, dev, Array(devlog.MAX_LINES + 50).fill("line"));
  assert.equal(devlog.read(devices, dev).length, devlog.MAX_LINES);
});

test("read: missing file is empty", () => {
  const devices = join(mkdtempSync(join(tmpdir(), "cwm-devlog-")), "devices");
  assert.deepEqual(devlog.read(devices, "deadbeef"), []);
});
