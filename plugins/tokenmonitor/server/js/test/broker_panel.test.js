// Handler-level tests for GET /device/{id}/panel: serve a user-authored panel
// document verbatim over the same HMAC channel as /device/{id}/sync. Mirrors
// the Go internal/broker/panel_test.go contract (200 exact bytes, 404
// unconfigured / unknown, 422 oversize / non-JSON, 401 bad sig, per-device
// dir precedence).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { State } from "../src/state.js";
import { Registry, _testing } from "../src/registry/store.js";

const PSK_HEX = "aa".repeat(32);
const PSK = Buffer.from(PSK_HEX, "hex");
const DEVID = "ab12cd34";

function makeCfg(panel = {}) {
  const p = { file: "", dir: "", ...panel };
  return {
    psk: () => Buffer.from("00".repeat(32), "hex"),
    security: { max_timestamp_skew_seconds: 60 },
    codex: { enabled: false },
    panel: p,
    panelFileAbs: () => p.file || "",
    panelDirAbs: () => p.dir || "",
  };
}

function silentLogger() {
  return { info() {}, warn() {}, error() {}, debug() {} };
}

class FakeRes extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.body = "";
    this.ended = false;
    this.socket = { remoteAddress: "127.0.0.1" };
  }
  setHeader(k, v) { this.headers[k.toLowerCase()] = v; }
  writeHead(s) { this.statusCode = s; }
  end(buf) {
    if (buf) this.body += buf.toString("utf8");
    this.ended = true;
    this.emit("close");
  }
}

function makeReq(headers) {
  const req = new EventEmitter();
  req.method = "GET";
  req.url = `/device/${DEVID}/panel`;
  req.headers = Object.assign({ host: "localhost" }, headers);
  req.socket = { remoteAddress: "127.0.0.1" };
  return req;
}

function panelHeaders({ tamper = false } = {}) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = "0123456789abcdef" + Math.random().toString(16).slice(2).padEnd(16, "0").slice(0, 16);
  const path = `/device/${DEVID}/panel`;
  let sig = auth.computeSignature(PSK, "GET", path, ts, nonce, DEVID, "1");
  if (tamper) sig = "0".repeat(sig.length);
  return {
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-signature": sig,
    "x-tmon-device": DEVID,
    "x-tmon-config-version": "1",
  };
}

function dispatch(handler, req, res) {
  return new Promise((resolve) => {
    res.on("close", () => resolve());
    handler(req, res);
    if (res.ended) resolve();
  });
}

function setup(panel, { withDevice = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-panel-"));
  const reg = new Registry(join(dir, "devices"));
  if (withDevice) {
    reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
  }
  const handler = createHandler({
    cfg: makeCfg(panel), cache: new auth.NonceCache(300), state: new State(),
    fwLogs: null, registry: reg, logger: silentLogger(),
  });
  return { dir, handler };
}

async function run(panel, opts = {}) {
  const { dir, handler } = setup(panel, opts);
  try {
    const res = new FakeRes();
    await dispatch(handler, makeReq(panelHeaders(opts)), res);
    return res;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("configured file is served verbatim (200)", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-panelf-"));
  try {
    const body = '{"version":1,"tiles":[{"type":"text","text":"hi"}]}';
    const f = join(d, "panel.json");
    writeFileSync(f, body);
    const res = await run({ file: f });
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(res.body, body);
    assert.equal(res.headers["cache-control"], "no-store");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("not configured → 404", async () => {
  const res = await run({});
  assert.equal(res.statusCode, 404);
});

test("unknown device → 404", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-panelf-"));
  try {
    const f = join(d, "panel.json");
    writeFileSync(f, '{"version":1}');
    const res = await run({ file: f }, { withDevice: false });
    assert.equal(res.statusCode, 404);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("oversize → 422", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-panelf-"));
  try {
    const f = join(d, "panel.json");
    writeFileSync(f, '{"x":"' + "a".repeat(8 * 1024) + '"}');
    const res = await run({ file: f });
    assert.equal(res.statusCode, 422);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("non-JSON → 422", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-panelf-"));
  try {
    const f = join(d, "panel.json");
    writeFileSync(f, "not json at all");
    const res = await run({ file: f });
    assert.equal(res.statusCode, 422);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("bad signature → 401", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-panelf-"));
  try {
    const f = join(d, "panel.json");
    writeFileSync(f, '{"version":1}');
    const res = await run({ file: f }, { tamper: true });
    assert.equal(res.statusCode, 401);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("per-device <dir>/<id>.json wins", async () => {
  const d = mkdtempSync(join(tmpdir(), "tmon-paneld-"));
  try {
    const panels = join(d, "panels");
    mkdirSync(panels);
    writeFileSync(join(panels, "global.json"), '{"src":"global"}');
    writeFileSync(join(panels, "default.json"), '{"src":"default"}');
    const per = '{"src":"perdevice"}';
    writeFileSync(join(panels, `${DEVID}.json`), per);
    const res = await run({ file: join(panels, "global.json"), dir: panels });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body, per);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("serves compat golden byte-exact", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  let golden = null;
  let dir = here;
  for (let i = 0; i < 9; i++) {
    const cand = join(dir, "compat", "panel", "golden", "session_line.json");
    if (existsSync(cand)) { golden = cand; break; }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  if (!golden) { return; } // standalone checkout: compat/ absent
  const want = readFileSync(golden, "utf8");
  const res = await run({ file: golden });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body, want);
});
