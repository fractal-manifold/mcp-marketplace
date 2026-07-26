import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createHandler } from "../src/broker/server.js";
import * as auth from "../src/auth.js";
import { LeaseManager, NopController, LeaseBusyError } from "../src/usbprov/lease.js";
import { LeaseClient } from "../src/usbprov/leaseclient.js";
import { LEASE_PATH, LEASE_RENEW_PATH, LEASE_RELEASE_PATH } from "../src/usbprov/leasewire.js";

const PSK = randomBytes(32);
const logger = { info() {}, warn() {}, error() {} };

function mkCfg() {
  return {
    psk: () => PSK,
    security: { max_timestamp_skew_seconds: 300 },
    server: { bind: "127.0.0.1", port: 0 },
  };
}

function mkDeps(leaseManager) {
  return {
    cfg: mkCfg(),
    cache: new auth.NonceCache(300),
    state: { recordRequest() {} },
    registry: null,
    logger,
    leaseManager,
  };
}

// A real, existing filesystem path so canonicalPort (realpathSync) resolves.
function fakePort() {
  const dir = mkdtempSync(join(tmpdir(), "tmonport-"));
  const p = join(dir, "ttyFAKE0");
  writeFileSync(p, "");
  return p;
}

function signHeaders(path, bodyBuf) {
  const bodySha = createHash("sha256").update(bodyBuf).digest("hex");
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString("hex");
  const sig = auth.computeSignatureBody(PSK, "POST", path, ts, nonce, "", "", bodySha);
  return {
    "content-type": "application/json",
    "content-length": String(bodyBuf.length),
    "x-tmon-timestamp": ts,
    "x-tmon-nonce": nonce,
    "x-tmon-signature": sig,
    "x-tmon-body-sha256": bodySha,
  };
}

// Drive createHandler with a mock req/res so we control the peer address.
function call(handler, { method = "POST", path, headers = {}, body, remote = "127.0.0.1" }) {
  const req = new EventEmitter();
  req.method = method;
  req.url = path;
  req.headers = { host: "127.0.0.1", ...headers };
  req.socket = { remoteAddress: remote };
  req.destroy = () => {};
  const res = {
    statusCode: 200,
    _headers: {},
    setHeader(k, v) {
      this._headers[k.toLowerCase()] = v;
    },
    end(buf) {
      this._body = buf ? buf.toString() : "";
      if (this._resolve) this._resolve();
    },
    on() {},
  };
  const done = new Promise((r) => (res._resolve = r));
  handler(req, res);
  setImmediate(() => {
    if (body !== undefined) req.emit("data", Buffer.from(body));
    req.emit("end");
  });
  return done.then(() => ({ status: res.statusCode, body: res._body ? JSON.parse(res._body) : null }));
}

test("nil lease manager → 503", async () => {
  const handler = createHandler(mkDeps(undefined));
  const body = JSON.stringify({ port: "/dev/ttyACM0", ttl_ms: 20000 });
  const r = await call(handler, { path: LEASE_PATH, headers: signHeaders(LEASE_PATH, Buffer.from(body)), body });
  assert.equal(r.status, 503);
});

test("non-loopback peer → 403 (before auth)", async () => {
  const handler = createHandler(mkDeps(new LeaseManager(new NopController(), 10000)));
  const body = JSON.stringify({ port: "/dev/ttyACM0", ttl_ms: 20000 });
  const r = await call(handler, {
    path: LEASE_PATH,
    headers: signHeaders(LEASE_PATH, Buffer.from(body)),
    body,
    remote: "10.0.0.5",
  });
  assert.equal(r.status, 403);
});

test("missing body digest → 401 (no v2 fallback)", async () => {
  const handler = createHandler(mkDeps(new LeaseManager(new NopController(), 10000)));
  const body = JSON.stringify({ port: "/dev/ttyACM0", ttl_ms: 20000 });
  const r = await call(handler, {
    path: LEASE_PATH,
    headers: { "content-type": "application/json", "content-length": String(body.length) },
    body,
  });
  assert.equal(r.status, 401);
});

test("wrong method → 405", async () => {
  const handler = createHandler(mkDeps(new LeaseManager(new NopController(), 10000)));
  const r = await call(handler, { method: "GET", path: LEASE_PATH });
  assert.equal(r.status, 405);
});

test("grant → 409 on second → renew → release → 410 on renew after release", async () => {
  const mgr = new LeaseManager(new NopController(), 10000);
  const handler = createHandler(mkDeps(mgr));
  const port = fakePort();

  const grantBody = JSON.stringify({ port, ttl_ms: 20000 });
  const g = await call(handler, { path: LEASE_PATH, headers: signHeaders(LEASE_PATH, Buffer.from(grantBody)), body: grantBody });
  assert.equal(g.status, 200);
  assert.match(g.body.lease_id, /^[0-9a-f]{32}$/);
  // Field names are the cross-runtime contract (PROVISION_WIRE §6): ttl_ms (not
  // granted_ms), plus the canonical port echoed back. 20000 clamps to the
  // manager's 10000 max.
  assert.equal(g.body.ttl_ms, 10_000);
  assert.equal(g.body.port, realpathSync(port));
  assert.equal(typeof g.body.expires_unix_ms, "number");
  const id = g.body.lease_id;

  // Second grant on the same canonical port → 409 with the §6 body shape.
  const g2 = await call(handler, { path: LEASE_PATH, headers: signHeaders(LEASE_PATH, Buffer.from(grantBody)), body: grantBody });
  assert.equal(g2.status, 409);
  assert.deepEqual(g2.body, { error: "busy", holder: "lease" });

  // Renew → 200. The body carries ONLY the id; the leader re-applies the TTL it
  // granted, so the response echoes that clamped 10000.
  const renewBody = JSON.stringify({ lease_id: id });
  const rn = await call(handler, { path: LEASE_RENEW_PATH, headers: signHeaders(LEASE_RENEW_PATH, Buffer.from(renewBody)), body: renewBody });
  assert.equal(rn.status, 200);
  assert.equal(rn.body.ttl_ms, 10_000);
  assert.equal(typeof rn.body.expires_unix_ms, "number");

  // Release → 200 {ok:true}.
  const relBody = JSON.stringify({ lease_id: id });
  const rl = await call(handler, { path: LEASE_RELEASE_PATH, headers: signHeaders(LEASE_RELEASE_PATH, Buffer.from(relBody)), body: relBody });
  assert.equal(rl.status, 200);
  assert.equal(rl.body.ok, true);

  // Renew after release → 410 Gone.
  const rn2 = await call(handler, { path: LEASE_RENEW_PATH, headers: signHeaders(LEASE_RENEW_PATH, Buffer.from(renewBody)), body: renewBody });
  assert.equal(rn2.status, 410);
});

test("ttl_ms outside int64 → 400 (Go-parity, not a silent clamp)", async () => {
  // Go unmarshals ttl_ms into an int64, so a value it answers 400 for must not
  // quietly clamp to the max here — the same request has to get the same answer
  // whichever runtime happens to be leader.
  const handler = createHandler(mkDeps(new LeaseManager(new NopController(), 10000)));
  const body = JSON.stringify({ port: fakePort(), ttl_ms: 2 ** 63 });
  const r = await call(handler, { path: LEASE_PATH, headers: signHeaders(LEASE_PATH, Buffer.from(body)), body });
  assert.equal(r.status, 400);
});

test("bad auth signature → 401", async () => {
  const handler = createHandler(mkDeps(new LeaseManager(new NopController(), 10000)));
  const body = JSON.stringify({ port: "/dev/ttyACM0", ttl_ms: 20000 });
  const headers = signHeaders(LEASE_PATH, Buffer.from(body));
  headers["x-tmon-signature"] = "0".repeat(64); // wrong
  const r = await call(handler, { path: LEASE_PATH, headers, body });
  assert.equal(r.status, 401);
});

// Cross-check: the real LeaseClient signs requests a real broker accepts over a
// loopback socket, and grant/409/renew/release wire up end-to-end. Mirrors Go's
// leaseclient_linux_test (minus the actual serial open, which needs a pty).
test("LeaseClient signs requests the broker accepts (real socket)", async () => {
  const mgr = new LeaseManager(new NopController(), 10000);
  const handler = createHandler(mkDeps(mgr));
  const server = createServer(handler);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port: httpPort } = server.address();
  const baseURL = `http://127.0.0.1:${httpPort}`;
  const client = new LeaseClient({ baseURL, psk: PSK });
  const devPort = fakePort();
  try {
    const { id, needLease } = await client._acquire(devPort, 20000);
    assert.equal(needLease, true);
    assert.match(id, /^[0-9a-f]{32}$/);

    // Second acquire on the same port → busy.
    await assert.rejects(() => client._acquire(devPort, 20000), LeaseBusyError);

    await client._renew(id); // resolves (200) — renew takes no TTL
    await client._releaseBounded(id); // resolves (200)
    await assert.rejects(() => client._renew(id)); // 410 after release
  } finally {
    server.close();
  }
});

// The end-to-end test above cannot prove the renew SHAPE: both ends are ours, so
// a ttl_ms neither side reads would still pass. Assert the serialized bytes —
// this is what a Go leader parses, and a stray ttl_ms there is exactly the bug
// that clamps a lease to the 1 s floor mid-session (PROVISION_WIRE §6).
test("LeaseClient renew body carries ONLY lease_id", async () => {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({ path: req.url, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ttl_ms: 10000, expires_unix_ms: Date.now() + 10000 }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const client = new LeaseClient({
      baseURL: `http://127.0.0.1:${server.address().port}`,
      psk: PSK,
    });
    await client._renew("a".repeat(32));
    assert.equal(seen.length, 1);
    assert.equal(seen[0].path, LEASE_RENEW_PATH);
    assert.deepEqual(JSON.parse(seen[0].body), { lease_id: "a".repeat(32) });
  } finally {
    server.close();
  }
});
