import { test } from "node:test";
import assert from "node:assert/strict";

import { _internal, Publisher } from "../src/mdns.js";
import { State } from "../src/state.js";

const { buildTxt, txtEqual, isLoopback, advertisedIps } = _internal;

test("buildTxt dedupes, sorts and tags runtime", () => {
  const txt = buildTxt(["bb", "aa", "bb"]);
  assert.equal(txt.v, "1");
  assert.equal(txt.runtime, "js");
  assert.equal(txt.devs, "aa,bb");
});

test("buildTxt caps devs at a whole-id boundary under 255 bytes", () => {
  // 8-hex ids + comma = 9 bytes each; 40 ids = 359 joined > 250 cap.
  const ids = Array.from({ length: 40 }, (_, i) => i.toString(16).padStart(8, "0"));
  const txt = buildTxt(ids);
  assert.ok(txt.devs.length <= 255 - "devs=".length);
  assert.ok(!txt.devs.endsWith(","));
  // Every surviving entry is a complete 8-char id.
  for (const id of txt.devs.split(",")) assert.equal(id.length, 8);
});

test("txtEqual compares the three published keys", () => {
  const a = buildTxt(["aa"]);
  assert.ok(txtEqual(a, buildTxt(["aa"])));
  assert.ok(!txtEqual(a, buildTxt(["bb"])));
});

test("isLoopback: wildcard binds are publishable, loopback is not", () => {
  assert.equal(isLoopback(""), false);
  assert.equal(isLoopback("0.0.0.0"), false);
  assert.equal(isLoopback("::"), false);
  assert.equal(isLoopback("127.0.0.1"), true);
  assert.equal(isLoopback("localhost"), true);
  assert.equal(isLoopback("::1"), true);
  assert.equal(isLoopback("192.168.1.142"), false);
});

test("advertisedIps: literal bind is pinned verbatim", () => {
  assert.deepEqual(advertisedIps("192.168.1.142"), ["192.168.1.142"]);
});

test("advertisedIps: wildcard bind re-reads interfaces each call", () => {
  // Can't fake OS interfaces here; assert shape + no virtual/loopback.
  const ips = advertisedIps("0.0.0.0");
  assert.ok(Array.isArray(ips));
  for (const ip of ips) {
    assert.match(ip, /^\d+\.\d+\.\d+\.\d+$/);
    assert.ok(!ip.startsWith("127."));
  }
});

// --- idle-liveness watchdog -------------------------------------------
//
// The device recovers from a moved broker by querying us (see
// firmware/components/net/src/cred_client.c). This watchdog covers the other
// failure: our own advertisement went stale — flapping interface, wedged mDNS
// stack, an announcement lost in a lossy multicast domain — so no query of
// theirs is answered. Everything below is about not turning that into a
// permanent multicast beacon aimed at a device that is simply off.
// Mirrors the Go and Python idle-watchdog tests.

const { reannounceGap, shouldReannounce } = _internal;

test("reannounceGap: floor, then doubling to the ceiling", () => {
  const want = [30_000, 30_000, 60_000, 120_000, 240_000, 300_000, 300_000];
  assert.deepEqual(want.map((_, n) => reannounceGap(n)), want);
});

test("shouldReannounce needs an idle broker with devices", () => {
  const now = 1_700_000_000_000;
  assert.equal(shouldReannounce(now, now - 3_600_000, 0, 0, 0), false,
    "no registered device: nobody our advertisement could help");
  assert.equal(shouldReannounce(now, now - 29_000, 0, 0, 1), false,
    "29 s of quiet is not idle yet");
  assert.equal(shouldReannounce(now, now - 30_000, 0, 0, 1), true);
});

test("shouldReannounce respects the backoff", () => {
  const now = 1_700_000_000_000;
  const idle = now - 3_600_000;
  assert.equal(shouldReannounce(now, idle, now - 29_000, 1, 1), false);
  assert.equal(shouldReannounce(now, idle, now - 30_000, 1, 1), true);
  // Third re-announce onwards the gap doubles: 60 s, not 30.
  assert.equal(shouldReannounce(now, idle, now - 59_000, 2, 1), false);
  assert.equal(shouldReannounce(now, idle, now - 60_000, 2, 1), true);
});

test("takeIdleReannounce backs off, then resets when traffic returns", () => {
  let lastReq = 1_700_000_000_000;
  const pub = new Publisher();
  pub._lastReq = () => lastReq;
  pub._startedAt = lastReq;

  let now = lastReq;
  assert.equal(pub._takeIdleReannounce(now + 29_000, 1)[0], false);

  now += 30_000;
  const [fired, idleFor] = pub._takeIdleReannounce(now, 1);
  assert.equal(fired, true);
  assert.equal(idleFor, 30_000);

  for (const gap of [30_000, 60_000, 120_000, 240_000, 300_000, 300_000]) {
    assert.equal(pub._takeIdleReannounce(now + gap - 1_000, 1)[0], false,
      `fired one second early inside a ${gap} ms gap`);
    now += gap;
    assert.equal(pub._takeIdleReannounce(now, 1)[0], true,
      `did not fire at the end of a ${gap} ms gap`);
  }

  // A device comes back: the next tick must find the watchdog disarmed and
  // back at the floor, not still out at five minutes.
  lastReq = now + 1_000;
  assert.equal(pub._takeIdleReannounce(now + 2_000, 1)[0], false);
  assert.equal(pub._takeIdleReannounce(now + 32_000, 1)[0], true);
});

test("takeIdleReannounce never fires without devices or a reader", () => {
  const lastReq = 1_700_000_000_000;
  const pub = new Publisher();
  pub._lastReq = () => lastReq;
  pub._startedAt = lastReq;
  assert.equal(pub._takeIdleReannounce(lastReq + 3_600_000, 0)[0], false);

  // The loopback no-op publisher has no reader at all.
  assert.equal(new Publisher()._takeIdleReannounce(lastReq + 3_600_000, 3)[0], false);
});

test("takeIdleReannounce measures from start before any request", () => {
  // A broker that has never been hit still has registered devices — one may be
  // booting right now with a stale URL. Idle is measured from start.
  const started = 1_700_000_000_000;
  const pub = new Publisher();
  pub._lastReq = () => 0;
  pub._startedAt = started;
  assert.equal(pub._takeIdleReannounce(started + 29_000, 1)[0], false);
  assert.equal(pub._takeIdleReannounce(started + 30_000, 1)[0], true);
});

test("takeIdleReannounce resets on traffic seen only between ticks", () => {
  // The loop ticks at the same 30 s as the idle threshold, so a request that
  // lands just after a tick is already ~30 s old when the next one looks at
  // it. Resetting on "is this request recent?" would miss it to scheduling
  // jitter and leave the backoff out at its five-minute ceiling.
  let lastReq = 1_700_000_000_000;
  const pub = new Publisher();
  pub._lastReq = () => lastReq;
  pub._startedAt = lastReq;

  let now = lastReq + 30_000;
  for (const gap of [0, 30_000, 60_000, 120_000, 240_000, 300_000]) {
    now += gap;
    assert.equal(pub._takeIdleReannounce(now, 1)[0], true, `setup: expected a fire at +${gap}`);
  }

  // A device hits us, and the next tick lands 31 s later — never inside the
  // threshold, so only the "have I seen this request before?" test catches it.
  lastReq = now + 5_000;
  assert.equal(pub._takeIdleReannounce(lastReq + 31_000, 1)[0], true,
    "traffic seen only between ticks must reset the backoff to the floor");
});

// --- the refresh tick actually republishes -------------------------------
// _takeIdleReannounce returning true proves nothing on its own: the tick has
// to go on and republish. Each of the three causes is exercised alone, so an
// `|| idle` dropped from the condition fails exactly one of them.

function tickHarness({ lastIps, lastReq }) {
  const pub = new Publisher();
  pub._instance = "tmon-broker-test";
  pub._port = 8765;
  pub._lastIps = lastIps;
  pub._lastTxt = buildTxt(["aa11bb22"]);
  pub._lastReq = lastReq;
  pub._startedAt = lastReq ? lastReq() : 0;
  const calls = { open: 0, teardown: 0 };
  pub._openAndPublish = (ips, txt) => {
    calls.open += 1;
    pub._lastIps = ips.join(",");
    pub._lastTxt = txt;
  };
  pub._teardown = async () => { calls.teardown += 1; };
  return { pub, calls };
}

const BIND = "192.168.1.10";
const LISTER = { listDeviceIds: () => ["aa11bb22"] };

test("tick republishes when the idle watchdog fires", async () => {
  const { pub, calls } = tickHarness({ lastIps: BIND, lastReq: () => Date.now() - 60_000 });
  await pub._tick(LISTER, null, BIND);
  assert.equal(calls.open, 1, "an idle tick must republish");
  assert.equal(calls.teardown, 1, "and tear the old advertisement down first");
});

test("tick republishes when the advertised addresses changed", async () => {
  const { pub, calls } = tickHarness({ lastIps: "10.0.0.1", lastReq: () => Date.now() });
  await pub._tick(LISTER, null, BIND);
  assert.equal(calls.open, 1, "a changed address set must republish");
});

test("tick republishes when nothing is published yet", async () => {
  const { pub, calls } = tickHarness({ lastIps: null, lastReq: () => Date.now() });
  await pub._tick(LISTER, null, BIND);
  assert.equal(calls.open, 1, "a down publisher must be retried");
});

test("tick does not republish when idle, addresses and TXT are all unchanged", async () => {
  const { pub, calls } = tickHarness({ lastIps: BIND, lastReq: () => Date.now() });
  await pub._tick(LISTER, null, BIND);
  assert.equal(calls.open, 0, "a quiet tick must not republish");
  assert.equal(calls.teardown, 0);
});

// --- State feeds the watchdog in milliseconds ----------------------------
// Lives here rather than beside State because the millisecond precision
// exists only for this watchdog: the threshold and the tick are both 30 s, so
// truncating to whole seconds can move the crossing a whole tick.

test("lastRequestAt is 0 until a request arrives", () => {
  assert.equal(new State().lastRequestAt(), 0);
});

test("lastRequestAt keeps sub-second precision", () => {
  const st = new State();
  // Truncating to whole seconds pushes the stamp BACK, below the instant the
  // call was made — which is what let the watchdog cross its threshold a
  // whole tick early. Anything at or after `before` cannot have been floored.
  const before = Date.now();
  st.recordRequest("1.2.3.4", 200);
  assert.ok(st.lastRequestAt() >= before,
    "must not report a request as older than the moment it was recorded");
  assert.ok(st.lastRequestAt() <= Date.now());
});

test("an explicit epoch-second `when` still yields milliseconds", () => {
  const st = new State();
  st.recordRequest("1.2.3.4", 200, 1_700_000_000);
  assert.equal(st.lastRequestAt(), 1_700_000_000_000);
});
