import { test } from "node:test";
import assert from "node:assert/strict";

import { LeaseManager, NopController, LeaseBusyError, LeaseUnknownError, randomLeaseID } from "../src/usbprov/lease.js";

// fakeController records suspend/resume calls per port and can fail a port.
class FakeController {
  constructor() {
    this.suspend = new Map();
    this.resume = new Map();
    this.failPort = "";
  }
  async suspendPort(p) {
    if (p === this.failPort) throw new Error("cannot yield");
    this.suspend.set(p, (this.suspend.get(p) || 0) + 1);
  }
  resumePort(p) {
    this.resume.set(p, (this.resume.get(p) || 0) + 1);
  }
  counts(p) {
    return [this.suspend.get(p) || 0, this.resume.get(p) || 0];
  }
}

// newTestManager builds a manager with a controllable clock + deterministic ids.
function newTestManager(ctrl) {
  const clk = { t: 1_700_000_000_000 };
  const m = new LeaseManager(ctrl, 10_000);
  m.now = () => clk.t;
  let n = 0;
  m.newID = () => "lease" + ++n;
  return { m, clk };
}

test("grant suspends, release resumes (idempotent)", async () => {
  const ctrl = new FakeController();
  const { m } = newTestManager(ctrl);
  const { id, grantedMs } = await m.Grant("/dev/ttyACM0", 5000);
  assert.equal(grantedMs, 5000);
  assert.deepEqual(ctrl.counts("/dev/ttyACM0"), [1, 0]);
  m.Release(id);
  assert.deepEqual(ctrl.counts("/dev/ttyACM0"), [1, 1]);
  m.Release(id); // idempotent
  assert.deepEqual(ctrl.counts("/dev/ttyACM0"), [1, 1]);
});

test("second grant on same port is busy; distinct port is free", async () => {
  const { m } = newTestManager(new FakeController());
  await m.Grant("/dev/ttyACM0", 1000);
  await assert.rejects(() => m.Grant("/dev/ttyACM0", 1000), LeaseBusyError);
  await m.Grant("/dev/ttyACM1", 1000); // ok
});

test("TTL clamped to [min,max]", async () => {
  const { m } = newTestManager(new FakeController());
  const a = await m.Grant("/dev/ttyACM0", 3600_000);
  assert.equal(a.grantedMs, 10_000); // max
  const b = await m.Grant("/dev/ttyACM1", 1);
  assert.equal(b.grantedMs, 1000); // min
});

test("renew extends then rejects after expiry (frees port)", async () => {
  const ctrl = new FakeController();
  const { m, clk } = newTestManager(ctrl);
  const { id } = await m.Grant("/dev/ttyACM0", 5000);
  clk.t += 3000;
  // Renew carries no TTL: the lease re-applies its ORIGINAL granted 5000 ms,
  // so the deadline moves to t+3000+5000 = +8000.
  assert.equal(m.Renew(id).grantedMs, 5000);
  clk.t += 6000; // t=+9000 > +8000
  assert.throws(() => m.Renew(id), LeaseUnknownError);
  assert.deepEqual(ctrl.counts("/dev/ttyACM0"), [1, 1]); // resumed on failed renew
});

test("renew re-applies the CLAMPED grant, never a caller TTL", async () => {
  // A renew must re-apply what the lease was GRANTED, not what was asked for:
  // a request clamped down must stay clamped, and no renew may shrink the
  // window. Mirrors Go's TestLease_RenewExtendsAndRejectsExpired.
  const { m, clk } = newTestManager(new FakeController());
  const { id, grantedMs } = await m.Grant("/dev/ttyACM0", 3600_000);
  assert.equal(grantedMs, 10_000); // clamped to this manager's max
  clk.t += 9000;
  assert.equal(m.Renew(id).grantedMs, 10_000); // the clamped grant, not 3600 s
  clk.t += 9000; // deadline is +19000; still alive at +18000
  assert.equal(m.Renew(id).grantedMs, 10_000);
});

test("reapExpired resumes only expired ports; reaped port is grantable", async () => {
  const ctrl = new FakeController();
  const { m, clk } = newTestManager(ctrl);
  await m.Grant("/dev/ttyACM0", 2000);
  await m.Grant("/dev/ttyACM1", 8000);
  clk.t += 3000;
  assert.equal(m.ReapExpired(), 1);
  assert.equal(ctrl.counts("/dev/ttyACM0")[1], 1);
  assert.equal(ctrl.counts("/dev/ttyACM1")[1], 0);
  await m.Grant("/dev/ttyACM0", 1000); // re-grantable
});

test("grant fails if controller cannot yield; port stays free", async () => {
  const ctrl = new FakeController();
  ctrl.failPort = "/dev/ttyACM0";
  const { m } = newTestManager(ctrl);
  await assert.rejects(() => m.Grant("/dev/ttyACM0", 1000));
  ctrl.failPort = "";
  await m.Grant("/dev/ttyACM0", 1000); // free after failed grant
});

// A slow suspend on one port must not block a Grant/Release on another, and a
// concurrent Grant on the still-reserving port must fail busy, not block.
test("slow suspend does not block other ports", async () => {
  let releaseGate;
  const gate = new Promise((r) => (releaseGate = r));
  let entered;
  const enteredP = new Promise((r) => (entered = r));
  const ctrl = {
    suspend: new Map(),
    resume: new Map(),
    async suspendPort(p) {
      if (p === "/dev/ttyACM0") {
        entered();
        await gate;
      }
      this.suspend.set(p, (this.suspend.get(p) || 0) + 1);
    },
    resumePort(p) {
      this.resume.set(p, (this.resume.get(p) || 0) + 1);
    },
  };
  const m = new LeaseManager(ctrl, 10_000);

  const gatedGrant = m.Grant("/dev/ttyACM0", 5000);
  await enteredP;

  // Unrelated port leases + releases fast.
  const id1 = (await m.Grant("/dev/ttyACM1", 1000)).id;
  m.Release(id1);

  // Concurrent same-port grant reports busy, not block.
  await assert.rejects(() => m.Grant("/dev/ttyACM0", 1000), LeaseBusyError);

  releaseGate();
  await gatedGrant; // commits
});

test("randomLeaseID is 32 lowercase hex and unique", () => {
  const seen = new Set();
  for (let i = 0; i < 100; i++) {
    const id = randomLeaseID();
    assert.match(id, /^[0-9a-f]{32}$/);
    assert.equal(seen.has(id), false);
    seen.add(id);
  }
});

test("NopController leaves every port free", async () => {
  const m = new LeaseManager(new NopController(), 0);
  const { id } = await m.Grant("/dev/ttyACM0", 5000);
  m.Release(id);
});
