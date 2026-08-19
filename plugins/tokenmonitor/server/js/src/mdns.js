// Advertise the tokenmonitor-mcp broker on the local network.
//
// Wire-compatible with tokenmonitor-mcp/internal/mdns/publish.go and the Python
// publisher: service type `_tmon-broker._tcp`, TXT keys `v`, `runtime`
// and `devs`. See compat/mdns.md for the contract.
//
// Identity vs location: the PSK is the cryptographic identity of the
// device↔broker pair; mDNS only answers "where is the broker right
// now?". device_id is public (it travels in X-Tmon-Device on every
// poll), so listing IDs in TXT leaks nothing — it just lets the device
// filter "is my broker on this LAN?".

import { createHash } from "node:crypto";
import { hostname, networkInterfaces } from "node:os";

import bonjourPkg from "bonjour-service";

const { Bonjour } = bonjourPkg;

export const SERVICE_TYPE = "tmon-broker";
export const RUNTIME = "js";
const REFRESH_MS = 30_000;

// Idle-liveness watchdog. If no device has hit the broker for IDLE_MS we
// re-announce, on the theory that our own advertisement is what went stale —
// an interface that flapped, a wedged mDNS stack, an announcement lost in a
// lossy multicast domain. Bounded by a doubling backoff so a device that is
// simply switched off does not have us multicasting every 30 s forever. The
// backoff mirrors the device's own discovery backoff (see
// firmware/components/core/src/tmon_discovery.c) — same shape, so the two
// sides of this recovery read the same way. Wire-compatible with the Go and
// Python publishers.
const IDLE_MS = 30_000;
const REANNOUNCE_MIN_MS = 30_000;
const REANNOUNCE_MAX_MS = 300_000;

// Wait after `attempts` idle re-announcements: the floor for the first,
// doubling to the ceiling thereafter.
function reannounceGap(attempts) {
  let gap = REANNOUNCE_MIN_MS;
  for (let i = 1; i < attempts; i++) {
    if (gap >= REANNOUNCE_MAX_MS / 2) return REANNOUNCE_MAX_MS;
    gap *= 2;
  }
  return gap;
}

// Pure decision behind the watchdog. `lastReq` must already be normalised by
// the caller (the broker's start time stands in before any device has ever hit
// us); `lastReannounce` of 0 means "never". All times are epoch milliseconds.
//
// devs === 0 means no device is registered here, so there is nobody our
// advertisement could help and no reason to put packets on the LAN.
function shouldReannounce(now, lastReq, lastReannounce, attempts, devs) {
  if (devs === 0) return false;
  if (now - lastReq < IDLE_MS) return false;
  if (!lastReannounce) return true;
  return now - lastReannounce >= reannounceGap(attempts);
}
const MAX_TXT = 255;

function hostShort() {
  let h = "";
  try { h = hostname() || ""; } catch { h = ""; }
  if (!h) return "anon00";
  return createHash("sha256").update(h).digest("hex").slice(0, 6);
}

// Interface name prefixes the WiFi device cannot reach. Kept in sync
// with the Go and Python publishers; see CLAUDE.md for the rationale.
const VIRTUAL_IFACE_PREFIXES = [
  "docker", "br-", "veth", "virbr", "vnet", "tun", "tap",
  "vmnet", "tailscale", "wg", "zt",
];

function isVirtualIface(name) {
  return VIRTUAL_IFACE_PREFIXES.some(p => name.startsWith(p));
}

function physicalIPv4s() {
  const out = [];
  const ifaces = networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    if (isVirtualIface(name)) continue;
    for (const i of ifaces[name] || []) {
      if (i.family !== "IPv4" || i.internal) continue;
      out.push(i.address);
    }
  }
  return out;
}

function isLoopback(bind) {
  if (!bind || bind === "0.0.0.0" || bind === "::") return false;
  // crude but enough for the cases we care about
  return bind === "127.0.0.1" || bind === "localhost" || bind.startsWith("127.") || bind === "::1";
}

function buildTxt(devs) {
  const sorted = [...new Set(devs)].sort();
  let joined = sorted.join(",");
  const cap = MAX_TXT - "devs=".length;
  if (joined.length > cap) {
    joined = joined.slice(0, cap);
    const cut = joined.lastIndexOf(",");
    if (cut > 0) joined = joined.slice(0, cut);
  }
  // bonjour-service serialises this object into TXT key=value entries.
  return { v: "1", runtime: RUNTIME, devs: joined };
}

function txtEqual(a, b) {
  return a.v === b.v && a.runtime === b.runtime && a.devs === b.devs;
}

// A records to advertise. When bind is 0.0.0.0/empty, pin to the
// LAN-reachable physical IPv4s so we don't advertise Docker bridges and
// VPN tunnels that the device can't route to. A literal bind never
// changes at runtime; the wildcard set is re-read on every refresh tick.
function advertisedIps(bind) {
  return (!bind || bind === "0.0.0.0" || bind === "::")
    ? physicalIPv4s()
    : [bind];
}

/**
 * Publisher owns the Bonjour service and the refresh interval. Construct
 * via `start(...)`; release with `close()`. Both are idempotent.
 */
export class Publisher {
  constructor() {
    this._bonjour = null;
    this._service = null;
    this._timer = null;
    this._lastTxt = null;
    this._lastIps = null;   // joined advertised-IP list; null = nothing published
    this._instance = null;
    this._port = 0;
    // Idle-liveness watchdog state; see _takeIdleReannounce.
    this._lastReq = null;
    this._startedAt = 0;
    this._lastSeenReq = 0;   // _lastReq as of the previous check
    this._idleAttempts = 0;
    this._lastReannounce = 0;
  }

  // Is an idle re-announce due right now? When it is, consume it: the caller
  // must go on to republish. Returns [fired, idleForMs] for the log line. Any
  // request seen since the previous call resets the backoff to the floor,
  // however old that request is by now.
  _takeIdleReannounce(now, devs) {
    if (typeof this._lastReq !== "function") return [false, 0];
    let lastReq = this._lastReq();
    if (!lastReq) lastReq = this._startedAt;
    // Reset on a request we had not seen before, not on "the request we can
    // see is recent". The loop ticks at the same 30 s as the threshold, so a
    // request landing just after a tick is already 30 s old by the next one:
    // keying the reset on freshness would miss it to scheduling jitter and
    // leave the backoff out at five minutes.
    if (lastReq !== this._lastSeenReq) {
      this._lastSeenReq = lastReq;
      this._idleAttempts = 0;
      this._lastReannounce = 0;
    }
    if (!shouldReannounce(now, lastReq, this._lastReannounce, this._idleAttempts, devs)) {
      return [false, 0];
    }
    this._idleAttempts += 1;
    this._lastReannounce = now;
    return [true, now - lastReq];
  }

  // Create a fresh Bonjour instance (multicast sockets bind to the
  // current interfaces here — reusing one across a network change would
  // keep stale group memberships) and publish. Records _lastTxt/_lastIps
  // only on success; throws on failure with everything torn back down.
  _openAndPublish(ips, txt) {
    this._bonjour = new Bonjour();
    try {
      const opts = { name: this._instance, type: SERVICE_TYPE, port: this._port, txt };
      if (ips.length > 0) opts.host = ips[0];
      this._service = this._bonjour.publish(opts);
    } catch (e) {
      try { this._bonjour.destroy(); } catch {}
      this._bonjour = null;
      this._service = null;
      throw e;
    }
    this._lastTxt = txt;
    this._lastIps = ips.join(",");
  }

  async _teardown() {
    if (this._service && typeof this._service.stop === "function") {
      await new Promise((resolve) => {
        try { this._service.stop(() => resolve()); }
        catch { resolve(); }
      });
    }
    this._service = null;
    if (this._bonjour) {
      try { this._bonjour.destroy(); } catch {}
      this._bonjour = null;
    }
  }

  // One refresh tick, extracted from the interval so a test can drive it.
  // Each of the three causes below must independently produce a republish;
  // an `|| idle` quietly dropped from the condition is invisible to a test
  // that only exercises _takeIdleReannounce.
  async _tick(lister, logger, bind) {
    let cur = [];
    try { cur = lister.listDeviceIds(); }
    catch (e) { logger?.warn?.(`mdns: refresh device list: ${e.message}`); return; }
    const next = buildTxt(cur);

    // Interface addresses changed (DHCP renew, network switch): the
    // pinned A record and the multicast sockets are both stale — tear
    // the whole advertisement down and republish fresh. This is what
    // lets a device rediscover the broker after the host moves LANs.
    // Liveness: nobody has talked to us in a while, so re-announce in case
    // it is our own advertisement that went stale. Consumed here so the
    // backoff advances exactly once per tick whatever the republish does.
    const [idle, idleForMs] = this._takeIdleReannounce(Date.now(), cur.length);
    if (idle) logger?.info?.(`mdns: no device traffic for ${Math.floor(idleForMs / 1000)}s, re-announcing`);

    const ips = advertisedIps(bind);
    if (idle || ips.join(",") !== this._lastIps) {
      const why = idle ? "idle" : `addresses changed (${this._lastIps || "none"} -> ${ips.join(",") || "none"})`;
      logger?.info?.(`mdns: ${why}, republishing`);
      await this._teardown();
      try {
        this._openAndPublish(ips, next);
        logger?.info?.(`mdns: republished, ips=${ips.join(",")}`);
      } catch (e) {
        // Leave _lastIps null so the next tick retries the republish. That
        // null is also what keeps _lastTxt = null safe: txtEqual would throw
        // on it, but a null _lastIps can never equal a joined IP string, so
        // the branch above always wins before the comparison is reached.
        // This is the JS spelling of Go's `srv == nil` and Python's
        // `self._zc is None` retry term.
        this._lastIps = null;
        this._lastTxt = null;
        logger?.warn?.(`mdns: republish: ${e.message}`);
      }
      return;
    }

    if (txtEqual(next, this._lastTxt)) return;
    this._lastTxt = next;
    try {
      // bonjour-service exposes an `updateTxt` method on the published
      // service handle; if for some reason it's not available, fall
      // back to unpublish+republish so the change still propagates.
      if (this._service && typeof this._service.updateTxt === "function") {
        this._service.updateTxt(next);
      } else if (this._service && typeof this._service.stop === "function") {
        this._service.stop(() => {
          this._service = this._bonjour.publish({ name: this._instance, type: SERVICE_TYPE, port: this._port, txt: next });
        });
      }
      logger?.info?.(`mdns: TXT updated, devs=${cur.length}`);
    } catch (e) {
      logger?.warn?.(`mdns: update TXT: ${e.message}`);
    }
  }

  // `lastReq` reports when a device last hit the broker (epoch milliseconds,
  // 0 for never); it drives the idle re-announce watchdog and may be omitted
  // to disable it.
  static async start(bind, port, lister, logger, lastReq) {
    const pub = new Publisher();
    if (isLoopback(bind)) {
      logger?.info?.(`mdns: bind=${bind} is loopback, skipping broker advertisement`);
      return pub;
    }
    if (!lister || typeof lister.listDeviceIds !== "function") {
      throw new Error("mdns: registry without listDeviceIds()");
    }

    let devs = [];
    try { devs = lister.listDeviceIds(); }
    catch (e) { logger?.warn?.(`mdns: initial device list: ${e.message}`); devs = []; }
    const txt = buildTxt(devs);

    pub._instance = `tmon-broker-${hostShort()}`;
    pub._port = port;
    pub._lastReq = typeof lastReq === "function" ? lastReq : null;
    pub._startedAt = Date.now();
    const explicit = advertisedIps(bind);
    pub._openAndPublish(explicit, txt);
    logger?.info?.(`mdns: published ${pub._instance}._${SERVICE_TYPE}._tcp.local. port=${port} devs=${devs.length} ips=${explicit.join(",")}`);

    pub._timer = setInterval(() => { void pub._tick(lister, logger, bind); }, REFRESH_MS);
    if (typeof pub._timer.unref === "function") pub._timer.unref();
    return pub;
  }

  async close() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    await this._teardown();
  }
}

// Exported for tests.
export const _internal = { buildTxt, isLoopback, hostShort, txtEqual, advertisedIps,
                          reannounceGap, shouldReannounce };
