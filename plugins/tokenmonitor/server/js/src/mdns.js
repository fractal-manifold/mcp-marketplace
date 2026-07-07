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

  static async start(bind, port, lister, logger) {
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
    const explicit = advertisedIps(bind);
    pub._openAndPublish(explicit, txt);
    logger?.info?.(`mdns: published ${pub._instance}._${SERVICE_TYPE}._tcp.local. port=${port} devs=${devs.length} ips=${explicit.join(",")}`);

    pub._timer = setInterval(async () => {
      let cur = [];
      try { cur = lister.listDeviceIds(); }
      catch (e) { logger?.warn?.(`mdns: refresh device list: ${e.message}`); return; }
      const next = buildTxt(cur);

      // Interface addresses changed (DHCP renew, network switch): the
      // pinned A record and the multicast sockets are both stale — tear
      // the whole advertisement down and republish fresh. This is what
      // lets a device rediscover the broker after the host moves LANs.
      const ips = advertisedIps(bind);
      if (ips.join(",") !== pub._lastIps) {
        logger?.info?.(`mdns: addresses changed (${pub._lastIps || "none"} -> ${ips.join(",") || "none"}), republishing`);
        await pub._teardown();
        try {
          pub._openAndPublish(ips, next);
          logger?.info?.(`mdns: republished, ips=${ips.join(",")}`);
        } catch (e) {
          // Leave _lastIps null so the next tick retries the republish.
          pub._lastIps = null;
          pub._lastTxt = null;
          logger?.warn?.(`mdns: republish: ${e.message}`);
        }
        return;
      }

      if (txtEqual(next, pub._lastTxt)) return;
      pub._lastTxt = next;
      try {
        // bonjour-service exposes an `updateTxt` method on the published
        // service handle; if for some reason it's not available, fall
        // back to unpublish+republish so the change still propagates.
        if (pub._service && typeof pub._service.updateTxt === "function") {
          pub._service.updateTxt(next);
        } else if (pub._service && typeof pub._service.stop === "function") {
          pub._service.stop(() => {
            pub._service = pub._bonjour.publish({ name: pub._instance, type: SERVICE_TYPE, port, txt: next });
          });
        }
        logger?.info?.(`mdns: TXT updated, devs=${cur.length}`);
      } catch (e) {
        logger?.warn?.(`mdns: update TXT: ${e.message}`);
      }
    }, REFRESH_MS);
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
export const _internal = { buildTxt, isLoopback, hostShort, txtEqual, advertisedIps };
