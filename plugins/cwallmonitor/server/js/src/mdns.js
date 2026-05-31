// Advertise the cwm-mcp broker on the local network.
//
// Wire-compatible with cwm-mcp/internal/mdns/publish.go and the Python
// publisher: service type `_cwm-broker._tcp`, TXT keys `v`, `runtime`
// and `devs`. See compat/mdns.md for the contract.
//
// Identity vs location: the PSK is the cryptographic identity of the
// device↔broker pair; mDNS only answers "where is the broker right
// now?". device_id is public (it travels in X-Cwm-Device on every
// poll), so listing IDs in TXT leaks nothing — it just lets the device
// filter "is my broker on this LAN?".

import { createHash } from "node:crypto";
import { hostname, networkInterfaces } from "node:os";

import bonjourPkg from "bonjour-service";

const { Bonjour } = bonjourPkg;

export const SERVICE_TYPE = "cwm-broker";
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

    const instance = `cwm-broker-${hostShort()}`;
    // When bind is 0.0.0.0/empty, pin the A records to the LAN-reachable
    // physical IPv4s so we don't advertise Docker bridges and VPN
    // tunnels that the device can't route to.
    const explicit = (!bind || bind === "0.0.0.0" || bind === "::")
      ? physicalIPv4s()
      : [bind];
    pub._bonjour = new Bonjour();
    try {
      const opts = { name: instance, type: SERVICE_TYPE, port, txt };
      if (explicit.length > 0) opts.host = explicit[0];
      pub._service = pub._bonjour.publish(opts);
    } catch (e) {
      try { pub._bonjour.destroy(); } catch {}
      pub._bonjour = null;
      throw e;
    }
    pub._lastTxt = txt;
    logger?.info?.(`mdns: published ${instance}._${SERVICE_TYPE}._tcp.local. port=${port} devs=${devs.length} ips=${explicit.join(",")}`);

    pub._timer = setInterval(() => {
      let cur = [];
      try { cur = lister.listDeviceIds(); }
      catch (e) { logger?.warn?.(`mdns: refresh device list: ${e.message}`); return; }
      const next = buildTxt(cur);
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
            pub._service = pub._bonjour.publish({ name: instance, type: SERVICE_TYPE, port, txt: next });
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
}

// Exported for tests.
export const _internal = { buildTxt, isLoopback, hostShort, txtEqual };
