// tokenmonitor_set_wifi — move a device onto a different WiFi network over
// the control plane, with no cable and nobody touching the screen.
//
// Mirror of Go's internal/mcp/wifi.go and Python's _set_wifi. The interesting
// behaviour, and the reason this is its own tool rather than two more fields
// on tokenmonitor_set_device_pending, is the decision in the middle: a network
// the device already remembers needs no password, because the device is
// holding it. Only an unknown network makes this ask.
//
// The device reports its remembered networks by NAME only, so the broker can
// answer "do you know this network?" without ever being able to answer "what
// is its password?".

import { validDeviceID } from "../registry/store.js";
import { registryUnavailableMsg } from "./server.js";

// 802.11 limits. The device enforces these too (tmon_wifi_store.h); checking
// here turns a silent device-side rejection into an immediate error.
const WIFI_SSID_MAX = 32;
const WIFI_PASS_MAX = 63;

// Render the remembered list for an error message. Names only, which is all
// the broker has.
function knownNetworkNames(nets) {
  if (!nets || nets.length === 0) return "(none reported)";
  return nets.map((n) => {
    let s = String(n.ssid || "");
    if (n.open) s += " (open — cannot be switched to remotely)";
    else if (!n.verified) s += " (never connected successfully)";
    return s;
  }).join(", ");
}

export function setWiFiTool(deps, args) {
  if (!deps.registry) return { error: registryUnavailableMsg() };
  const deviceID = String(args.device_id || "").trim().toLowerCase();
  if (!validDeviceID(deviceID)) return { error: "device_id must be 8 lowercase hex chars" };

  // NOT trimmed: leading and trailing spaces are legal in an SSID and
  // trimming them would silently target a different network than the caller
  // named — one the device may not remember at all.
  const ssid = typeof args.ssid === "string" ? args.ssid : "";
  if (!ssid) return { error: "ssid is required" };
  const ssidBytes = Buffer.byteLength(ssid, "utf8");
  if (ssidBytes > WIFI_SSID_MAX) {
    return { error: `ssid is ${ssidBytes} bytes; the 802.11 limit is ${WIFI_SSID_MAX}` };
  }
  if (args.pass != null && typeof args.pass !== "string") return { error: "pass must be a string" };
  const pass = typeof args.pass === "string" ? args.pass : "";
  const passBytes = Buffer.byteLength(pass, "utf8");
  if (passBytes > WIFI_PASS_MAX) {
    return { error: `pass is ${passBytes} bytes; the WPA2 limit is ${WIFI_PASS_MAX}` };
  }

  let dev;
  try { dev = deps.registry.load(deviceID); }
  catch (e) {
    if (/not found/.test(e.message)) return { error: `device ${deviceID} not registered — call tokenmonitor_register_device first` };
    return { error: e.message };
  }

  // Decide whether a password is needed, but ONLY when none was given. A
  // supplied password is always honoured: it is how an operator fixes a
  // network whose password changed, and second-guessing that would make a
  // rotated credential unfixable from here.
  if (!pass) {
    const known = dev.active.wifiKnown;
    const match = (known || []).find((n) => String(n.ssid || "") === ssid);
    if (!match) {
      // Distinguish "the device told us its networks and this is not one"
      // from "the device never told us anything", because the second is old
      // firmware and the fix is different.
      if (known == null) {
        return { error: `this device has not reported its remembered networks, so I cannot tell whether it knows ${JSON.stringify(ssid)}. That report needs firmware with wifi_known support. Supply \`pass\` to switch to it regardless.` };
      }
      return { error: `needs_password=true: the device does not remember ${JSON.stringify(ssid)}, so it needs the passphrase. Ask the user for it and call again with \`pass\`. Networks it does remember: ${knownNetworkNames(known)}` };
    }
    if (match.open) {
      return { error: `${JSON.stringify(ssid)} is remembered but is an OPEN network, and the device never auto-joins open networks — an SSID alone is trivially impersonated. Switch to it with the USB cable (tokenmonitor_usb_provision) or on the device's own screen.` };
    }
  }

  let updated;
  try { updated = deps.registry.setPending(deviceID, { wifi_ssid: ssid, wifi_pass: pass }); }
  catch (e) { return { error: e.message }; }
  if (!updated.pending) {
    // setPending drops a pending identical to active. Reached when the device
    // is already being sent to this network.
    return { text: `No change staged: ${deviceID} is already set to switch to ${JSON.stringify(ssid)}.` };
  }

  const how = pass ? "using the password you supplied" : "using the password it already remembers";
  return { text: `Staged config v${updated.pending.payload.version} for ${deviceID}: switch to WiFi ${JSON.stringify(ssid)}, ${how}. The device applies it on its next sync (~10 s) and reboots onto the new network. If it does not come up there, it falls back through its remembered networks on boot.` };
}
