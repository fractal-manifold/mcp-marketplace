// tokenmonitor_set_wifi — move a device onto a different WiFi network over
// the control plane, with no cable and nobody touching the screen.
//
// WHY THIS IS ITS OWN TOOL
// ------------------------
// It could have been two more fields on tokenmonitor_set_device_pending, and
// that would have been wrong. Every other field there is fire-and-forget: you
// set a brightness, the device applies it, done. This one has a decision in
// the middle that only the broker can make, because only the broker knows
// what the device remembers — does this request need a password, or not?
//
// That question is the entire feature. A device that has been on the office
// WiFi before is holding the credential; asking the operator to retype it is
// asking them for something the device already has. So a bare `ssid` means
// "switch to a network you know", and a password is requested ONLY when the
// device says it has never seen that network. Folding this into a generic
// pending-setter would have buried the one interesting behaviour behind a
// field that looks optional but sometimes is not.
//
// The device reports its remembered networks by NAME ONLY (see
// registry.KnownNetwork). No password ever travels device→broker, so the
// broker can answer "do you know this network?" without ever being able to
// answer "what is its password?".
package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// 802.11 limits. The device enforces these too (tmon_wifi_store.h); checking
// here turns a silent device-side rejection into an immediate error.
const (
	wifiSSIDMaxBytes = 32
	wifiPassMaxBytes = 63
)

func setWiFiTool() mcp.Tool {
	return mcp.NewTool("tokenmonitor_set_wifi",
		mcp.WithDescription("Move a registered device onto a different WiFi network, over the network — no USB cable and nothing to tap on the device. Stages a pending config the device applies on its next sync (within ~10 s) and then reboots onto the new network.\n\nPASSWORDS: send `ssid` alone first. If the device already remembers that network it still holds the password, and none is needed. If it does not, this returns needs_password=true with the list of networks it does know — ask the user for the password and call again with `pass`.\n\nSAFETY: if the new network does not come up, the device works back through its remembered networks on boot, preferring ones that have actually connected before, so a wrong answer is recoverable without a cable. The exception is a device carried somewhere NONE of its remembered networks exist — there, recovery is the USB cable (tokenmonitor_usb_provision). Note also that a remembered OPEN network can never be switched to this way: the device refuses to auto-join open networks because an SSID alone is trivially impersonated."),
		mcp.WithString("device_id", mcp.Required(),
			mcp.Description("8 lowercase hex chars. From tokenmonitor_list_devices.")),
		mcp.WithString("ssid", mcp.Required(),
			mcp.Description("SSID to switch to, 1-32 bytes. Case-sensitive and exact — this is matched against the device's remembered networks, so 'MyWiFi' and 'mywifi' are different networks.")),
		mcp.WithString("pass",
			mcp.Description("WiFi passphrase, up to 63 bytes. Omit on the first attempt: it is only needed for a network the device has never seen, and this tool will tell you when that is the case. Supplying it for an already-remembered network REPLACES the stored password, which is how you fix one that has changed.")),
	)
}

// knownNetworkNames renders the remembered list for an error message. Names
// only, which is all the broker has.
func knownNetworkNames(nets []registry.KnownNetwork) string {
	if len(nets) == 0 {
		return "(none reported)"
	}
	parts := make([]string, 0, len(nets))
	for _, n := range nets {
		s := n.SSID
		switch {
		case n.Open:
			s += " (open — cannot be switched to remotely)"
		case !n.Verified:
			s += " (never connected successfully)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func handleSetWiFi(d Deps) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))
		if !registry.ValidDeviceID(deviceID) {
			return mcp.NewToolResultError("device_id must be 8 lowercase hex chars"), nil
		}

		// NOT trimmed: leading and trailing spaces are legal in an SSID and
		// trimming them would silently target a different network than the
		// caller named — one the device may not remember at all.
		ssid := req.GetString("ssid", "")
		if ssid == "" {
			return mcp.NewToolResultError("ssid is required"), nil
		}
		if len(ssid) > wifiSSIDMaxBytes {
			return mcp.NewToolResultError(fmt.Sprintf(
				"ssid is %d bytes; the 802.11 limit is %d", len(ssid), wifiSSIDMaxBytes)), nil
		}
		pass := req.GetString("pass", "")
		if len(pass) > wifiPassMaxBytes {
			return mcp.NewToolResultError(fmt.Sprintf(
				"pass is %d bytes; the WPA2 limit is %d", len(pass), wifiPassMaxBytes)), nil
		}

		dev, err := d.Registry.Load(deviceID)
		if errors.Is(err, registry.ErrNotFound) {
			return mcp.NewToolResultError(fmt.Sprintf(
				"device %s not registered — call tokenmonitor_register_device first", deviceID)), nil
		} else if err != nil {
			return mcp.NewToolResultErrorFromErr("load device", err), nil
		}

		// Decide whether a password is needed, but ONLY when none was given.
		// A supplied password is always honoured: it is how an operator fixes
		// a network whose password changed, and second-guessing that would
		// make a rotated credential unfixable from here.
		if pass == "" {
			var known []registry.KnownNetwork
			if dev.Active.WiFiKnown != nil {
				known = *dev.Active.WiFiKnown
			}
			var match *registry.KnownNetwork
			for i := range known {
				if known[i].SSID == ssid {
					match = &known[i]
					break
				}
			}
			switch {
			case match == nil:
				// Distinguish "the device told us its networks and this is
				// not one" from "the device never told us anything", because
				// the second is old firmware and the fix is different.
				if dev.Active.WiFiKnown == nil {
					return mcp.NewToolResultError(fmt.Sprintf(
						"this device has not reported its remembered networks, so I cannot tell whether it knows %q. That report needs firmware with wifi_known support. Supply `pass` to switch to it regardless.", ssid)), nil
				}
				return mcp.NewToolResultError(fmt.Sprintf(
					"needs_password=true: the device does not remember %q, so it needs the passphrase. Ask the user for it and call again with `pass`. Networks it does remember: %s",
					ssid, knownNetworkNames(known))), nil
			case match.Open:
				return mcp.NewToolResultError(fmt.Sprintf(
					"%q is remembered but is an OPEN network, and the device never auto-joins open networks — an SSID alone is trivially impersonated. Switch to it with the USB cable (tokenmonitor_usb_provision) or on the device's own screen.", ssid)), nil
			}
		}

		update := registry.ConfigPayload{WiFiSSID: ssid, WiFiPass: pass}
		updated, err := d.Registry.SetPending(deviceID, update)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("set pending", err), nil
		}
		if updated.Pending == nil {
			// SetPending drops a pending identical to active. Reached when
			// the device is already being sent to this network.
			return mcp.NewToolResultText(fmt.Sprintf(
				"No change staged: %s is already set to switch to %q.", deviceID, ssid)), nil
		}

		how := "using the password it already remembers"
		if pass != "" {
			how = "using the password you supplied"
		}
		return mcp.NewToolResultText(fmt.Sprintf(
			"Staged config v%d for %s: switch to WiFi %q, %s. The device applies it on its next sync (~10 s) and reboots onto the new network. If it does not come up there, it falls back through its remembered networks on boot.",
			updated.Pending.Version, deviceID, ssid, how)), nil
	}
}
