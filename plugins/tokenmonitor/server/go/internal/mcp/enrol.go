package mcp

// Enrolment — the rule tokenmonitor_provision (LAN) and
// tokenmonitor_usb_provision (cable) share for pairing a device with this
// broker: which PSK is pushed, which broker address goes with it, and what the
// registry records afterwards. compat/mcp-errors.md states it for all three
// runtimes; the strings here are canonical.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

// Notes attached to a provisioning result.
const (
	noteNoRegistry    = "no device registry is configured on this install, so no PSK was generated or pushed; pass psk_hex to pair the device"
	notePSKUnrecorded = "a fresh PSK was generated and is now live on the device, but the registry does NOT hold it; record psk_hex and register the device with tokenmonitor_register_device"
	notePSKMaybeLive  = "a fresh PSK was generated and may already be stored on the device (a failed write can leave a partial config); record psk_hex — the registry was NOT updated"
	notePSKUnknown    = "a fresh PSK was generated and may already be live on the device; record it — the registry was NOT updated because the outcome is unknown. Do not blindly re-run."
)

// Refusals: the call stops before anything is written to the device.
const (
	errDeviceHasPSK = "the device already holds a PSK that this registry does not know — it may be paired with another broker, or an earlier enrolment here was never recorded. Nothing was written. Pass enroll=false to keep that pairing and change settings only, enroll=true to re-pair the device with this broker, or psk_hex if you have the key it holds"
	errEnrollChoice = "this device is not in the registry and nothing says whether it is already paired with another broker. Nothing was written. Pass enroll=true to pair it with this broker (replacing any PSK it holds), or enroll=false to change settings only"
	errNoSeedLAN    = "could not work out an address of this broker that the device can reach, and firmware older than 1.0.0 cannot pair without one. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint)"
	// errNoSeedUSBFmt takes the firmware version and the candidate count.
	errNoSeedUSBFmt = "this device's firmware (%s) is older than 1.0.0 and cannot find the broker without an address, and this host has %d candidate addresses. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to change settings without pairing"
)

func joinNotes(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// enrollArg reads the three-valued `enroll` argument: absent (decide from the
// evidence), true (pair here, whatever the device holds) or false (never).
func enrollArg(req mcp.CallToolRequest) (explicit, value bool) {
	v, ok := req.GetArguments()["enroll"]
	if !ok || v == nil {
		return false, true
	}
	return true, req.GetBool("enroll", true)
}

// explicitPSK validates a caller-supplied psk_hex and the one combination that
// contradicts itself. It needs no device and runs before any port is opened.
func explicitPSK(req mcp.CallToolRequest) (string, *mcp.CallToolResult) {
	pskHex := strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", "")))
	if pskHex == "" {
		return "", nil
	}
	if explicit, enroll := enrollArg(req); explicit && !enroll {
		return "", mcp.NewToolResultError("enroll=false cannot be combined with psk_hex")
	}
	if len(pskHex) != 64 {
		return "", mcp.NewToolResultError("psk_hex must be 64 hex chars")
	}
	if _, err := hex.DecodeString(pskHex); err != nil {
		return "", mcp.NewToolResultError("psk_hex is not valid hex")
	}
	return pskHex, nil
}

// resolveEnrolPSK decides which PSK, if any, a call pushes.
//
//   - enroll=false: none. Settings only; PSK and registry untouched.
//   - psk_hex: that key.
//   - no registry on this install: none (see noRegistryNote) — a minted key
//     could not be kept and would orphan the device.
//   - the registry already holds a PSK for deviceID: REUSE it. Rotating the key
//     on every reconfigure risks desyncing a device whose push silently fails,
//     and re-sending the same key is harmless whatever state the device is in.
//   - otherwise the device is unknown here, and a fresh key would replace
//     whatever it holds. That is only done on evidence the caller means it:
//     enroll=true; or the device itself reports it holds no PSK (hasPSK=false,
//     serial HELLO_RESP on firmware that sends it); or, when the device cannot
//     say, a broker_url — which is how every caller asked for a pairing before
//     the address stopped being configuration. With no such evidence the call
//     is refused rather than re-keying a device that may be paired elsewhere.
//
// hasPSK is nil when the device did not say (the LAN transport, or firmware
// that predates the field): "unknown", never "fresh".
func resolveEnrolPSK(d Deps, req mcp.CallToolRequest, deviceID string, hasPSK *bool) (pskHex string, generated, reused bool, errText string) {
	explicit, enroll := enrollArg(req)
	if !enroll {
		return "", false, false, ""
	}
	if pskHex = strings.ToLower(strings.TrimSpace(req.GetString("psk_hex", ""))); pskHex != "" {
		return pskHex, false, false, ""
	}
	if d.Registry == nil {
		return "", false, false, ""
	}
	dev, err := d.Registry.Load(deviceID)
	switch {
	case err == nil && dev != nil && dev.Active.PSKHex != "":
		return dev.Active.PSKHex, false, true, ""
	case err != nil && !errors.Is(err, registry.ErrNotFound):
		// Only "no such device" means a new one. A record that exists but
		// cannot be read (permissions, a torn or malformed file) must not be
		// answered by minting: that would re-key a paired device because of a
		// transient read failure.
		return "", false, false, "registry load: " + err.Error()
	}
	if !explicit {
		switch {
		case hasPSK != nil && *hasPSK:
			return "", false, false, errDeviceHasPSK
		case hasPSK == nil && strings.TrimSpace(req.GetString("broker_url", "")) == "":
			return "", false, false, errEnrollChoice
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false, false, "psk gen: " + err.Error()
	}
	return hex.EncodeToString(b), true, false, ""
}

// noRegistryNote explains an enrolment that could not happen because this
// install has no registry to keep a PSK in.
func noRegistryNote(d Deps, req mcp.CallToolRequest, pskHex string) string {
	if _, enroll := enrollArg(req); d.Registry == nil && pskHex == "" && enroll {
		return noteNoRegistry
	}
	return ""
}

var semverHead = regexp.MustCompile(`^(\d+)\.\d+\.\d+`)

// fwFindsBrokerAlone reports whether firmware `fw` can leave BOOT_NEEDS_CONFIG
// on a PSK alone. That arrived in 1.0.0 (mDNS bootstrap); everything older
// needs a broker URL beside the key or it waits for setup forever. An empty or
// unparseable version counts as old — the safe reading.
func fwFindsBrokerAlone(fw string) bool {
	m := semverHead.FindStringSubmatch(strings.TrimSpace(fw))
	if m == nil {
		return false
	}
	major, err := strconv.Atoi(m[1])
	return err == nil && major >= 1
}

// brokerPort is this broker's configured port, 0 when there is no config.
func brokerPort(d Deps) int {
	if d.Cfg == nil {
		return 0
	}
	return d.Cfg.Server.Port
}

// hintURLs is the provision hint's candidate list: one URL per LAN interface.
func hintURLs(d Deps) []string {
	port := brokerPort(d)
	ips, err := localIPv4s()
	if err != nil || port == 0 {
		return nil
	}
	urls := make([]string, 0, len(ips))
	for _, ip := range ips {
		urls = append(urls, "http://"+net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	return urls
}

// seedURLTowards is the broker URL a device at host:port can demonstrably
// reach: this host's address on the route to it. A connected UDP socket is how
// the kernel is asked for that address — nothing is sent.
func seedURLTowards(d Deps, hostport string) string {
	port := brokerPort(d)
	if port == 0 {
		return ""
	}
	c, err := net.Dial("udp4", hostport)
	if err != nil {
		return ""
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil || ua.IP.IsUnspecified() {
		return ""
	}
	return "http://" + net.JoinHostPort(ua.IP.String(), strconv.Itoa(port))
}

// seedURLFromHint picks the broker URL for a cable-attached device, whose
// route nobody can observe: the provision hint, but only when it is
// unambiguous. Returns "" and a refusal otherwise.
func seedURLFromHint(fw string, candidates []string) (string, string) {
	if len(candidates) == 1 {
		return candidates[0], ""
	}
	if fw == "" {
		fw = "unknown version"
	}
	return "", fmt.Sprintf(errNoSeedUSBFmt, fw, len(candidates))
}

// mirrorToRegistry records a just-applied enrolment. A new device is
// registered; a known one is converged in place (ReplaceActive).
//
// One case writes nothing: the device is already in the registry, the PSK
// pushed is the one the registry holds (whether it was reused or the caller
// passed that same key), and the caller gave no broker_url (converge=false; an
// auto-seeded address does not count — nobody asked for a converge). The
// record is correct as it stands, and replacing it would reset the config
// version to 1 under a live device still at version N — after which every
// pending the broker stages is numbered below what the device already has and
// is ignored. That is the headline "point it at my WiFi" call.
func mirrorToRegistry(d Deps, deviceID string, reg registry.ConfigPayload, converge bool) (registered, reregistered, enrolled bool, note string) {
	if !converge {
		if dev, err := d.Registry.Load(deviceID); err == nil && dev != nil && dev.Active.PSKHex == reg.PSKHex {
			return false, false, true, ""
		}
	}
	_, err := d.Registry.Register(deviceID, reg)
	switch {
	case err == nil:
		return true, false, true, ""
	case strings.Contains(err.Error(), "already exists"):
		// Device was re-provisioned (e.g. user wiped NVS and started over).
		// It has ALREADY applied the new PSK locally and proved presence, so
		// converge the active config in place rather than queuing a pending
		// the wiped device can neither decrypt nor promote. Preserves
		// device-level metadata (serial, SKU, channel, …). See #8.
		if _, perr := d.Registry.ReplaceActive(deviceID, reg); perr != nil {
			return false, false, false, "device provisioned but registry re-register failed: " + perr.Error()
		}
		return false, true, true, ""
	default:
		return false, false, false, "device provisioned but registry write failed: " + err.Error()
	}
}
