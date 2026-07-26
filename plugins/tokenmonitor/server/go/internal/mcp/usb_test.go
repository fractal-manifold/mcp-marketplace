package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// buildFromArgs drives buildUSBPayload with a bare request (nil Registry, so the
// PSK-reuse path is skipped) and returns the payload JSON or the error result.
func buildFromArgs(t *testing.T, args map[string]any, expectID string) (usbProvisionPayload, string, bool, bool, *mcp.CallToolResult) {
	t.Helper()
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return buildUSBPayload(Deps{}, req, "071718", expectID)
}

func errText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("expected an error result, got nil")
	}
	blob, _ := json.Marshal(res)
	return string(blob)
}

func TestBuildUSBPayload_BrokerURLWithoutPSKAndNoDeviceIDRejected(t *testing.T) {
	// High #1: a broker_url with no psk and no device_id would push a broker the
	// device can never authenticate against. Must error, not silently omit psk.
	_, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"broker_url": "http://10.0.0.5:8787",
	}, "")) // expectID empty (explicit port, no device_id)
	if res == nil {
		t.Fatal("broker_url without psk/device_id must be rejected")
	}
	if s := errText(t, res); !contains(s, "broker_url") {
		t.Errorf("error should mention broker_url, got %s", s)
	}
}

func TestBuildUSBPayload_ExplicitPSKAccepted(t *testing.T) {
	psk := "00000000000000000000000000000000000000000000000000000000000000ab"
	payload, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"broker_url": "http://10.0.0.5:8787",
		"psk_hex":    psk,
	}, ""))
	if res != nil {
		t.Fatalf("explicit psk should be accepted: %s", errText(t, res))
	}
	if payload.PSKHex != psk {
		t.Errorf("psk not carried: %q", payload.PSKHex)
	}
}

func TestBuildUSBPayload_WiFiTogethernessRule(t *testing.T) {
	// Bare wifi_ssid (no wifi_pass key) is an error, never a silent open network.
	_, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
	}, ""))
	if res == nil {
		t.Fatal("bare wifi_ssid must be rejected")
	}
	// Bare wifi_pass (no wifi_ssid) is likewise an error.
	_, _, _, _, res2 := build5(buildFromArgs(t, map[string]any{
		"wifi_pass": "secret",
	}, ""))
	if res2 == nil {
		t.Fatal("bare wifi_pass must be rejected")
	}
}

func TestBuildUSBPayload_WiFiOpenNetworkExplicitEmptyPass(t *testing.T) {
	// An explicit empty wifi_pass alongside wifi_ssid is a deliberate open net:
	// both must be emitted (pointers), pass as "".
	payload, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": "OpenNet",
		"wifi_pass": "",
	}, ""))
	if res != nil {
		t.Fatalf("open-network pair should be accepted: %s", errText(t, res))
	}
	if payload.WiFiSSID == nil || *payload.WiFiSSID != "OpenNet" {
		t.Errorf("wifi_ssid not carried: %+v", payload.WiFiSSID)
	}
	if payload.WiFiPass == nil || *payload.WiFiPass != "" {
		t.Errorf("explicit empty wifi_pass must be emitted, got %+v", payload.WiFiPass)
	}
	// And it must serialise with wifi_pass present (open network on the wire).
	blob, _ := json.Marshal(payload)
	if !contains(string(blob), `"wifi_pass":""`) {
		t.Errorf("open-network wifi_pass missing from JSON: %s", blob)
	}
}

func TestBuildUSBPayload_WiFiOnlyOmitsBrokerAndPSK(t *testing.T) {
	// The headline flow: only wifi_ssid + wifi_pass. Nothing else on the wire.
	payload, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
		"wifi_pass": "hunter2",
	}, ""))
	if res != nil {
		t.Fatalf("wifi-only should be accepted: %s", errText(t, res))
	}
	blob, _ := json.Marshal(payload)
	s := string(blob)
	if contains(s, "broker_url") || contains(s, "psk_hex") {
		t.Errorf("wifi-only payload must not carry broker/psk: %s", s)
	}
}

// build5 is a tiny adapter so the 5-value buildUSBPayload return threads through
// a single call site in the tests above.
func build5(payload usbProvisionPayload, pskHex string, gen, reuse bool, res *mcp.CallToolResult) (usbProvisionPayload, string, bool, bool, *mcp.CallToolResult) {
	return payload, pskHex, gen, reuse, res
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func TestBuildUSBPayload_WiFiByteLengthEnforced(t *testing.T) {
	// PROVISION_WIRE §7: the bound is UTF-8 BYTES, not code points. JSON Schema
	// maxLength counts characters, so a 32-CHARACTER multibyte SSID slips past it
	// and would be rejected by firmware only after a whole lease + serial session
	// was spent. Each runtime MUST check the byte length itself.
	ssid32chars := strings.Repeat("ñ", 32) // 32 code points, 64 bytes
	_, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": ssid32chars,
		"wifi_pass": "hunter2",
	}, ""))
	if res == nil {
		t.Fatal("a 64-byte SSID must be rejected client-side")
	}
	if s := errText(t, res); !contains(s, "wifi_ssid") {
		t.Errorf("error should name wifi_ssid, got %s", s)
	}

	// An over-long passphrase is likewise a client error.
	_, _, _, _, res = build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
		"wifi_pass": strings.Repeat("a", 65),
	}, ""))
	if res == nil {
		t.Fatal("a 65-byte passphrase must be rejected client-side")
	}

	// Exactly at the limits is fine (32 and 64 bytes).
	payload, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"wifi_ssid": strings.Repeat("a", 32),
		"wifi_pass": strings.Repeat("b", 64),
	}, ""))
	if res != nil {
		t.Fatalf("SSID/pass exactly at the byte limits must be accepted: %s", errText(t, res))
	}
	if payload.WiFiSSID == nil || len(*payload.WiFiSSID) != 32 {
		t.Errorf("boundary SSID not carried: %+v", payload.WiFiSSID)
	}
}

func TestBuildUSBPayload_NoRegistryRefusesToMintPSK(t *testing.T) {
	// A minted PSK can only be kept if there is a registry to persist it in.
	// Without one it would be pushed to the device and immediately lost, leaving
	// the device signing with a key nobody on the host has.
	_, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"broker_url": "http://10.0.0.5:8787",
	}, "02c4777c")) // device_id known, but Deps{} has a nil Registry
	if res == nil {
		t.Fatal("minting a PSK with no registry must be refused")
	}
	if s := errText(t, res); !contains(s, "psk_hex") {
		t.Errorf("error should tell the caller to pass psk_hex, got %s", s)
	}
}

func TestBuildUSBPayload_ProvidersUseAntigravityWireKey(t *testing.T) {
	// PROVISION_WIRE §3 fixes the nested key set as {claude, codex, antigravity}.
	// Firmware still accepts the legacy "gemini", but py/js are written from the
	// doc, so all three runtimes must emit "antigravity" to stay byte-identical.
	payload, _, _, _, res := build5(buildFromArgs(t, map[string]any{
		"provider_claude":      true,
		"provider_antigravity": true,
	}, ""))
	if res != nil {
		t.Fatalf("providers should be accepted: %s", errText(t, res))
	}
	if _, ok := payload.Providers["antigravity"]; !ok {
		t.Errorf("providers must use the antigravity key: %+v", payload.Providers)
	}
	if _, ok := payload.Providers["gemini"]; ok {
		t.Errorf("providers must NOT emit the legacy gemini key: %+v", payload.Providers)
	}
	// The deprecated arg still maps onto the modern wire key.
	payload, _, _, _, _ = build5(buildFromArgs(t, map[string]any{"provider_gemini": true}, ""))
	if !payload.Providers["antigravity"] {
		t.Errorf("provider_gemini must map to the antigravity wire key: %+v", payload.Providers)
	}
}

func TestBuildUSBPayload_AbsentPairingCodeStaysOffTheWire(t *testing.T) {
	// The cable is the physical-presence proof: the device's serial transport
	// applies a payload with no pairing_code at all. An empty code must not be
	// emitted as "" either — firmware treats an empty string as a supplied-and-
	// wrong code on the transports that do check one.
	payload, _, _, _, res := build5(buildUSBPayloadFromArgs(t, map[string]any{
		"city": "Madrid",
	}, "", ""))
	if res != nil {
		t.Fatalf("a codeless USB payload must be accepted: %s", errText(t, res))
	}
	blob, _ := json.Marshal(payload)
	if contains(string(blob), "pairing_code") {
		t.Errorf("absent pairing_code must not reach the wire: %s", blob)
	}

	// A code that IS supplied still travels, so a caller who has the screen in
	// front of them keeps the extra check on the transports that honour it.
	payload, _, _, _, _ = build5(buildUSBPayloadFromArgs(t, map[string]any{"city": "Madrid"}, "071718", ""))
	if payload.PairingCode != "071718" {
		t.Errorf("a supplied pairing_code must be carried, got %q", payload.PairingCode)
	}
}

// buildUSBPayloadFromArgs is buildFromArgs with the pairing code as a parameter
// rather than pinned to a valid one.
func buildUSBPayloadFromArgs(t *testing.T, args map[string]any, code, expectID string) (usbProvisionPayload, string, bool, bool, *mcp.CallToolResult) {
	t.Helper()
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return buildUSBPayload(Deps{}, req, code, expectID)
}
