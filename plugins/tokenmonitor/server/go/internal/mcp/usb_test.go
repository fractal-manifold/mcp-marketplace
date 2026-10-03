package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// buildFromArgs drives buildUSBPayload — the part of the payload the arguments
// alone decide — and returns it or the error result.
func buildFromArgs(t *testing.T, args map[string]any) (usbProvisionPayload, *mcp.CallToolResult) {
	t.Helper()
	return buildUSBPayloadFromArgs(t, args, "071718")
}

func errText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("expected an error result, got nil")
	}
	blob, _ := json.Marshal(res)
	return string(blob)
}

func TestBuildUSBPayload_ExplicitPSKAccepted(t *testing.T) {
	psk := "00000000000000000000000000000000000000000000000000000000000000ab"
	payload, res := buildFromArgs(t, map[string]any{
		"broker_url": "http://10.0.0.5:8787",
		"psk_hex":    psk,
	})
	if res != nil {
		t.Fatalf("explicit psk should be accepted: %s", errText(t, res))
	}
	if payload.PSKHex != psk {
		t.Errorf("psk not carried: %q", payload.PSKHex)
	}
}

func TestBuildUSBPayload_WiFiTogethernessRule(t *testing.T) {
	// Bare wifi_ssid (no wifi_pass key) is an error, never a silent open network.
	_, res := buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
	})
	if res == nil {
		t.Fatal("bare wifi_ssid must be rejected")
	}
	// Bare wifi_pass (no wifi_ssid) is likewise an error.
	_, res2 := buildFromArgs(t, map[string]any{
		"wifi_pass": "secret",
	})
	if res2 == nil {
		t.Fatal("bare wifi_pass must be rejected")
	}
}

func TestBuildUSBPayload_WiFiOpenNetworkExplicitEmptyPass(t *testing.T) {
	// An explicit empty wifi_pass alongside wifi_ssid is a deliberate open net:
	// both must be emitted (pointers), pass as "".
	payload, res := buildFromArgs(t, map[string]any{
		"wifi_ssid": "OpenNet",
		"wifi_pass": "",
	})
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
	payload, res := buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
		"wifi_pass": "hunter2",
	})
	if res != nil {
		t.Fatalf("wifi-only should be accepted: %s", errText(t, res))
	}
	blob, _ := json.Marshal(payload)
	s := string(blob)
	if contains(s, "broker_url") || contains(s, "psk_hex") {
		t.Errorf("wifi-only payload must not carry broker/psk: %s", s)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func TestBuildUSBPayload_WiFiByteLengthEnforced(t *testing.T) {
	// PROVISION_WIRE §7: the bound is UTF-8 BYTES, not code points. JSON Schema
	// maxLength counts characters, so a 32-CHARACTER multibyte SSID slips past it
	// and would be rejected by firmware only after a whole lease + serial session
	// was spent. Each runtime MUST check the byte length itself.
	ssid32chars := strings.Repeat("ñ", 32) // 32 code points, 64 bytes
	_, res := buildFromArgs(t, map[string]any{
		"wifi_ssid": ssid32chars,
		"wifi_pass": "hunter2",
	})
	if res == nil {
		t.Fatal("a 64-byte SSID must be rejected client-side")
	}
	if s := errText(t, res); !contains(s, "wifi_ssid") {
		t.Errorf("error should name wifi_ssid, got %s", s)
	}

	// An over-long passphrase is likewise a client error.
	_, res = buildFromArgs(t, map[string]any{
		"wifi_ssid": "HomeNet",
		"wifi_pass": strings.Repeat("a", 65),
	})
	if res == nil {
		t.Fatal("a 65-byte passphrase must be rejected client-side")
	}

	// Exactly at the limits is fine (32 and 64 bytes).
	payload, res := buildFromArgs(t, map[string]any{
		"wifi_ssid": strings.Repeat("a", 32),
		"wifi_pass": strings.Repeat("b", 64),
	})
	if res != nil {
		t.Fatalf("SSID/pass exactly at the byte limits must be accepted: %s", errText(t, res))
	}
	if payload.WiFiSSID == nil || len(*payload.WiFiSSID) != 32 {
		t.Errorf("boundary SSID not carried: %+v", payload.WiFiSSID)
	}
}

func TestBuildUSBPayload_ProvidersUseAntigravityWireKey(t *testing.T) {
	// PROVISION_WIRE §3 fixes the nested key set as {claude, codex, antigravity}.
	// Firmware still accepts the legacy "gemini", but py/js are written from the
	// doc, so all three runtimes must emit "antigravity" to stay byte-identical.
	payload, res := buildFromArgs(t, map[string]any{
		"provider_claude":      true,
		"provider_antigravity": true,
	})
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
	payload, _ = buildFromArgs(t, map[string]any{"provider_gemini": true})
	if !payload.Providers["antigravity"] {
		t.Errorf("provider_gemini must map to the antigravity wire key: %+v", payload.Providers)
	}
}

func TestBuildUSBPayload_AbsentPairingCodeStaysOffTheWire(t *testing.T) {
	// The cable is the physical-presence proof: the device's serial transport
	// applies a payload with no pairing_code at all. An empty code must not be
	// emitted as "" either — firmware treats an empty string as a supplied-and-
	// wrong code on the transports that do check one.
	payload, res := buildUSBPayloadFromArgs(t, map[string]any{
		"city": "Madrid",
	}, "")
	if res != nil {
		t.Fatalf("a codeless USB payload must be accepted: %s", errText(t, res))
	}
	blob, _ := json.Marshal(payload)
	if contains(string(blob), "pairing_code") {
		t.Errorf("absent pairing_code must not reach the wire: %s", blob)
	}

	// A code that IS supplied still travels, so a caller who has the screen in
	// front of them keeps the extra check on the transports that honour it.
	payload, _ = buildUSBPayloadFromArgs(t, map[string]any{"city": "Madrid"}, "071718")
	if payload.PairingCode != "071718" {
		t.Errorf("a supplied pairing_code must be carried, got %q", payload.PairingCode)
	}
}

// buildUSBPayloadFromArgs is buildFromArgs with the pairing code as a parameter
// rather than pinned to a valid one.
func buildUSBPayloadFromArgs(t *testing.T, args map[string]any, code string) (usbProvisionPayload, *mcp.CallToolResult) {
	t.Helper()
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return buildUSBPayload(req, code)
}

func TestBuildUSBPayload_ExplicitPSKValidatedBeforeAnyPortIsOpened(t *testing.T) {
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"psk_hex": "abcd"}, "psk_hex must be 64 hex chars"},
		{map[string]any{"psk_hex": strings.Repeat("z", 64)}, "psk_hex is not valid hex"},
		{map[string]any{"psk_hex": usbTestPSK, "enroll": false}, "enroll=false cannot be combined with psk_hex"},
	} {
		_, res := buildFromArgs(t, tc.args)
		if res == nil || !contains(errText(t, res), tc.want) {
			t.Errorf("%v: want %q", tc.args, tc.want)
		}
	}
}

// --- enrolment -------------------------------------------------------------

const (
	usbTestID  = "02c4777c"
	usbTestPSK = "00000000000000000000000000000000000000000000000000000000000000ab"
)

func usbTestRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	return r
}

// Firmware as it answers the HELLO. has_psk arrived after 1.0.1; older
// firmware does not send it and reports fw_version only.
var (
	yes, no = true, false

	devFresh   = usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "1.0.2", HasPSK: &no}
	devPaired  = usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "1.0.2", HasPSK: &yes}
	devV101    = usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "1.0.1"}  // finds the broker; cannot say has_psk
	devLegacy  = usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "0.12.0"} // needs a broker_url; cannot say has_psk
	devAncient = usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "0.11.0"}

	oneCandidate  = []string{"http://192.168.1.10:8765"}
	twoCandidates = []string{"http://192.168.1.10:8765", "http://10.8.0.2:8765"}
)

// finalize runs the two halves of payload construction the way the handler
// does: the argument-only part, then the part that needs the HELLO_RESP.
func finalize(t *testing.T, r *registry.Registry, args map[string]any, dev usbprov.DeviceInfo, candidates []string) (usbFinal, string) {
	t.Helper()
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	base, res := buildUSBPayload(req, "")
	if res != nil {
		t.Fatalf("buildUSBPayload: %s", errText(t, res))
	}
	return finalizeUSBPayload(Deps{Registry: r}, req, base, dev, candidates)
}

// fin is a finalized payload as the report sees it.
func fin(payload usbProvisionPayload, gen, reused bool) usbFinal {
	return usbFinal{
		deviceID: usbTestID, payload: payload, pskHex: payload.PSKHex,
		pskGenerated: gen, pskReused: reused, callerURL: payload.BrokerURL != "",
	}
}

func usbResult(body string) *usbprov.ProvisionResult {
	return &usbprov.ProvisionResult{
		Device:     usbprov.DeviceInfo{DeviceID: usbTestID, SKU: "S1", FW: "1.0.1"},
		ResultJSON: []byte(body),
	}
}

const usbResultOK = `{"ok":true,"device_id":"02c4777c","next":"rebooting"}`

func TestFinalizeUSB_FreshDevicePairsInOneCall(t *testing.T) {
	// First-time pairing: the device says it holds no PSK, so the headline
	// WiFi-only call also pairs it — no enroll, no broker_url, no device_id.
	f, errText := finalize(t, usbTestRegistry(t), map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}, devFresh, twoCandidates)
	if errText != "" {
		t.Fatalf("a fresh device must be paired: %s", errText)
	}
	if !f.pskGenerated || f.pskReused || len(f.pskHex) != 64 || f.payload.PSKHex != f.pskHex {
		t.Errorf("a fresh device must get a minted PSK: %+v", f)
	}
	// 1.0.0+ finds the broker by mDNS: no address is pushed, however many
	// interfaces this host has.
	if f.payload.BrokerURL != "" || f.seeded != "" {
		t.Errorf("no broker_url may be seeded on firmware that does not need one: %+v", f)
	}
}

func TestFinalizeUSB_PairedUnknownDeviceIsNotRekeyed(t *testing.T) {
	// The device holds a PSK this registry has never seen: it is paired with
	// another broker. A WiFi-only call must not silently replace that key.
	r := usbTestRegistry(t)
	if _, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}, devPaired, nil); errText != errDeviceHasPSK {
		t.Fatalf("want the has-PSK refusal, got %q", errText)
	}
	// Even a broker_url does not override the device's own answer.
	if _, errText := finalize(t, r, map[string]any{"broker_url": "http://10.0.0.5:8787"}, devPaired, nil); errText != errDeviceHasPSK {
		t.Fatalf("broker_url must not override has_psk=true, got %q", errText)
	}
	// The three ways out the message names.
	f, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2", "enroll": false}, devPaired, nil)
	if errText != "" || f.pskHex != "" || f.payload.PSKHex != "" || f.payload.BrokerURL != "" {
		t.Errorf("enroll=false must push settings only: %+v %q", f, errText)
	}
	if f, errText = finalize(t, r, map[string]any{"enroll": true}, devPaired, nil); errText != "" || !f.pskGenerated {
		t.Errorf("enroll=true must re-pair: %+v %q", f, errText)
	}
	if f, errText = finalize(t, r, map[string]any{"psk_hex": usbTestPSK}, devPaired, nil); errText != "" || f.pskHex != usbTestPSK || f.pskGenerated {
		t.Errorf("psk_hex must be pushed as given: %+v %q", f, errText)
	}
}

func TestFinalizeUSB_FirmwareThatCannotSayNeedsIntent(t *testing.T) {
	// Firmware without has_psk (everything up to 1.0.1): "unknown", never
	// "fresh". An unknown device is only re-keyed when the caller says so.
	r := usbTestRegistry(t)
	for _, dev := range []usbprov.DeviceInfo{devV101, devLegacy} {
		if _, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}, dev, oneCandidate); errText != errEnrollChoice {
			t.Fatalf("fw %s: want the enrol-choice refusal, got %q", dev.FW, errText)
		}
		// WiFi-only on someone else's device stays possible.
		f, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2", "enroll": false}, dev, twoCandidates)
		if errText != "" || f.pskHex != "" || f.payload.BrokerURL != "" {
			t.Errorf("fw %s: enroll=false must push settings only: %+v %q", dev.FW, f, errText)
		}
		// A broker_url is intent, and is used as given.
		f, errText = finalize(t, r, map[string]any{"broker_url": "http://10.0.0.5:8787"}, dev, twoCandidates)
		if errText != "" || !f.pskGenerated || f.payload.BrokerURL != "http://10.0.0.5:8787" || f.seeded != "" || !f.callerURL {
			t.Errorf("fw %s: broker_url must pair with that address: %+v %q", dev.FW, f, errText)
		}
	}
}

func TestFinalizeUSB_LegacyFirmwareIsSeededABrokerURL(t *testing.T) {
	// Firmware older than 1.0.0 stays on "Waiting for setup" with a PSK alone.
	r := usbTestRegistry(t)
	for _, dev := range []usbprov.DeviceInfo{devLegacy, devAncient, {DeviceID: usbTestID}} {
		f, errText := finalize(t, r, map[string]any{"enroll": true}, dev, oneCandidate)
		if errText != "" {
			t.Fatalf("fw %q: one candidate must be seeded: %s", dev.FW, errText)
		}
		if f.seeded != oneCandidate[0] || f.payload.BrokerURL != oneCandidate[0] || f.callerURL {
			t.Errorf("fw %q: broker_url not seeded: %+v", dev.FW, f)
		}
	}
	// Ambiguous or empty hint: refuse, before anything is written.
	_, errText := finalize(t, r, map[string]any{"enroll": true}, devLegacy, twoCandidates)
	want := "this device's firmware (0.12.0) is older than 1.0.0 and cannot find the broker without an address, and this host has 2 candidate addresses. Nothing was written. Pass broker_url (see tokenmonitor_provision_hint), or enroll=false to change settings without pairing"
	if errText != want {
		t.Errorf("refusal text drifted from compat/mcp-errors.md:\n got %q\nwant %q", errText, want)
	}
	if _, errText = finalize(t, r, map[string]any{"enroll": true}, devLegacy, nil); !contains(errText, "this host has 0 candidate addresses") {
		t.Errorf("no candidate must refuse too: %q", errText)
	}
	if _, errText = finalize(t, r, map[string]any{"enroll": true}, usbprov.DeviceInfo{DeviceID: usbTestID}, nil); !contains(errText, "firmware (unknown version)") {
		t.Errorf("an unreported version reads as old: %q", errText)
	}
	// 1.0.1 does not need one.
	if f, errText := finalize(t, r, map[string]any{"enroll": true}, devV101, twoCandidates); errText != "" || f.seeded != "" || f.payload.BrokerURL != "" {
		t.Errorf("1.0.1 must not be seeded: %+v %q", f, errText)
	}
}

func TestFinalizeUSB_RegisteredDeviceReusesItsPSK(t *testing.T) {
	// device_id comes from the HELLO_RESP, so an explicit port with no
	// device_id argument still finds the registry's key.
	r := usbTestRegistry(t)
	if _, err := r.Register(usbTestID, registry.ConfigPayload{PSKHex: usbTestPSK}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, dev := range []usbprov.DeviceInfo{devFresh, devPaired, devV101} {
		f, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}, dev, twoCandidates)
		if errText != "" || f.pskGenerated || !f.pskReused || f.payload.PSKHex != usbTestPSK || f.payload.BrokerURL != "" {
			t.Errorf("fw %s: a registered device must be re-sent its own PSK: %+v %q", dev.FW, f, errText)
		}
	}
	// On legacy firmware the reused key travels with a seeded address.
	f, errText := finalize(t, r, map[string]any{"wifi_ssid": "HomeNet", "wifi_pass": "hunter2"}, devLegacy, oneCandidate)
	if errText != "" || !f.pskReused || f.seeded != oneCandidate[0] {
		t.Errorf("legacy: reuse + seed expected: %+v %q", f, errText)
	}
	// enroll=false leaves even a known device's key alone.
	if f, _ := finalize(t, r, map[string]any{"enroll": false}, devPaired, nil); f.pskHex != "" {
		t.Errorf("enroll=false must push no PSK: %+v", f)
	}
}

func TestFinalizeUSB_NoRegistryNeverMintsPSK(t *testing.T) {
	// A minted PSK can only be kept if there is a registry to persist it in.
	// Without one it would be pushed to the device and immediately lost, so a
	// registry-less install pushes none and the result carries noteNoRegistry.
	f, errText := finalize(t, nil, map[string]any{"broker_url": "http://10.0.0.5:8787"}, devLegacy, nil)
	if errText != "" || f.pskHex != "" || f.payload.PSKHex != "" {
		t.Fatalf("no PSK may be minted without a registry: %+v %q", f, errText)
	}
	if f.payload.BrokerURL != "http://10.0.0.5:8787" {
		t.Errorf("broker_url is still pushed, got %q", f.payload.BrokerURL)
	}
}

func TestFinalizeUSB_WireBytes(t *testing.T) {
	// The exact bytes, shared with py/js: key order is the Go struct's.
	f, errText := finalize(t, usbTestRegistry(t), map[string]any{
		"psk_hex": usbTestPSK, "city": "Madrid", "wifi_ssid": "HomeNet", "wifi_pass": "hunter2",
		"provider_claude": true, "provider_antigravity": true,
	}, devLegacy, oneCandidate)
	if errText != "" {
		t.Fatal(errText)
	}
	want := `{"broker_url":"http://192.168.1.10:8765","psk_hex":"` + usbTestPSK + `","city":"Madrid","providers":{"antigravity":true,"claude":true,"codex":false},"wifi_ssid":"HomeNet","wifi_pass":"hunter2"}`
	if string(f.body) != want {
		t.Errorf("wire bytes:\n got %s\nwant %s", f.body, want)
	}
}

func TestFinalizeUSB_WireBytesEscaping(t *testing.T) {
	// json.Marshal writes < > & U+2028 U+2029 as \uXXXX and leaves other
	// non-ASCII as UTF-8. py and js pin the same bytes, so the 1024-byte
	// budget is counted alike in all three.
	f, errText := finalize(t, usbTestRegistry(t), map[string]any{
		"enroll": false, "city": "A<b>&c\u2028d\u2029é",
	}, devLegacy, oneCandidate)
	if errText != "" {
		t.Fatal(errText)
	}
	want := `{"city":"A\u003cb\u003e\u0026c\u2028d\u2029é"}`
	if string(f.body) != want {
		t.Errorf("wire bytes:\n got %s\nwant %s", f.body, want)
	}
}

func TestFinalizeUSB_SizeIsCheckedAgainOnceComplete(t *testing.T) {
	// The base payload fits; the PSK and seeded URL push it over. That must be
	// a refusal, not an outcome-unknown from inside the PROVISION send.
	city := strings.Repeat("a", usbprov.PayloadMax-60)
	_, errText := finalize(t, usbTestRegistry(t), map[string]any{"city": city, "enroll": true}, devLegacy, oneCandidate)
	if !contains(errText, "over the 1024-byte device limit") {
		t.Errorf("want the size refusal, got %q", errText)
	}
}

func TestFwFindsBrokerAlone(t *testing.T) {
	for fw, want := range map[string]bool{
		"1.0.0": true, "1.0.1": true, "2.3.4": true, "1.0.0-dev": true, "10.0.0": true,
		"0.12.0": false, "0.9.4": false, "": false, "dev": false, "v1.0.0": false, "1.0": false,
	} {
		if got := fwFindsBrokerAlone(fw); got != want {
			t.Errorf("fwFindsBrokerAlone(%q) = %v, want %v", fw, got, want)
		}
	}
}

func TestUSBProvisionReport_EnrolsNewDeviceWithoutBrokerURL(t *testing.T) {
	r := usbTestRegistry(t)
	out := usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{PSKHex: usbTestPSK, City: "Madrid"}, true, false), "")
	if !out.OK || !out.Registered || !out.Enrolled || out.PSKHex != "" || out.Note != "" {
		t.Fatalf("new device must be registered cleanly: %+v", out)
	}
	dev, err := r.Load(usbTestID)
	if err != nil {
		t.Fatalf("device not in registry: %v", err)
	}
	if dev.Active.PSKHex != usbTestPSK || dev.Active.BrokerURL != "" || dev.Active.City != "Madrid" {
		t.Errorf("registry record wrong: %+v", dev.Active.ConfigPayload)
	}
}

func TestUSBProvisionReport_DeviceErrorIsNotOKAndWritesNothing(t *testing.T) {
	// A RESULT frame is only the device ANSWERING. An error RESULT used to come
	// back as ok:true and still be mirrored into the registry.
	r := usbTestRegistry(t)
	out := usbProvisionReport(Deps{Registry: r}, usbResult(`{"error":"psk_hex must be 64 lowercase hex chars"}`),
		fin(usbProvisionPayload{PSKHex: usbTestPSK, BrokerURL: "http://10.0.0.5:8787"}, true, false), "")
	if out.OK || out.Registered || out.Reregistered || out.Enrolled {
		t.Fatalf("a device-side error must not report success: %+v", out)
	}
	if out.Error != "psk_hex must be 64 lowercase hex chars" {
		t.Errorf("the device's error must be surfaced, got %q", out.Error)
	}
	if _, err := r.Load(usbTestID); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("a device-side error must not write the registry (err=%v)", err)
	}
	// A failed write can leave a partial config, so a minted PSK is handed back.
	if out.PSKHex != usbTestPSK || out.Note != notePSKMaybeLive {
		t.Errorf("minted PSK must be returned on a device error: psk=%q note=%q", out.PSKHex, out.Note)
	}
	// A RESULT that is valid JSON but carries no ok:true is an error too.
	out = usbProvisionReport(Deps{Registry: r}, usbResult(`{"next":"rebooting"}`),
		fin(usbProvisionPayload{}, false, false), "")
	if out.OK || out.Error != "device rejected the provisioning payload" {
		t.Errorf("a RESULT without ok:true must not be ok: %+v", out)
	}
}

func TestUSBProvisionReport_ReusedPSKLeavesRegistryRecordAlone(t *testing.T) {
	// The headline WiFi-only call on a device this registry already knows: the
	// same PSK is re-sent and the record must NOT be replaced — ReplaceActive
	// resets the config version to 1 under a live device still at version N,
	// after which every staged pending is numbered too low to be applied.
	r := usbTestRegistry(t)
	if _, err := r.Register(usbTestID, registry.ConfigPayload{PSKHex: usbTestPSK, City: "Madrid"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := r.SetPending(usbTestID, registry.ConfigPayload{City: "Sevilla"}); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	out := usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{PSKHex: usbTestPSK}, false, true), "")
	if !out.OK || !out.Enrolled || out.Registered || out.Reregistered || !out.PSKReused {
		t.Fatalf("reuse must report enrolled without a registry write: %+v", out)
	}
	dev, _ := r.Load(usbTestID)
	if dev.Active.City != "Madrid" || dev.Pending == nil {
		t.Errorf("the registry record must be untouched: active=%+v pending=%v", dev.Active.ConfigPayload, dev.Pending)
	}

	// Passing that same key explicitly (reused=false) changes nothing: what
	// matters is that it is the key the registry already holds.
	out = usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{PSKHex: usbTestPSK}, false, false), "")
	if !out.Enrolled || out.Registered || out.Reregistered {
		t.Fatalf("an explicit PSK equal to the registry's must not rewrite the record: %+v", out)
	}
	if dev, _ = r.Load(usbTestID); dev.Active.City != "Madrid" || dev.Pending == nil {
		t.Errorf("the registry record must be untouched: active=%+v pending=%v", dev.Active.ConfigPayload, dev.Pending)
	}

	// With a broker_url the call is an explicit re-provision and converges the
	// record in place, as it always has.
	out = usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{PSKHex: usbTestPSK, BrokerURL: "http://10.0.0.5:8787"}, false, true), "")
	if !out.Reregistered || !out.Enrolled {
		t.Fatalf("broker_url + reuse must converge the record: %+v", out)
	}
	dev, _ = r.Load(usbTestID)
	if dev.Active.BrokerURL != "http://10.0.0.5:8787" || dev.Pending != nil {
		t.Errorf("record not converged: %+v pending=%v", dev.Active.ConfigPayload, dev.Pending)
	}
}

func TestUSBProvisionReport_EnrollFalseLeavesRegistryAlone(t *testing.T) {
	r := usbTestRegistry(t)
	wifi := "HomeNet"
	out := usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{WiFiSSID: &wifi, WiFiPass: &wifi}, false, false), "")
	if !out.OK || out.Enrolled || out.Registered || out.PSKHex != "" {
		t.Fatalf("enroll=false must succeed without enrolling: %+v", out)
	}
	if _, err := r.Load(usbTestID); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("enroll=false must not write the registry (err=%v)", err)
	}
}

func TestUSBProvisionReport_ProvidersReachTheRegistry(t *testing.T) {
	// The USB payload carries the "antigravity" wire key; the registry lift
	// must read that key, not the LAN payload's "gemini".
	r := usbTestRegistry(t)
	usbProvisionReport(Deps{Registry: r}, usbResult(usbResultOK),
		fin(usbProvisionPayload{
			PSKHex:    usbTestPSK,
			Providers: map[string]bool{"claude": true, "codex": false, "antigravity": true},
		}, true, false), "")
	dev, err := r.Load(usbTestID)
	if err != nil || dev.Active.ProviderModes == nil {
		t.Fatalf("providers not mirrored: dev=%v err=%v", dev, err)
	}
	if !dev.Active.ProviderModes.Gemini.Enabled() || dev.Active.ProviderModes.Codex.Enabled() {
		t.Errorf("provider modes wrong: %+v", dev.Active.ProviderModes)
	}
}

func TestUSBProvisionErrorReport_OutcomeUnknownEchoesMintedPSK(t *testing.T) {
	rep, _ := json.Marshal(usbProvisionErrorReport(usbprov.ErrOutcomeUnknown, usbTestPSK, true))
	if !contains(string(rep), `"outcome_unknown":true`) || !contains(string(rep), usbTestPSK) {
		t.Errorf("outcome-unknown must flag itself and hand back a minted PSK: %s", rep)
	}
	rep, _ = json.Marshal(usbProvisionErrorReport(usbprov.ErrOutcomeUnknown, usbTestPSK, false))
	if contains(string(rep), usbTestPSK) {
		t.Errorf("a reused/explicit PSK is already known and must not be echoed: %s", rep)
	}
}
