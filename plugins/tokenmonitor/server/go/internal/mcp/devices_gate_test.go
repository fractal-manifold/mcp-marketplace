package mcp

// The hand-staging tools must reach the same verdict the device will.
//
// set_device_pending, publish_firmware and revert_firmware are how an operator
// pushes a build at a specific unit, and until now they wrote whatever they
// were handed on the grounds that "the device-side gate is authoritative". It
// is — but its refusal is silent: the device clears the pending, logs nothing
// to the broker and reboots. So the operator's only feedback was a device that
// stubbornly kept running the old version. Reading a manifest's fields needs no
// key, so there was never a reason to stage blind.

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

const gateTestID = "ab12cd34"

// gateTestRegistry gives a production unit (non-DEV serial) at the given
// anti-rollback floor — the shape of every unit in the field.
func gateTestRegistry(t *testing.T, floor uint32) *registry.Registry {
	t.Helper()
	r, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, err := r.Register(gateTestID, registry.ConfigPayload{
		PSKHex:    strings.Repeat("ab", 32),
		BrokerURL: "https://broker.example",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.SetSerial(gateTestID, "CWM-S1-MAD-2620-000001-0", "S1"); err != nil {
		t.Fatalf("SetSerial: %v", err)
	}
	if floor > 0 {
		if err := r.RecordMinSV(gateTestID, floor); err != nil {
			t.Fatalf("RecordMinSV: %v", err)
		}
	}
	return r
}

// manifestB64 builds the canonical manifest bytes the signer emits. The
// signature is not checked here — the broker holds no key and never verifies —
// so any 88-char placeholder stands in for one.
func manifestB64(sku, version string, minSV uint32, sha string, channel string) string {
	open := "{"
	if channel != "" {
		open = fmt.Sprintf("{%q:%q,", "channel", channel)
	}
	canonical := fmt.Sprintf(
		open+"\"key_id\":\"ed25519-test\",\"min_secure_version\":%d,\"sha256\":%q,"+
			"\"size\":2048,\"sku\":%q,\"version\":%q}",
		minSV, sha, sku, version)
	return base64.StdEncoding.EncodeToString([]byte(canonical))
}

const fakeSig = "c2lnbmF0dXJlLXBsYWNlaG9sZGVyLW5vdC12ZXJpZmllZC1ieS10aGUtYnJva2VyLWV2ZXItLS0tLS0tLS0tLS0="

func callTool(t *testing.T, r *registry.Registry, name string, h func(Deps) server.ToolHandlerFunc, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	res, err := h(Deps{Registry: r})(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

// The incident, reached through the operator's hands rather than the auto
// loop: the published 1.0.0 manifest declares packed(0.11.4) as its floor, and
// the unit in front of you already confirmed 1.0.0 before being flashed back
// down over USB (tmon_min_sv is monotonic and survives the flash).
func TestSetDevicePending_RefusesManifestBelowTheDeviceFloor(t *testing.T) {
	r := gateTestRegistry(t, 16777216) // packed(1.0.0)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-1.0.0.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "1.0.0",
		"firmware_manifest_b64":     manifestB64("S1", "1.0.0", 720900, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError {
		t.Fatal("staging a manifest the device refuses must be an error, not a success")
	}
	txt := resultText(t, res)
	for _, want := range []string{"min-sv-below-floor", "720900", "16777216", "min_secure_version"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("the message must name %q so the operator can fix it; got %q", want, txt)
		}
	}
	// And nothing was written: a refused stage costs the device nothing.
	dev, err := r.Load(gateTestID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.Pending != nil {
		t.Fatalf("nothing should have been staged; got %+v", dev.Pending)
	}
}

// The same release with the floor tmtools would have picked stages fine — the
// pair that shows the refusal is about the manifest, not the version.
func TestSetDevicePending_StagesTheConformantManifest(t *testing.T) {
	r := gateTestRegistry(t, 16777216)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-1.0.1.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "1.0.1",
		"firmware_manifest_b64":     manifestB64("S1", "1.0.1", 16777217, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if res.IsError {
		t.Fatalf("conformant manifest must stage; got %q", resultText(t, res))
	}
	dev, err := r.Load(gateTestID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.Pending == nil || dev.Pending.FirmwareVersion != "1.0.1" {
		t.Fatalf("expected 1.0.1 staged; got %+v", dev.Pending)
	}
}

// A manifest left over from the previous build is the most common hand-staging
// slip, and on-device it is indistinguishable from the floor case: silence.
func TestSetDevicePending_RefusesManifestForADifferentImage(t *testing.T) {
	r := gateTestRegistry(t, 0)
	staged := strings.Repeat("b", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-1.0.1.bin",
		"firmware_sha256":           staged,
		"firmware_version":          "1.0.1",
		"firmware_manifest_b64":     manifestB64("S1", "1.0.1", 16777217, strings.Repeat("a", 64), ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError || !strings.Contains(resultText(t, res), "sha-mismatch") {
		t.Fatalf("expected sha-mismatch, got err=%v %q", res.IsError, resultText(t, res))
	}
}

func TestSetDevicePending_RefusesManifestForAnotherSKU(t *testing.T) {
	r := gateTestRegistry(t, 0)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S2-1.0.1.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "1.0.1",
		"firmware_manifest_b64":     manifestB64("S2", "1.0.1", 16777217, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError || !strings.Contains(resultText(t, res), "sku") {
		t.Fatalf("expected an sku refusal, got err=%v %q", res.IsError, resultText(t, res))
	}
}

// Dev-channel firmware on a production serial: the device gates on the
// serial's FAC field, so no amount of broker-side channel config makes this
// install.
func TestSetDevicePending_RefusesDevChannelOnProduction(t *testing.T) {
	r := gateTestRegistry(t, 0)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-dev.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "1.0.1-dev.202609081200",
		"firmware_manifest_b64":     manifestB64("S1", "1.0.1-dev.202609081200", 16777217, sha, "dev"),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError || !strings.Contains(resultText(t, res), "dev-channel-on-production") {
		t.Fatalf("expected dev-channel-on-production, got err=%v %q", res.IsError, resultText(t, res))
	}
}

// An unsigned stage carries nothing to predict from — CI does this against dev
// units built with TMON_OTA_UNSIGNED, and the gate must not stand in its way.
func TestSetDevicePending_UnsignedStageIsNotJudged(t *testing.T) {
	r := gateTestRegistry(t, 16777216)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":        gateTestID,
		"firmware_url":     "https://downloads.example/tmon-S1-0.11.4.bin",
		"firmware_sha256":  strings.Repeat("a", 64),
		"firmware_version": "0.11.4",
	})
	if res.IsError {
		t.Fatalf("an unsigned stage must still be possible; got %q", resultText(t, res))
	}
}

// The firmware drops any pending whose URL is ≥256 chars before the gate ever
// runs (config_sync.c) — another silent failure worth naming here.
func TestSetDevicePending_RefusesAnOverlongURL(t *testing.T) {
	r := gateTestRegistry(t, 0)
	long := "https://downloads.example/" + strings.Repeat("x", 240) + ".bin"
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              long,
		"firmware_sha256":           sha,
		"firmware_version":          "1.0.1",
		"firmware_manifest_b64":     manifestB64("S1", "1.0.1", 16777217, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError || !strings.Contains(resultText(t, res), "256") {
		t.Fatalf("expected a URL-length refusal, got err=%v %q", res.IsError, resultText(t, res))
	}
}

// revert_firmware used to check an operator-typed target_min_secure_version and
// nothing else, which answered the wrong question: once the floor has risen,
// gate 4b (packed(version) < floor) refuses the older image no matter what its
// manifest declares. A revert past the floor is simply not possible over OTA.
func TestRevertFirmware_RefusesADowngradeBelowTheFloor(t *testing.T) {
	r := gateTestRegistry(t, 16777216) // packed(1.0.0)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_revert_firmware", handleRevertFirmware, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-0.11.4.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "0.11.4",
		"firmware_manifest_b64":     manifestB64("S1", "0.11.4", 720900, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if !res.IsError {
		t.Fatal("a revert the device cannot perform must be refused, not staged")
	}
	txt := resultText(t, res)
	if !strings.Contains(txt, "min-sv-below-floor") && !strings.Contains(txt, "version-below-floor") {
		t.Fatalf("expected an anti-rollback verdict, got %q", txt)
	}
	dev, err := r.Load(gateTestID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.BlockedFirmwareVersion != "" {
		t.Fatalf("a refused revert must not tombstone anything; got %q", dev.BlockedFirmwareVersion)
	}
}

// A revert within the floor is the case the tool exists for, and it still works.
func TestRevertFirmware_AllowsARevertTheFloorPermits(t *testing.T) {
	r := gateTestRegistry(t, 720896) // packed(0.11.0)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_revert_firmware", handleRevertFirmware, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-0.11.4.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "0.11.4",
		"firmware_manifest_b64":     manifestB64("S1", "0.11.4", 720900, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
	})
	if res.IsError {
		t.Fatalf("this revert is installable; got %q", resultText(t, res))
	}
	dev, err := r.Load(gateTestID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.Pending == nil || dev.Pending.FirmwareVersion != "0.11.4" {
		t.Fatalf("expected 0.11.4 staged; got %+v", dev.Pending)
	}
}

// target_min_secure_version is kept as a cross-check on the manifest, not as
// the check: stating a floor the artifact does not declare means one of the two
// came from a different build.
func TestRevertFirmware_TargetFloorMustMatchTheManifest(t *testing.T) {
	r := gateTestRegistry(t, 720896)
	sha := strings.Repeat("a", 64)
	res := callTool(t, r, "tokenmonitor_revert_firmware", handleRevertFirmware, map[string]any{
		"device_id":                 gateTestID,
		"firmware_url":              "https://downloads.example/tmon-S1-0.11.4.bin",
		"firmware_sha256":           sha,
		"firmware_version":          "0.11.4",
		"firmware_manifest_b64":     manifestB64("S1", "0.11.4", 720900, sha, ""),
		"firmware_manifest_sig_b64": fakeSig,
		"target_min_secure_version": 720899,
	})
	if !res.IsError || !strings.Contains(resultText(t, res), "720899") {
		t.Fatalf("expected the disagreement to be named, got err=%v %q", res.IsError, resultText(t, res))
	}
}

// publishTo is the local-hosting path of publish_firmware, pointed at a
// throwaway HOME so the copy lands in a temp firmware dir.
func publishTo(t *testing.T, r *registry.Registry, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := home + "/tokenmonitor.bin"
	if err := os.WriteFile(bin, []byte("not really a firmware image"), 0o644); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	args["bin_path"] = bin
	d := Deps{Registry: r, Cfg: &config.Config{}}
	d.Cfg.Server.Port = 8765
	req := mcp.CallToolRequest{}
	req.Params.Name = "tokenmonitor_publish_firmware"
	req.Params.Arguments = args
	res, err := handlePublishFirmware(d)(context.Background(), req)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

// reportRunning puts the device on a given running version, the way an
// authenticated /sync does.
func reportRunning(t *testing.T, r *registry.Registry, version, localAddr string) {
	t.Helper()
	if err := r.SetActiveFirmwareVersion(gateTestID, version, nil); err != nil {
		t.Fatalf("SetActiveFirmwareVersion: %v", err)
	}
	if err := r.Touch(gateTestID, "192.168.2.44:9000", localAddr); err != nil {
		t.Fatalf("Touch: %v", err)
	}
}

// A unit older than 0.10.2 has no CONFIG_TMON_OTA_ALLOW_HTTP: it drops any
// http:// pending in config_sync.c without a word. Serving the .bin off the
// broker's own /firmware/ endpoint is exactly what the local path does, so this
// publish can only ever be silence — say so instead.
func TestPublishFirmware_RefusesHTTPBelow0102(t *testing.T) {
	r := gateTestRegistry(t, 0)
	reportRunning(t, r, "0.10.0", "192.168.2.28:8765")
	res := publishTo(t, r, map[string]any{
		"device_id":        gateTestID,
		"firmware_version": "1.0.1",
	})
	if !res.IsError {
		t.Fatal("an http publish to a pre-0.10.2 unit must be refused")
	}
	txt := resultText(t, res)
	if !strings.Contains(txt, "0.10.2") || !strings.Contains(txt, "external_url") {
		t.Fatalf("the message must name the cutoff and the way out; got %q", txt)
	}
	dev, err := r.Load(gateTestID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if dev.Pending != nil {
		t.Fatalf("nothing should have been staged; got %+v", dev.Pending)
	}
}

// From 0.10.2 the same publish is fine — signed manifest and SHA are what
// establish trust, not TLS — and it goes out on the origin the device proved.
func TestPublishFirmware_HTTPIsFineFrom0102AndUsesTheProvenOrigin(t *testing.T) {
	r := gateTestRegistry(t, 0)
	reportRunning(t, r, "0.10.2", "192.168.2.28:8765")
	res := publishTo(t, r, map[string]any{
		"device_id":        gateTestID,
		"firmware_version": "1.0.1",
	})
	if res.IsError {
		t.Fatalf("0.10.2 accepts http OTA; got %q", resultText(t, res))
	}
	txt := resultText(t, res)
	if !strings.Contains(txt, "http://192.168.2.28:8765/firmware/") {
		t.Fatalf("firmware_url must sit on the address the device dialled; got %q", txt)
	}
}

// A device that has never reported a version is not evidence of an old one:
// refusing here would block the first publish to a freshly registered unit.
func TestPublishFirmware_UnknownVersionIsNotTreatedAsOld(t *testing.T) {
	r := gateTestRegistry(t, 0)
	reportRunning(t, r, "", "192.168.2.28:8765")
	res := publishTo(t, r, map[string]any{
		"device_id":        gateTestID,
		"firmware_version": "1.0.1",
	})
	if res.IsError {
		t.Fatalf("an unknown running version must not block a publish; got %q", resultText(t, res))
	}
}
