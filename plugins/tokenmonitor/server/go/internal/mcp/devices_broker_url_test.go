package mcp

// broker_url on tokenmonitor_set_device_pending is a legacy re-point: firmware
// older than 1.0.1 cannot follow a broker that moved any other way, and
// firmware from 1.0.1 resolves the broker by mDNS and must not be handed one.

import (
	"encoding/json"
	"io"
	"log"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/registry"
)

const (
	repointOld = "http://192.168.1.28:8765"
	repointNew = "http://192.168.1.50:8765"
)

// repointRegistry is a registered device that last reported firmware `fw`
// ("" = it has never been seen).
func repointRegistry(t *testing.T, fw string) *registry.Registry {
	t.Helper()
	r, err := registry.New(t.TempDir())
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, err := r.Register(gateTestID, registry.ConfigPayload{PSKHex: lanTestPSK, BrokerURL: repointOld}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if fw != "" {
		if err := r.SetActiveFirmwareVersion(gateTestID, fw, log.New(io.Discard, "", 0)); err != nil {
			t.Fatalf("set fw: %v", err)
		}
	}
	return r
}

func stageBrokerURL(t *testing.T, r *registry.Registry, url string) (map[string]any, string) {
	t.Helper()
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending,
		map[string]any{"device_id": gateTestID, "broker_url": url})
	if res.IsError {
		return nil, errText(t, res)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].(mcp.TextContent).Text), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out, ""
}

func TestSetDevicePending_BrokerURLStagedForLegacyFirmware(t *testing.T) {
	for _, fw := range []string{"0.10.3", "0.12.0", "1.0.0", "1.0.0-dev.202609011200"} {
		r := repointRegistry(t, fw)
		out, errMsg := stageBrokerURL(t, r, repointNew)
		if errMsg != "" {
			t.Fatalf("fw %s: a legacy device must accept a re-point: %s", fw, errMsg)
		}
		if out["note"] != nil {
			t.Errorf("fw %s: nothing is held for a known legacy device: %v", fw, out["note"])
		}
		dev := out["device"].(map[string]any)
		if changes, _ := dev["pending_changes"].([]any); len(changes) != 1 || changes[0] != "broker_url" {
			t.Errorf("fw %s: pending_changes = %v", fw, dev["pending_changes"])
		}
		rec, _ := r.Load(gateTestID)
		if rec.Pending == nil || rec.Pending.BrokerURL != repointNew || rec.Active.BrokerURL != repointOld {
			t.Errorf("fw %s: the address must be staged, not applied: %+v", fw, rec)
		}
	}
}

func TestSetDevicePending_BrokerURLRefusedFrom101(t *testing.T) {
	for _, fw := range []string{"1.0.1", "1.0.1-dev.202609181200", "1.0.2", "2.0.0"} {
		r := repointRegistry(t, fw)
		_, errMsg := stageBrokerURL(t, r, repointNew)
		want := "broker_url cannot be staged for device " + gateTestID + ": it reports firmware " + fw +
			", and firmware 1.0.1 or newer resolves the broker by mDNS and does not take a pushed address. Nothing was staged."
		if !contains(errMsg, want) {
			t.Fatalf("fw %s: want the canonical refusal, got %s", fw, errMsg)
		}
		if rec, _ := r.Load(gateTestID); rec.Pending != nil {
			t.Errorf("fw %s: a refusal must stage nothing: %+v", fw, rec.Pending)
		}
	}
	// The refusal covers the whole call: nothing else in it is staged either.
	r := repointRegistry(t, "1.0.2")
	res := callTool(t, r, "tokenmonitor_set_device_pending", handleSetDevicePending,
		map[string]any{"device_id": gateTestID, "broker_url": repointNew, "city": "Paris"})
	if rec, _ := r.Load(gateTestID); !res.IsError || rec.Pending != nil {
		t.Errorf("a refused call must stage nothing at all: %+v", rec.Pending)
	}
}

func TestSetDevicePending_BrokerURLHeldWhileFirmwareUnknown(t *testing.T) {
	for _, fw := range []string{"", "dev"} {
		r := repointRegistry(t, fw)
		out, errMsg := stageBrokerURL(t, r, repointNew)
		if errMsg != "" {
			t.Fatalf("fw %q: an unseen device must accept the staging: %s", fw, errMsg)
		}
		if out["note"] != noteBrokerURLHeld {
			t.Errorf("fw %q: the response must say the address is held: %v", fw, out["note"])
		}
		dev := out["device"].(map[string]any)
		if changes, _ := dev["pending_changes"].([]any); len(changes) != 1 || changes[0] != labelBrokerURLHeld {
			t.Errorf("fw %q: pending_changes = %v", fw, dev["pending_changes"])
		}
	}
}

func TestSetDevicePending_BrokerURLShape(t *testing.T) {
	r := repointRegistry(t, "0.12.0")
	long := "http://" + string(make([]byte, 0)) + "a"
	for len(long) <= 127 {
		long += "a"
	}
	for _, bad := range []string{"192.168.1.50:8765", "ftp://192.168.1.50", long} {
		if _, errMsg := stageBrokerURL(t, r, bad); !contains(errMsg, errBrokerURLShape) {
			t.Errorf("%q: want the shape error, got %s", bad, errMsg)
		}
	}
}

func TestSummarise_BrokerURLLabelsAndDropReport(t *testing.T) {
	// A device that upgraded between the staging and its next poll: until the
	// poll drops the address, the listing says that is what will happen.
	r := repointRegistry(t, "1.0.0")
	if _, errMsg := stageBrokerURL(t, r, repointNew); errMsg != "" {
		t.Fatal(errMsg)
	}
	if err := r.SetActiveFirmwareVersion(gateTestID, "1.0.2", log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	rec, _ := r.Load(gateTestID)
	if s := summarise(rec); len(s.PendingChanges) == 0 || s.PendingChanges[0] != labelBrokerURLDrop {
		t.Errorf("pending_changes = %v", s.PendingChanges)
	}
	// After the drop the listing reports it.
	if dropped, err := r.DropPendingBrokerURL(gateTestID, 1); err != nil || dropped != repointNew {
		t.Fatalf("drop: %q %v", dropped, err)
	}
	rec, _ = r.Load(gateTestID)
	s := summarise(rec)
	if s.BrokerURLDropped != repointNew || s.ActiveBrokerURL != repointOld || s.PendingVersion != 3 {
		t.Errorf("the drop must be reported: %+v", s)
	}
	for _, c := range s.PendingChanges {
		if contains(c, "broker_url") {
			t.Errorf("the address is no longer pending: %v", s.PendingChanges)
		}
	}
}

// A unit that took the re-point while still legacy and upgraded before its
// acknowledging poll reports the pending's own version: it did apply the
// address, so nothing is dropped and the acknowledgement promotes it.
func TestDropPendingBrokerURL_LeavesAnAppliedRepointAlone(t *testing.T) {
	r := repointRegistry(t, "1.0.0")
	if _, errMsg := stageBrokerURL(t, r, repointNew); errMsg != "" {
		t.Fatal(errMsg)
	}
	if dropped, err := r.DropPendingBrokerURL(gateTestID, 2); err != nil || dropped != "" {
		t.Fatalf("drop: %q %v", dropped, err)
	}
	if promoted, err := r.MaybePromote(gateTestID, 2, false); err != nil || !promoted {
		t.Fatalf("promote: %v %v", promoted, err)
	}
	rec, _ := r.Load(gateTestID)
	if rec.Active.BrokerURL != repointNew || rec.BrokerURLDropped != "" {
		t.Errorf("the applied address must be recorded: %+v", rec)
	}
}
