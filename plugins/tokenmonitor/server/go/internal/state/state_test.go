package state

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNew_StartsUnknown(t *testing.T) {
	s := New()
	if got := s.Snapshot().Role; got != "unknown" {
		t.Errorf("role = %q, want unknown", got)
	}
}

func TestSetRole_TracksTransitions(t *testing.T) {
	s := New()
	initial := s.Snapshot().RoleSince

	time.Sleep(2 * time.Millisecond)
	s.SetRole(RoleLeader)
	if got := s.Snapshot().Role; got != "leader" {
		t.Fatalf("role = %q, want leader", got)
	}
	afterLeader := s.Snapshot().RoleSince
	if !afterLeader.After(initial) {
		t.Error("RoleSince did not advance on transition")
	}

	// Setting the same role should not bump RoleSince.
	time.Sleep(2 * time.Millisecond)
	s.SetRole(RoleLeader)
	if got := s.Snapshot().RoleSince; !got.Equal(afterLeader) {
		t.Error("RoleSince advanced on no-op SetRole")
	}
}

func TestRecordRequest(t *testing.T) {
	s := New()
	now := time.Unix(1700000000, 0)
	s.RecordRequest("192.168.1.99:54321", 200, now)
	snap := s.Snapshot()
	if snap.LastRequestAt != now {
		t.Errorf("LastRequestAt = %v, want %v", snap.LastRequestAt, now)
	}
	if snap.LastRequestRemote != "192.168.1.99:54321" {
		t.Errorf("LastRequestRemote = %q", snap.LastRequestRemote)
	}
	if snap.LastRequestStatus != 200 {
		t.Errorf("LastRequestStatus = %d", snap.LastRequestStatus)
	}
	if snap.RequestsTotal != 1 {
		t.Errorf("RequestsTotal = %d, want 1", snap.RequestsTotal)
	}

	s.RecordRequest("x", 401, now.Add(time.Second))
	if snap := s.Snapshot(); snap.RequestsTotal != 2 {
		t.Errorf("RequestsTotal after 2 records = %d", snap.RequestsTotal)
	}
}

func TestUpdate_OmittedUntilKnown(t *testing.T) {
	s := New()
	// Before any check: fields must be entirely absent from the JSON so callers
	// can distinguish "not yet checked" from "up to date".
	b, _ := json.Marshal(s.Snapshot())
	if strings.Contains(string(b), "update_available") || strings.Contains(string(b), "latest_version") {
		t.Fatalf("unknown verdict leaked into snapshot: %s", b)
	}

	s.SetUpdate(UpdateInfo{Known: true, Outdated: true, Current: "0.9.2", Latest: "0.9.4"})
	snap := s.Snapshot()
	if snap.UpdateAvailable == nil || !*snap.UpdateAvailable {
		t.Errorf("UpdateAvailable = %v, want true", snap.UpdateAvailable)
	}
	if snap.LatestVersion != "0.9.4" {
		t.Errorf("LatestVersion = %q, want 0.9.4", snap.LatestVersion)
	}

	// Known and up to date: update_available present and false.
	s.SetUpdate(UpdateInfo{Known: true, Outdated: false, Current: "0.9.4", Latest: "0.9.4"})
	if snap := s.Snapshot(); snap.UpdateAvailable == nil || *snap.UpdateAvailable {
		t.Errorf("UpdateAvailable = %v, want non-nil false", snap.UpdateAvailable)
	}
}
