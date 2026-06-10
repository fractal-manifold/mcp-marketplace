package registry

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// statMode returns the file mode bits (perm only) of path.
func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestRegistry_PermsTightenedOnSave verifies the store is owner-only:
// the device TOML is 0600, the devices dir is 0700, and the per-device
// .lock is 0600 — including when an older broker created the dir/lock
// with the lax 0755/0644 modes (saveLocked chmods them back down).
func TestRegistry_PermsTightenedOnSave(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}
	dir := t.TempDir()
	// Simulate a legacy-deployed store: a group/other-readable dir.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	reg, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// New() should tighten the dir on open.
	if m := statMode(t, dir); m != 0o700 {
		t.Errorf("after New: dir mode = %o, want 700", m)
	}

	const id = "ab12cd34"
	psk := ""
	for i := 0; i < 32; i++ {
		psk += "ab"
	}
	if _, err := reg.Register(id, ConfigPayload{PSKHex: psk, BrokerURL: "http://x"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	tomlPath := filepath.Join(dir, id+".toml")
	lockPath := tomlPath + ".lock"

	if m := statMode(t, tomlPath); m != 0o600 {
		t.Errorf("device TOML mode = %o, want 600", m)
	}
	if m := statMode(t, dir); m != 0o700 {
		t.Errorf("devices dir mode = %o, want 700", m)
	}
	if m := statMode(t, lockPath); m != 0o600 {
		t.Errorf("lock mode = %o, want 600", m)
	}

	// Now loosen the dir + lock as a stale older broker would have, then
	// trigger another save: saveLocked must re-tighten them.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetPending(id, ConfigPayload{City: "Madrid"}); err != nil {
		t.Fatalf("SetPending: %v", err)
	}
	if m := statMode(t, dir); m != 0o700 {
		t.Errorf("after re-save: dir mode = %o, want 700", m)
	}
	if m := statMode(t, lockPath); m != 0o600 {
		t.Errorf("after re-save: lock mode = %o, want 600", m)
	}
	if m := statMode(t, tomlPath); m != 0o600 {
		t.Errorf("after re-save: device TOML mode = %o, want 600", m)
	}
}
