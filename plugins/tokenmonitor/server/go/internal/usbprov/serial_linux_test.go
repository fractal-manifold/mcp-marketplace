//go:build linux

package usbprov

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireLock_ExclusiveThenBusy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lk")
	const dev = "/dev/ttyACM0"

	lf, err := acquireLockIn(dir, dev)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A second acquire on the same device path must fail fast with ErrPortBusy,
	// not block.
	if _, err := acquireLockIn(dir, dev); !errors.Is(err, ErrPortBusy) {
		t.Fatalf("second acquire: want ErrPortBusy, got %v", err)
	}

	// After release, it is acquirable again.
	if err := releaseLock(lf); err != nil {
		t.Fatalf("release: %v", err)
	}
	lf2, err := acquireLockIn(dir, dev)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = releaseLock(lf2)
}

func TestAcquireLock_DistinctPathsDoNotCollide(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lk")
	a, err := acquireLockIn(dir, "/dev/ttyACM0")
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer releaseLock(a)
	// A different device path hashes to a different lock-file, so both can be
	// held at once.
	b, err := acquireLockIn(dir, "/dev/ttyACM1")
	if err != nil {
		t.Fatalf("acquire B (distinct path must not collide): %v", err)
	}
	_ = releaseLock(b)
}

func TestSecureLockDir_RejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := secureLockDir(link); err == nil {
		t.Error("a symlinked lock dir must be rejected")
	}
}

func TestSecureLockDir_RejectsGroupOrWorldAccess(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "loose")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Mkdir is subject to umask; force the loose bits on.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := secureLockDir(dir); err == nil {
		t.Error("a group/world-accessible lock dir must be rejected")
	}
}

func TestSecureLockDir_AcceptsAndCreates(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "fresh")
	if err := secureLockDir(dir); err != nil {
		t.Fatalf("creating a fresh 0700 dir must succeed: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("created dir perm = %#o, want 0700", fi.Mode().Perm())
	}
	// Second call on the now-existing safe dir must also pass.
	if err := secureLockDir(dir); err != nil {
		t.Errorf("revalidating an existing safe dir must succeed: %v", err)
	}
}

func TestAcquireLock_LockFileNamedByHash(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lk")
	lf, err := acquireLockIn(dir, "/dev/ttyACM0")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer releaseLock(lf)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly one lock file, got %d", len(entries))
	}
	name := entries[0].Name()
	if filepath.Ext(name) != ".lock" || len(name) != len("serial-")+64+len(".lock") {
		t.Errorf("unexpected lock file name %q (want serial-<64 hex>.lock)", name)
	}
}
