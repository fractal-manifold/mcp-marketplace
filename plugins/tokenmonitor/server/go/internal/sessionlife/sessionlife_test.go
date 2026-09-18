package sessionlife

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeaseCrossProcessFileLifecycle(t *testing.T) {
	t.Setenv("TMON_RUNTIME_DIR", t.TempDir())
	l, err := NewLease()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := liveSessionCount(time.Now()); err != nil || n != 1 {
		t.Fatalf("live sessions = %d, err=%v", n, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := liveSessionCount(time.Now()); err != nil || n != 0 {
		t.Fatalf("live sessions after close = %d, err=%v", n, err)
	}
}

func TestStaleLeaseIsReaped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMON_RUNTIME_DIR", dir)
	if err := os.MkdirAll(filepath.Join(dir, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "sessions", "session-dead")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-staleAfter - time.Second)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if n, err := liveSessionCount(time.Now()); err != nil || n != 0 {
		t.Fatalf("live sessions = %d, err=%v", n, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("stale lease was not removed: %v", err)
	}
}

func TestDaemonLockIsSingletonAndRecoverable(t *testing.T) {
	t.Setenv("TMON_RUNTIME_DIR", t.TempDir())
	a, ok, err := AcquireDaemonLock()
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	if b, ok, err := AcquireDaemonLock(); err != nil || ok || b != nil {
		t.Fatalf("second lock: lock=%v ok=%v err=%v", b, ok, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	c, ok, err := AcquireDaemonLock()
	if err != nil || !ok {
		t.Fatalf("reacquire: ok=%v err=%v", ok, err)
	}
	_ = c.Close()
}

func TestDaemonLogTail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMON_RUNTIME_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "broker.log"), []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, total, err := DaemonLogTail(2)
	if err != nil || total != 3 || len(lines) != 2 || lines[0] != "two" || lines[1] != "three" {
		t.Fatalf("tail=%q total=%d err=%v", lines, total, err)
	}
}

func TestMonitorCancelsAfterGrace(t *testing.T) {
	t.Setenv("TMON_RUNTIME_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancellation path must return immediately and never hang.
	done := make(chan struct{})
	go func() { Monitor(ctx, func() {}, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop with its context")
	}
}
