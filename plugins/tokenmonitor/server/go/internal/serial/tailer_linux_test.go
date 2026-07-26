//go:build linux

package serial_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/serial"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// openPty returns a pty master and the slave device path. The tailer opens the
// slave (a real tty, so its termios ioctls work); the test drives the master.
func openPty(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx available: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("unlockpt failed: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("TIOCGPTN failed: %v", err)
	}
	slave := fmt.Sprintf("/dev/pts/%d", n)
	if _, err := os.Stat(slave); err != nil {
		m.Close()
		t.Skipf("slave %s missing: %v", slave, err)
	}
	return m, slave
}

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestTailer_SuspendFreesPortThenResume(t *testing.T) {
	master, slave := openPty(t)
	defer master.Close()

	buf := &safeBuf{}
	tl := &serial.Tailer{Device: slave, Writer: buf, Logger: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tl.Run(ctx)

	waitFor(t, tl.Connected, "tailer to connect")

	// It reads console bytes from the master side.
	if _, err := master.WriteString("hello world\r\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(buf.String(), "hello world") }, "tailer to read a line")

	canonical, err := usbprov.CanonicalPort(slave)
	if err != nil {
		t.Fatal(err)
	}

	// Suspend must block until the port is actually free, then a competing
	// acquire of the SAME lock must succeed (proving the tailer released it).
	if err := tl.SuspendPort(canonical); err != nil {
		t.Fatalf("SuspendPort: %v", err)
	}
	if tl.Connected() {
		t.Error("tailer must be disconnected after SuspendPort returns")
	}
	rel, err := usbprov.AcquirePortLock(canonical)
	if err != nil {
		t.Fatalf("port lock must be free after suspend, got: %v", err)
	}
	// While the lock is held (simulating a provisioning session), the tailer
	// must NOT reconnect even though it isn't suspended-gated on this path.
	_ = rel()

	// Resume → the tailer reacquires and reconnects.
	tl.ResumePort(canonical)
	waitFor(t, tl.Connected, "tailer to reconnect after ResumePort")
}

// TestTailer_ResumeWorksWhenDeviceNodeIsGone is the regression for the wedge on
// the HAPPY path: a successful usb_provision makes the device reboot, so the USB
// node disappears for a second or two — exactly while the follower releases its
// lease and the manager calls ResumePort. If ResumePort re-resolved the device
// path it would fail to resolve, return early, and leave `suspended` set with
// nothing left to ever clear it: firmware logging dead until process restart.
// ResumePort must instead match the canonical string it was suspended FOR.
func TestTailer_ResumeWorksWhenDeviceNodeIsGone(t *testing.T) {
	master, slave := openPty(t)
	defer master.Close()

	// Point the tailer at the port through a SYMLINK, the way a real deployment
	// does (/dev/esp32s3 → ttyACM0). Deleting the link below reproduces exactly
	// what a post-provision reboot does to the configured path: it stops
	// resolving, so any attempt to re-derive the canonical path from t.Device
	// fails — while the underlying port itself is still perfectly usable.
	link := filepath.Join(t.TempDir(), "esp32s3")
	if err := os.Symlink(slave, link); err != nil {
		t.Fatal(err)
	}

	tl := &serial.Tailer{Device: link, Writer: io.Discard, Logger: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tl.Run(ctx)
	waitFor(t, tl.Connected, "tailer to connect")

	canonical, err := usbprov.CanonicalPort(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := tl.SuspendPort(canonical); err != nil {
		t.Fatalf("SuspendPort: %v", err)
	}
	if tl.Connected() {
		t.Fatal("tailer must be disconnected after SuspendPort")
	}

	// The device drops off the bus: the configured path no longer resolves.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := usbprov.CanonicalPort(link); err == nil {
		t.Fatal("precondition: the device path must be unresolvable for this test")
	}

	// Lease released WHILE the node is away → ResumePort with the canonical
	// string it was granted. This MUST ungate the tailer even though t.Device is
	// unresolvable at this instant. (The old code re-resolved t.Device here,
	// failed, and returned with `suspended` still set — permanently wedged.)
	tl.ResumePort(canonical)

	// The device finishes rebooting and re-enumerates at the same path.
	if err := os.Symlink(slave, link); err != nil {
		t.Fatal(err)
	}

	// An ungated tailer now reconnects on its next retry. A wedged one stays
	// parked in the suspend gate forever, however long the device is back.
	waitFor(t, tl.Connected, "tailer to reconnect once the device re-enumerates after ResumePort")
}

func TestTailer_SuspendForeignPortIsNoop(t *testing.T) {
	// SuspendPort for a port this tailer does not own must return immediately
	// (never block) and leave it running.
	master, slave := openPty(t)
	defer master.Close()

	tl := &serial.Tailer{Device: slave, Writer: io.Discard, Logger: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tl.Run(ctx)
	waitFor(t, tl.Connected, "tailer to connect")

	done := make(chan error, 1)
	go func() { done <- tl.SuspendPort("/dev/ttyDOESNOTEXIST99") }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("foreign SuspendPort returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("foreign SuspendPort blocked — must be a no-op")
	}
	if !tl.Connected() {
		t.Error("tailer must stay connected after a foreign SuspendPort")
	}
}
