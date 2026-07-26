//go:build linux

package usbprov

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openPtyUsb(t *testing.T) (*os.File, string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("TIOCGPTN: %v", err)
	}
	slave := fmt.Sprintf("/dev/pts/%d", n)
	if _, err := os.Stat(slave); err != nil {
		m.Close()
		t.Skipf("slave missing: %v", err)
	}
	return m, slave
}

func TestOpenExclusive_CloseUnblocksRead(t *testing.T) {
	master, slave := openPtyUsb(t)
	defer master.Close()

	h, err := OpenExclusive(slave)
	if err != nil {
		t.Fatalf("OpenExclusive: %v", err)
	}

	// A read with no data pending must block, then unblock when Release closes
	// the fd — the property RunProvision's cancellation depends on. If the fd
	// were left OS-blocking (O_NONBLOCK cleared), Close could not interrupt it.
	readErr := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, e := h.Conn.Read(b)
		readErr <- e
	}()
	time.Sleep(50 * time.Millisecond) // let the read block

	select {
	case e := <-readErr:
		t.Fatalf("read returned before Close (%v) — it should have blocked", e)
	default:
	}

	if err := h.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case <-readErr:
		// good: Close unblocked the read
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a blocked Read")
	}
}

func TestOpenExclusive_SecondOpenIsBusy(t *testing.T) {
	master, slave := openPtyUsb(t)
	defer master.Close()

	h1, err := OpenExclusive(slave)
	if err != nil {
		t.Fatalf("first OpenExclusive: %v", err)
	}
	defer h1.Release()

	// A second exclusive open of the same port must be reported as ErrPortBusy
	// (the flock is held) — the arbitration that stops two runtimes from
	// byte-splitting — not silently succeed. (Re-open after release is a real-
	// device property the tailer reconnect test covers; on a pty TIOCEXCL does
	// not clear cleanly on close, so it is not asserted here.)
	_, err = OpenExclusive(slave)
	if !errors.Is(err, ErrPortBusy) {
		t.Fatalf("second OpenExclusive: want ErrPortBusy, got %v", err)
	}
}
