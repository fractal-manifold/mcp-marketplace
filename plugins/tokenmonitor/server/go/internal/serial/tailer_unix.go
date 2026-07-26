//go:build !windows

package serial

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

func (t *Tailer) tailOnce(ctx context.Context) error {
	// Resolve to the canonical identity shared with the lease/lock, so the port
	// lock the tailer takes is the SAME one a provisioning session takes.
	canonical, err := usbprov.CanonicalPort(t.Device)
	if err != nil {
		return err // device absent → Run backs off and retries
	}

	// Acquire the port lock and open the device UNDER the gate mutex, together
	// with a suspend re-check: this makes acquisition atomic w.r.t. SuspendPort,
	// so a lease that arrives after Run's gate check cannot race the open. The
	// port lock also fences an election gap — a follower mid-session under a
	// lease a newly-elected leader never saw holds this lock and makes us wait
	// (usbprov.ErrPortBusy) rather than byte-splitting.
	t.ensureCond()
	t.gmu.Lock()
	if t.suspended || ctx.Err() != nil {
		t.gmu.Unlock()
		return nil // Run's gate will block on the next iteration
	}
	releaseLock, err := acquirePortLock(canonical)
	if err != nil {
		t.gmu.Unlock()
		return err // ErrPortBusy is retryable; Run backs off
	}
	f, err := os.OpenFile(canonical, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = releaseLock()
		t.gmu.Unlock()
		return err
	}
	fd := int(f.Fd())
	if err := setRaw(fd); err != nil {
		_ = f.Close()
		_ = releaseLock()
		t.gmu.Unlock()
		return err
	}
	// Leave the fd in Go's poller-managed non-blocking mode (do NOT clear
	// O_NONBLOCK): os.File already gives blocking Read semantics via the runtime
	// poller, and — critically for suspend — a Close() from another goroutine
	// then unblocks an in-flight Read. Clearing O_NONBLOCK would drop the read
	// into a raw kernel syscall that Close cannot interrupt, wedging SuspendPort.
	t.fdClose = func() { _ = f.Close() }
	t.gmu.Unlock()

	// Ordered teardown: close the fd, release the port lock, THEN clear fdClose
	// and wake any waiting SuspendPort — so SuspendPort only returns once the
	// port is fully free for the lessee to open.
	defer func() {
		_ = f.Close()
		_ = releaseLock()
		t.gmu.Lock()
		t.fdClose = nil
		t.gcond.Broadcast()
		t.gmu.Unlock()
	}()

	t.connected.Store(true)
	defer t.connected.Store(false)
	if t.Logger != nil {
		t.Logger.Printf("serial: tailing %s", canonical)
	}

	// Close the fd when ctx is cancelled so the blocking read unblocks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = f.Close()
		case <-done:
		}
	}()

	br := bufio.NewReader(f)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			t.writeLine(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return err
			}
			return err
		}
	}
}

// setRaw puts the tty in non-canonical, no-echo mode. We don't touch baud
// because USB-CDC ignores it anyway. The ioctl-request constants differ
// between Linux (TCGETS/TCSETS) and the BSDs/macOS (TIOCGETA/TIOCSETA); they
// come from tailer_linux.go / tailer_darwin.go.
func setRaw(fd int) error {
	tio, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return err
	}
	// cfmakeraw equivalent.
	tio.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	tio.Oflag &^= unix.OPOST
	tio.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	tio.Cflag &^= unix.CSIZE | unix.PARENB
	tio.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	// VMIN=1, VTIME=0 — block until at least one byte arrives.
	tio.Cc[unix.VMIN] = 1
	tio.Cc[unix.VTIME] = 0
	return unix.IoctlSetTermios(fd, ioctlSetTermios, tio)
}
