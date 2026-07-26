// Package serial owns the USB-CDC port that streams ESP-IDF logs from the
// TokenMonitor device. The tailer is started by the leader tokenmonitor-mcp process
// only — there's a single /dev/ttyACMx and exactly one process can read it
// at a time. Followers (and any tool that wants the logs) go through the
// broker's HTTP /firmware-logs endpoint instead.
//
// We deliberately avoid pulling in a serial-port library: USB-CDC ignores
// baud/parity/stop-bits, so all we need is to open the tty in raw,
// non-canonical mode and read bytes. Doing that with a couple of unix
// syscalls is cheaper than a dependency.
//
// The tty/termios plumbing is Unix-only and lives in tailer_unix.go (+ the
// per-OS ioctl-request constants in tailer_{linux,darwin}.go). On Windows
// (tailer_windows.go) tailOnce is a stub returning errUnsupported and Run
// exits cleanly — reading firmware logs over the serial port is not supported
// there, but nothing else in the broker depends on it.
package serial

import (
	"context"
	"errors"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/usbprov"
)

// errUnsupported is returned by tailOnce on platforms without a tty/termios
// implementation (Windows). Run treats it as terminal: log once, don't retry.
var errUnsupported = errors.New("serial: tailing not supported on this platform")

// Strip ANSI CSI sequences (color, cursor moves) that ESP-IDF emits when
// logs are colored. The MCP consumer doesn't render escapes.
var ansiCSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Tailer is a long-lived reader of one serial port. Run blocks until ctx
// is cancelled, reconnecting on errors so an unplugged device doesn't
// kill the goroutine.
type Tailer struct {
	Device string
	Writer io.Writer
	Logger *log.Logger

	connected atomic.Bool

	// Suspend/resume gate for the leader-mediated USB-provisioning lease
	// (compat/PROVISION_WIRE.md §6). When a follower leases this tailer's port,
	// the lease manager calls SuspendPort → the tailer closes its fd, releases
	// the port lock, and blocks in Run until ResumePort. The acquire-and-open in
	// tailOnce and the suspend flag are guarded by the SAME mutex so a suspend
	// cannot slip in between the gate check and the open.
	condOnce  sync.Once
	gmu       sync.Mutex
	gcond     *sync.Cond
	suspended bool
	// suspendedFor is the canonical path the current suspension was granted for.
	// ResumePort matches against THIS stored string rather than re-resolving
	// CanonicalPort(t.Device): a successful usb_provision reboots the device, so
	// the node drops off the USB bus for ~1-2s right when the follower releases
	// its lease — re-resolving would fail and leave the tailer wedged `suspended`
	// forever on the headline success path. The granted string is authoritative.
	suspendedFor string
	// fdClose closes the currently-open device fd (to interrupt a blocked read);
	// non-nil exactly while the tailer holds the fd AND the port lock.
	fdClose func()
}

// Connected reports whether the tailer currently has the device open. The
// MCP /firmware-logs handler surfaces this so callers can distinguish
// "device unplugged" from "no logs yet".
func (t *Tailer) Connected() bool { return t.connected.Load() }

func (t *Tailer) ensureCond() {
	t.condOnce.Do(func() { t.gcond = sync.NewCond(&t.gmu) })
}

// SuspendPort makes the tailer release canonical so a lessee can open it, and
// blocks until the fd and port lock are actually freed. A no-op (nil) for a
// port this tailer does not own. Implements usbprov.SerialController.
func (t *Tailer) SuspendPort(canonical string) error {
	if t.Device == "" {
		return nil
	}
	mine, err := usbprov.CanonicalPort(t.Device)
	if err != nil || mine != canonical {
		return nil // not our port (or the device is gone → nothing to free)
	}
	t.ensureCond()
	t.gmu.Lock()
	defer t.gmu.Unlock()
	t.suspended = true
	t.suspendedFor = canonical
	if t.fdClose != nil {
		t.fdClose() // interrupt the current read → tailOnce cleanup runs
	}
	for t.fdClose != nil { // wait until the fd + port lock are released
		t.gcond.Wait()
	}
	return nil
}

// ResumePort lets the tailer reacquire canonical after a lease ends. It matches
// canonical against the path the tailer was actually suspended for (set under
// gmu by SuspendPort) rather than re-resolving CanonicalPort(t.Device) — the
// device node can be ABSENT here (the post-provision reboot drops it off the bus
// for a second or two), and re-resolving would fail and leave the flag stuck.
// A no-op if this canonical is not the one we're suspended for.
// Implements usbprov.SerialController.
func (t *Tailer) ResumePort(canonical string) {
	if t.Device == "" {
		return
	}
	t.ensureCond()
	t.gmu.Lock()
	if t.suspended && t.suspendedFor == canonical {
		t.suspended = false
		t.suspendedFor = ""
		t.gcond.Broadcast()
	}
	t.gmu.Unlock()
}

// Run owns the reconnect loop. Each open attempt either succeeds (we read
// lines until EOF or ctx) or fails (we wait with capped backoff). Logs go
// to t.Logger; nothing returns to the caller.
func (t *Tailer) Run(ctx context.Context) {
	if t.Device == "" {
		return
	}
	t.ensureCond()
	// Wake the suspend gate when ctx is cancelled so a suspended tailer can exit
	// instead of blocking forever in the sync.Cond wait. runDone lets this helper
	// exit when Run returns for any other reason (e.g. errUnsupported on Windows),
	// so it never outlives Run waiting on a ctx that may never cancel.
	runDone := make(chan struct{})
	defer close(runDone)
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		t.gmu.Lock()
		t.gcond.Broadcast()
		t.gmu.Unlock()
	}()
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// Gate: block here while the port is leased to a follower.
		t.gmu.Lock()
		for t.suspended && ctx.Err() == nil {
			t.gcond.Wait()
		}
		t.gmu.Unlock()
		if ctx.Err() != nil {
			return
		}
		err := t.tailOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			// A clean return (EOF, or the suspend gate released) — don't carry a
			// doubled backoff into the next attempt, or a few lease cycles would
			// leave the tailer sleeping up to 30s before it resumes logging.
			backoff = time.Second
		}
		if errors.Is(err, errUnsupported) {
			if t.Logger != nil {
				t.Logger.Printf("serial: %s: %v", t.Device, err)
			}
			return
		}
		if err != nil && t.Logger != nil {
			t.Logger.Printf("serial: %s: %v (retry in %s)", t.Device, err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (t *Tailer) writeLine(raw string) {
	// Strip CRLF and ANSI escapes; add a single trailing '\n' so logbuf
	// stores one entry per line.
	clean := ansiCSI.ReplaceAllString(raw, "")
	clean = strings.TrimRight(clean, "\r\n")
	if clean == "" {
		return
	}
	_, _ = io.WriteString(t.Writer, clean+"\n")
}
