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
	"sync/atomic"
	"time"
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
}

// Connected reports whether the tailer currently has the device open. The
// MCP /firmware-logs handler surfaces this so callers can distinguish
// "device unplugged" from "no logs yet".
func (t *Tailer) Connected() bool { return t.connected.Load() }

// Run owns the reconnect loop. Each open attempt either succeeds (we read
// lines until EOF or ctx) or fails (we wait with capped backoff). Logs go
// to t.Logger; nothing returns to the caller.
func (t *Tailer) Run(ctx context.Context) {
	if t.Device == "" {
		return
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := t.tailOnce(ctx)
		if ctx.Err() != nil {
			return
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
