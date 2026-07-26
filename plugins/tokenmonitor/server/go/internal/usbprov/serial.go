package usbprov

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

// CanonicalPort resolves a serial-port path to the stable identity used as both
// the lease key and the OS-exclusive lock key, so an alias (/dev/serial/by-id/…)
// and the real node (/dev/ttyACM0) map to ONE lease and ONE lock — without this
// two followers could arbitrate "the same" device through different names and
// byte-split it (compat/PROVISION_WIRE.md §6). On POSIX it resolves symlinks and
// preserves case (device paths are case-sensitive); the device must exist. The
// Windows COM normalisation is deferred with the rest of the Windows port.
func CanonicalPort(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("usbprov: absolute path %q: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("usbprov: resolve %q: %w", path, err)
	}
	return resolved, nil
}

var (
	// ErrPortBusy is returned when another cooperating process already holds
	// the OS-exclusive lock on the port (a leader tailer, or a second
	// provisioning session). It is distinct from a raw open failure so callers
	// can surface "the port is in use" instead of "the port is broken".
	ErrPortBusy = errors.New("usbprov: serial port is held by another process")
	// ErrOpenUnsupported is returned by OpenExclusive on platforms without an
	// exclusive-serial implementation (macOS/Windows are deferred, matching the
	// enumerate stubs).
	ErrOpenUnsupported = errors.New("usbprov: exclusive serial open is not supported on this platform")
)

// Handle is an OS-exclusive hold on a serial port. Conn is the raw byte
// transport handed to RunProvision, which CONSUMES and closes it. The
// filesystem lock that guarantees exclusivity lives on a SEPARATE fd owned by
// this Handle; the caller must Release() it AFTER the session, which also
// best-effort closes Conn (idempotent) so an early-return path cannot leak the
// serial fd.
//
// Typical use:
//
//	h, err := OpenExclusive(path)
//	if err != nil { ... }
//	defer h.Release()
//	res, err := RunProvision(ctx, h.Conn, opts) // closes h.Conn
type Handle struct {
	Conn    io.ReadWriteCloser
	release func() error
}

// Release drops the exclusive lock (and best-effort closes Conn). Idempotent.
func (h *Handle) Release() error {
	if h == nil || h.release == nil {
		return nil
	}
	return h.release()
}

// OpenExclusive acquires an OS-exclusive hold on the serial port at path and
// opens it in raw mode with DTR/RTS cleared (to minimise the esptool-style
// auto-reset that opening the USB-Serial/JTAG port can trigger). The lock is
// taken on a separate lock-file BEFORE the device is opened, closing the race
// where two cooperating runtimes both open the port in the leader-election gap.
func OpenExclusive(path string) (*Handle, error) {
	return openExclusive(path)
}
