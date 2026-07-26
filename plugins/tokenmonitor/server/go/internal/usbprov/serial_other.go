//go:build !linux

package usbprov

// openExclusive is unimplemented off Linux (macOS/Windows are deferred, matching
// the enumerate stubs). The lock/termios plumbing is Unix-ioctl-specific and
// will be ported alongside per-OS enumeration.
func openExclusive(string) (*Handle, error) { return nil, ErrOpenUnsupported }

// AcquirePortLock is unimplemented off Linux (see openExclusive).
func AcquirePortLock(string) (func() error, error) { return nil, ErrOpenUnsupported }
