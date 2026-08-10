//go:build !linux && !darwin

package usbprov

// openExclusive is unimplemented off POSIX (Linux + macOS are handled by
// serial_posix.go; Windows is still deferred, matching the enumerate stub). The
// lock/termios plumbing is Unix-ioctl-specific.
func openExclusive(string) (*Handle, error) { return nil, ErrOpenUnsupported }

// AcquirePortLock is unimplemented off POSIX (see openExclusive).
func AcquirePortLock(string) (func() error, error) { return nil, ErrOpenUnsupported }
