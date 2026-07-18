//go:build linux

package serial

import "golang.org/x/sys/unix"

// Linux termios ioctl requests. On Linux the get/set termios ioctls are
// TCGETS/TCSETS.
const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
