//go:build darwin

package serial

import "golang.org/x/sys/unix"

// macOS/BSD termios ioctl requests. Unlike Linux (TCGETS/TCSETS), the BSDs
// use TIOCGETA/TIOCSETA for the get/set-termios ioctls.
const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
