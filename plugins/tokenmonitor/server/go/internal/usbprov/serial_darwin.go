//go:build darwin

package usbprov

import "golang.org/x/sys/unix"

// macOS (BSD) termios get/set ioctl request numbers. Linux names these
// TCGETS/TCSETS; on darwin they are TIOCGETA/TIOCSETA. The rest of the
// OS-exclusive serial implementation (open, flock, secure lock dir, DTR/RTS via
// TIOCEXCL/TIOCMBIC) is shared in serial_posix.go — x/sys/unix supplies the
// BSD-correct values for every constant it uses.
const (
	tcGet = unix.TIOCGETA
	tcSet = unix.TIOCSETA
)
