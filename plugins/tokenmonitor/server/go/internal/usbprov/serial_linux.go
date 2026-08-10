//go:build linux

package usbprov

import "golang.org/x/sys/unix"

// Linux termios get/set ioctl request numbers. The rest of the OS-exclusive
// serial implementation (open, flock, secure lock dir, DTR/RTS) is shared with
// macOS in serial_posix.go.
const (
	tcGet = unix.TCGETS
	tcSet = unix.TCSETS
)
