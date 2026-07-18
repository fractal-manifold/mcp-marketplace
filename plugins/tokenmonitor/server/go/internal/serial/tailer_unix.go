//go:build !windows

package serial

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func (t *Tailer) tailOnce(ctx context.Context) error {
	// O_NOCTTY prevents the tty from becoming our controlling terminal.
	// O_NONBLOCK lets Open return immediately even if the port's modem
	// status isn't asserted; we clear it right after via fcntl so reads
	// block normally.
	f, err := os.OpenFile(t.Device, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	fd := int(f.Fd())
	if err := setRaw(fd); err != nil {
		return err
	}
	// Drop O_NONBLOCK so subsequent reads are blocking again — saves a
	// busy-loop on the bufio reader.
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}

	t.connected.Store(true)
	defer t.connected.Store(false)
	if t.Logger != nil {
		t.Logger.Printf("serial: tailing %s", t.Device)
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
