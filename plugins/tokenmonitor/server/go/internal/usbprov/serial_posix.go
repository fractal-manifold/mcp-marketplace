//go:build linux || darwin

package usbprov

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// This file is the shared POSIX (Linux + macOS) implementation of the
// OS-exclusive serial open and its cross-runtime flock. The two platforms
// differ only in the termios get/set ioctl request numbers, which each supplies
// as tcGet/tcSet (serial_linux.go: TCGETS/TCSETS; serial_darwin.go:
// TIOCGETA/TIOCSETA). Everything below — the flock lock-file identity, the
// TIOCEXCL fence, DTR/RTS clearing, the secure lock dir — is byte-identical
// across both, which keeps the lock-file contract in compat/PROVISION_WIRE.md §6
// the same on every OS.

func openExclusive(path string) (*Handle, error) {
	// Resolve to the canonical identity shared with the lease key, so an alias
	// and the real node take the same lock.
	canonical, err := CanonicalPort(path)
	if err != nil {
		return nil, err
	}

	// Lock BEFORE opening the device: a flock on the sibling lock-file is what
	// serialises two cooperating runtimes, since applying TIOCEXCL only after
	// open() leaves a window where both have the port open.
	lock, err := acquirePortLock(canonical)
	if err != nil {
		return nil, err
	}

	f, err := openRawSerial(canonical)
	if err != nil {
		_ = lock.release()
		return nil, err
	}

	sf := &serialFile{f: f}
	var relOnce sync.Once
	var relErr error
	h := &Handle{
		Conn: sf,
		release: func() error {
			// Fully idempotent: sf.Close() is safe after RunProvision already
			// closed Conn, and lock.release() must run exactly once (a second
			// flock/close on the same fd would error or race).
			relOnce.Do(func() {
				cerr := sf.Close()
				lerr := lock.release()
				relErr = errors.Join(cerr, lerr)
			})
			return relErr
		},
	}
	return h, nil
}

// portLock is a held cross-runtime flock on a canonical serial port. The tailer
// takes one too, so a follower's lease (which suspends the tailer, releasing
// this lock) is what lets the follower's own OpenExclusive succeed.
type portLock struct {
	f    *os.File
	once sync.Once
	err  error
}

// acquirePortLock takes the non-blocking exclusive flock for canonical. Returns
// ErrPortBusy (retryable) if another cooperating runtime holds it.
func acquirePortLock(canonical string) (*portLock, error) {
	lf, err := acquireLockIn(lockDir(), canonical)
	if err != nil {
		return nil, err
	}
	return &portLock{f: lf}, nil
}

func (l *portLock) release() error {
	l.once.Do(func() { l.err = releaseLock(l.f) })
	return l.err
}

// AcquirePortLock takes the cross-runtime exclusive lock for canonical (already
// canonicalised via CanonicalPort) — for owners that manage their own open()
// and termios, i.e. the firmware-log tailer, rather than going through
// OpenExclusive. It is the SAME lock OpenExclusive uses, so a follower's lease
// (which suspends the tailer → releases this lock) is what lets the follower's
// own OpenExclusive succeed. Returns ErrPortBusy (retryable) if held. Release
// with the returned func on every exit path.
func AcquirePortLock(canonical string) (func() error, error) {
	l, err := acquirePortLock(canonical)
	if err != nil {
		return nil, err
	}
	return l.release, nil
}

// lockDir is the fixed directory holding serial lock-files. It keys on a
// filesystem fact (does /run/user/<euid> exist?), NOT on $XDG_RUNTIME_DIR, so a
// daemon without that env var and an interactive follower that has it still
// agree on the same lock path and cannot both grab the port. On macOS
// /run/user never exists, so it always resolves to /tmp/tokenmonitor-<euid>.
func lockDir() string {
	euid := os.Geteuid()
	if run := fmt.Sprintf("/run/user/%d", euid); dirExists(run) {
		return filepath.Join(run, "tokenmonitor")
	}
	return fmt.Sprintf("/tmp/tokenmonitor-%d", euid)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// acquireLockIn takes a non-blocking exclusive flock on a lock-file whose name
// is derived from the absolute device path (so /dev/ttyACM0 and a by-id symlink
// to it must resolve to the same abs path upstream to share a lock). A held
// lock yields ErrPortBusy rather than blocking, so a contended port fails fast
// with a clear message.
func acquireLockIn(dir, absPath string) (*os.File, error) {
	if err := secureLockDir(dir); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(absPath))
	lp := filepath.Join(dir, "serial-"+hex.EncodeToString(sum[:])+".lock")
	// O_NOFOLLOW: refuse to open a symlink planted at the lock-file path. Inside
	// a secureLockDir (0700, owned by us) no other user can plant one, but this
	// is cheap defence in depth.
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("usbprov: open lock file: %w", err)
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lf.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrPortBusy, absPath)
		}
		return nil, fmt.Errorf("usbprov: flock: %w", err)
	}
	return lf, nil
}

// secureLockDir creates dir (single level; its parent — /run/user/<euid> or
// /tmp — already exists) as 0700, or, if it already exists, verifies it is a
// real directory owned by the effective user with no group/other access and not
// a symlink. This closes the attack where another local user pre-creates the
// predictable /tmp/tokenmonitor-<euid> path (as an owned dir or a symlink) to
// subvert the lock — e.g. unlinking a held lock-file so a second flock succeeds.
func secureLockDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("usbprov: create lock dir %q: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("usbprov: stat lock dir %q: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("usbprov: lock dir %q is a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("usbprov: lock path %q is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("usbprov: lock dir %q has unsafe permissions %#o", dir, perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("usbprov: lock dir %q is not owned by the current user", dir)
	}
	return nil
}

func releaseLock(lf *os.File) error {
	if lf == nil {
		return nil
	}
	_ = unix.Flock(int(lf.Fd()), unix.LOCK_UN)
	return lf.Close()
}

// openRawSerial opens the tty raw (USB-CDC ignores baud), marks it
// exclusive-open, and clears DTR/RTS. It mirrors the tailer's setRaw plus the
// provisioning-specific TIOCEXCL and modem-line clearing.
func openRawSerial(path string) (*os.File, error) {
	// O_NOCTTY: don't adopt the tty as a controlling terminal. O_NONBLOCK: open
	// returns without waiting on modem status (a CDC gadget never asserts DCD);
	// cleared below so reads block.
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())

	// TIOCEXCL: further open()s by cooperating processes get EBUSY. Not enforced
	// against a privileged opener, which is why the flock above is the real
	// arbitration; this is defence in depth for foreign tools.
	if err := unix.IoctlSetInt(fd, unix.TIOCEXCL, 0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("usbprov: TIOCEXCL: %w", err)
	}
	if err := setRawSerial(fd); err != nil {
		_ = f.Close()
		return nil, err
	}
	// Best-effort: clear DTR and RTS so opening the port does not toggle the
	// esptool download-mode reset signal. open() often asserts DTR before we get
	// here, so this only narrows (not eliminates) the window — firmware
	// tolerates an unexpected reset as the real mitigation.
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCMBIC, unix.TIOCM_DTR|unix.TIOCM_RTS)

	// Leave the fd in Go's poller-managed non-blocking mode (do NOT clear
	// O_NONBLOCK). os.File already presents blocking Read semantics via the
	// runtime poller, and — critically for RunProvision's cancellation — a
	// Close() from the ctx-watcher then unblocks an in-flight Read. Clearing
	// O_NONBLOCK would drop the read into a raw kernel syscall that Close cannot
	// interrupt, leaking the reader goroutine on every silent-device cancel.
	return f, nil
}

// setRawSerial puts the tty in non-canonical, no-echo, 8N1 mode (cfmakeraw
// equivalent). Baud is left untouched because USB-CDC ignores it. The termios
// get/set request numbers are the only per-OS difference (tcGet/tcSet).
func setRawSerial(fd int) error {
	tio, err := unix.IoctlGetTermios(fd, tcGet)
	if err != nil {
		return fmt.Errorf("usbprov: get termios: %w", err)
	}
	tio.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	tio.Oflag &^= unix.OPOST
	tio.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	tio.Cflag &^= unix.CSIZE | unix.PARENB
	tio.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	tio.Cc[unix.VMIN] = 1
	tio.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, tcSet, tio); err != nil {
		return fmt.Errorf("usbprov: set termios: %w", err)
	}
	return nil
}

// serialFile is an idempotent-close io.ReadWriteCloser over the serial fd.
// Closing the fd is also what unblocks a blocked Read/Write, which RunProvision
// relies on for cancellation.
type serialFile struct {
	f    *os.File
	once sync.Once
	err  error
}

func (s *serialFile) Read(p []byte) (int, error)  { return s.f.Read(p) }
func (s *serialFile) Write(p []byte) (int, error) { return s.f.Write(p) }
func (s *serialFile) Close() error {
	s.once.Do(func() { s.err = s.f.Close() })
	return s.err
}
