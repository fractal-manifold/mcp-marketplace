//go:build windows

package filelock

import (
	"os"

	"golang.org/x/sys/windows"
)

// Lock blocks until an exclusive lock on f is acquired. Windows byte-range
// locks are mandatory (not advisory like Unix flock), but since callers only
// ever open the ".lock" sibling to take this lock, the stricter semantics are
// harmless. We lock the maximal range [0, 2^64) so a zero-length lock file is
// still covered.
func Lock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, ^uint32(0), ^uint32(0), ol,
	)
}

// Unlock releases the lock held on f.
func Unlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0, ^uint32(0), ^uint32(0), ol,
	)
}
