//go:build !windows

// Package filelock is a tiny cross-platform exclusive-file-lock helper. It
// exists so the registry and devlog stores get the same single-writer
// semantics on every OS the broker binary ships for. On Unix it is a thin
// wrapper over flock(2) (advisory, whole-file); on Windows it maps to
// LockFileEx (see filelock_windows.go). Callers lock a sibling ".lock" file,
// never the data file, so the data file can be rename(2)'d atomically while
// the lock is held.
package filelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// Lock blocks until an exclusive lock on f is acquired.
func Lock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }

// Unlock releases the lock held on f.
func Unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
