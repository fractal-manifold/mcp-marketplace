//go:build !windows

package state

import "os"

func replaceFile(src, dst string) error { return os.Rename(src, dst) }
