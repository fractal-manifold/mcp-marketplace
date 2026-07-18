//go:build !windows

package panelgen

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr puts the child in its own process group so we can signal the
// child AND any grandchildren it spawns with a single killpg, and so a Ctrl-C
// delivered to the broker's own group doesn't hit it twice.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// signalGroupTerm sends SIGTERM to the child's whole process group (pgid ==
// pid because Setpgid made the child a group leader).
func signalGroupTerm(pid int) { _ = syscall.Kill(-pid, syscall.SIGTERM) }

// signalGroupKill SIGKILLs the child's whole process group. We do this even
// when the direct child already exited, to reap any grandchildren it spawned
// that ignored (or never received) the SIGTERM — killpg on an already-empty
// group is a harmless ESRCH.
func signalGroupKill(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
