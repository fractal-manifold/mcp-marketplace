//go:build windows

package panelgen

import (
	"os/exec"
	"strconv"
	"syscall"
)

// setSysProcAttr starts the child in a new process group so its own tree is
// isolated from the broker's console signals. Windows has no killpg, so the
// signal helpers below shell out to taskkill /T to reach grandchildren.
//
// LIMITATION: CREATE_NEW_PROCESS_GROUP does not *contain* the tree the way a
// Unix process group does — taskkill /T reaps descendants by walking the live
// parent, so it only works while the direct child is still alive (which it is
// whenever terminate() reaches the kill: it only kills when Wait hasn't
// returned). A fully robust reap would assign the child to a Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; that's deferred — panelgen is an
// optional custom-panel feature and taskkill is always present on Windows.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// signalGroupTerm asks the child tree to exit gracefully. There is no true
// SIGTERM on Windows; `taskkill /T` (without /F) posts WM_CLOSE / console
// events to the process and its descendants, which is the closest analogue.
func signalGroupTerm(pid int) {
	_ = exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T").Run()
}

// signalGroupKill force-terminates the child and its whole tree.
func signalGroupKill(pid int) {
	_ = exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
}
