// Package devlog stores the diagnostic log lines a device uploads via
// POST /device/<id>/logs. Each device gets one plain-text file under
// <config>/device-logs/<id>.log, capped to the most recent MaxLines.
//
// The broker (whichever cwm-mcp process won leadership and serves the
// HTTP port) is the sole writer; every cwm-mcp process — leader or
// follower — reads the file directly for the wall_monitor_device_logs
// MCP tool. Writes serialise on a sibling .lock flock (the same idiom the
// registry uses) and rewrite-then-rename, so a concurrent reader always
// sees a whole file, never a half-written one.
package devlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	// MaxLines is the per-device retention cap. Matches the upper bound of
	// the wall_monitor_device_logs tool's `limit`.
	MaxLines = 2000
	// MaxLineBytes truncates any single stamped line. The firmware's own
	// lines are ≤200 chars, so this only bites a misbehaving/compromised
	// device trying to bloat the file with giant lines; it bounds total
	// retention at ~MaxLines*MaxLineBytes regardless of input.
	MaxLineBytes = 1024
	// MaxBodyBytes caps a single upload. The firmware sends ≤3 KB per
	// 60 s cycle; this leaves generous headroom while bounding abuse.
	MaxBodyBytes = 128 * 1024

	truncMarker = " [truncated]"
)

// DirFor derives the device-logs directory from the registry's devices
// directory (a sibling). Centralised so the HTTP handler and the MCP tool
// agree on the path without threading a new dependency around.
func DirFor(devicesDir string) string {
	return filepath.Join(filepath.Dir(devicesDir), "device-logs")
}

func logPath(dir, deviceID string) string {
	return filepath.Join(dir, deviceID+".log")
}

// StampLines splits an uploaded body into individual lines, drops blank
// ones, and prefixes each with the broker's receive time (RFC3339 UTC) so
// the operator can correlate the device's monotonic ms timestamps with
// wall-clock. The whole batch shares one stamp — they arrived together.
func StampLines(body string, recv time.Time) []string {
	stamp := recv.UTC().Format("[2006-01-02T15:04:05Z] ")
	var out []string
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		line := stamp + ln
		if len(line) > MaxLineBytes {
			line = truncateUTF8(line, MaxLineBytes-len(truncMarker)) + truncMarker
		}
		out = append(out, line)
	}
	return out
}

// truncateUTF8 returns s capped to at most max bytes, backing up to a rune
// boundary so a multi-byte sequence is never split (which would store
// invalid UTF-8). max is assumed < len(s).
func truncateUTF8(s string, max int) string {
	if max <= 0 {
		return ""
	}
	b := max
	for b > 0 && !utf8.RuneStart(s[b]) {
		b--
	}
	return s[:b]
}

// Read returns every retained line for the device (empty slice when the
// file doesn't exist yet). No lock: rename-atomic writes make a bare read
// safe.
func Read(dir, deviceID string) ([]string, error) {
	raw, err := os.ReadFile(logPath(dir, deviceID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var lines []string
	for _, ln := range strings.Split(string(raw), "\n") {
		if ln == "" {
			continue
		}
		lines = append(lines, ln)
	}
	return lines, nil
}

// Append adds `lines` to the device's log file, keeping only the most
// recent MaxLines. Single-writer-safe via flock; a no-op for an empty
// batch.
func Append(dir, deviceID string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("devlog: mkdir %s: %w", dir, err)
	}

	lockPath := logPath(dir, deviceID) + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("devlog: open lock: %w", err)
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("devlog: flock: %w", err)
	}
	defer unix.Flock(int(lf.Fd()), unix.LOCK_UN)

	existing, _ := Read(dir, deviceID)
	all := append(existing, lines...)
	if len(all) > MaxLines {
		all = all[len(all)-MaxLines:]
	}
	return writeAtomic(logPath(dir, deviceID), all)
}

func writeAtomic(path string, lines []string) error {
	tmp := path + ".tmp"
	data := []byte(strings.Join(lines, "\n"))
	if len(lines) > 0 {
		data = append(data, '\n')
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("devlog: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("devlog: rename: %w", err)
	}
	return nil
}
