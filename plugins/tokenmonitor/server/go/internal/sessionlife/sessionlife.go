// Package sessionlife owns the process-independent lifetime contract between
// MCP stdio sessions and the single TokenMonitor broker daemon.
package sessionlife

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	heartbeatInterval = 5 * time.Second
	staleAfter        = 30 * time.Second
	idleGrace         = 10 * time.Second
	maxDaemonLogBytes = 2 << 20
)

// RuntimeDir is deliberately identical in Go, Python and JavaScript. A daemon
// of one runtime must see leases created by sessions using either of the others.
func RuntimeDir() (string, error) {
	if p := strings.TrimSpace(os.Getenv("TMON_RUNTIME_DIR")); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); p != "" {
		return filepath.Join(p, "tokenmonitor"), nil
	}
	cache := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME"))
	if cache == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cache = filepath.Join(home, ".cache")
	}
	return filepath.Join(cache, "tokenmonitor", "runtime"), nil
}

func ensureRuntimeDir() (string, error) {
	dir, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "sessions"), 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	_ = os.Chmod(filepath.Join(dir, "sessions"), 0o700)
	return dir, nil
}

func randomToken() (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(cryptorand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Lease is one live Codex/Claude/Agy CLI or UI MCP connection. Its file is the
// cross-runtime protocol: existence plus a fresh mtime means the session lives.
type Lease struct {
	path string
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func NewLease() (*Lease, error) {
	dir, err := ensureRuntimeDir()
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "sessions", fmt.Sprintf("session-%d-%s", os.Getpid(), token))
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return nil, err
	}
	l := &Lease{path: path, stop: make(chan struct{}), done: make(chan struct{})}
	go l.heartbeat()
	return l, nil
}

func (l *Lease) heartbeat() {
	defer close(l.done)
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			if err := os.Chtimes(l.path, now, now); err != nil {
				// A suspend/resume can make the daemon observe the old mtime
				// before this process gets CPU and reap the file. Recreate it
				// inside the grace window so a still-live session is not lost.
				_ = os.WriteFile(l.path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
			}
		}
	}
}

func (l *Lease) Close() error {
	var err error
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		err = os.Remove(l.path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	})
	return err
}

// DaemonLock is a mkdir-based global singleton shared by all runtimes.
type DaemonLock struct {
	dir string
	pid string
}

func lockPath() (string, error) {
	dir, err := ensureRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "broker.lock"), nil
}

func readLockPID(path string) int {
	b, err := os.ReadFile(filepath.Join(path, "pid"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func DaemonRunning() bool {
	path, err := lockPath()
	if err != nil {
		return false
	}
	pid := readLockPID(path)
	return pid > 0 && processAlive(pid)
}

// AcquireDaemonLock returns (nil, false, nil) when another healthy daemon owns
// the singleton. A dead owner's directory is recovered before retrying.
func AcquireDaemonLock() (*DaemonLock, bool, error) {
	path, err := lockPath()
	if err != nil {
		return nil, false, err
	}
	for tries := 0; tries < 3; tries++ {
		err = os.Mkdir(path, 0o700)
		if err == nil {
			pid := strconv.Itoa(os.Getpid())
			if err := os.WriteFile(filepath.Join(path, "pid"), []byte(pid+"\n"), 0o600); err != nil {
				_ = os.RemoveAll(path)
				return nil, false, err
			}
			return &DaemonLock{dir: path, pid: pid}, true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, false, err
		}
		pid := readLockPID(path)
		if pid > 0 && processAlive(pid) {
			return nil, false, nil
		}
		// A creator may be between mkdir and writing pid. Give it one short
		// chance before treating the directory as abandoned.
		if pid == 0 && tries == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return nil, false, err
		}
	}
	return nil, false, errors.New("could not acquire broker singleton lock")
}

func (l *DaemonLock) Close() error {
	if l == nil {
		return nil
	}
	b, _ := os.ReadFile(filepath.Join(l.dir, "pid"))
	if strings.TrimSpace(string(b)) != l.pid {
		return nil
	}
	if dir, err := RuntimeDir(); err == nil {
		_ = os.Remove(filepath.Join(dir, "broker-state.json"))
	}
	return os.RemoveAll(l.dir)
}

// StartDaemon starts this exact runtime detached. Concurrent sessions may race
// here; the cross-runtime lock makes every losing child exit harmlessly.
func StartDaemon(configPath string) error {
	if DaemonRunning() {
		return nil
	}
	dir, err := ensureRuntimeDir()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"--daemon"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	logPath := filepath.Join(dir, "broker.log")
	if info, statErr := os.Stat(logPath); statErr == nil && info.Size() > maxDaemonLogBytes {
		_ = os.Rename(logPath, logPath+".1")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	setDetached(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// DaemonLogTail exposes the detached broker's bounded on-disk log to every MCP
// adapter. It replaces the old accidental per-process in-memory view.
func DaemonLogTail(limit int) ([]string, int, error) {
	dir, err := RuntimeDir()
	if err != nil {
		return nil, 0, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "broker.log"))
	if err != nil {
		return nil, 0, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	total := len(lines)
	if limit < total {
		lines = lines[total-limit:]
	}
	return lines, total, nil
}

// Supervise keeps the daemon invariant true while at least this session is
// alive. It recovers a crashed daemon without requiring the user to open a new
// CLI/UI session; the singleton lock makes concurrent supervisors harmless.
func Supervise(ctx context.Context, configPath string, logf func(string, ...any)) {
	ensure := func() {
		if err := StartDaemon(configPath); err != nil && logf != nil {
			logf("sessions: start broker daemon: %v", err)
		}
	}
	ensure()
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ensure()
		}
	}
}

func liveSessionCount(now time.Time) (int, error) {
	dir, err := ensureRuntimeDir()
	if err != nil {
		return 0, err
	}
	sessions := filepath.Join(dir, "sessions")
	ents, err := os.ReadDir(sessions)
	if err != nil {
		return 0, err
	}
	live := 0
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasPrefix(ent.Name(), "session-") {
			continue
		}
		path := filepath.Join(sessions, ent.Name())
		info, err := ent.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > staleAfter {
			_ = os.Remove(path)
			continue
		}
		live++
	}
	return live, nil
}

// Monitor cancels the daemon after the last session has been absent for the
// grace period. Stale leases from killed clients are reaped automatically.
func Monitor(ctx context.Context, cancel context.CancelFunc, logf func(string, ...any)) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var emptySince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			count, err := liveSessionCount(now)
			if err != nil {
				if logf != nil {
					logf("sessions: %v", err)
				}
				continue
			}
			if count > 0 {
				emptySince = time.Time{}
				continue
			}
			if emptySince.IsZero() {
				emptySince = now
				continue
			}
			if now.Sub(emptySince) >= idleGrace {
				if logf != nil {
					logf("sessions: none remain; stopping broker daemon")
				}
				cancel()
				return
			}
		}
	}
}
