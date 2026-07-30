package panelgen

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
)

type fakeReg struct {
	ids []string
	err error
}

func (f fakeReg) ListDeviceIDs() ([]string, error) { return f.ids, f.err }

func testManager(cfg *config.Config, reg DeviceLister) *Manager {
	m := newManager(cfg, reg, log.New(io.Discard, "", 0))
	m.reconcileInterval = 50 * time.Millisecond
	m.termGrace = 300 * time.Millisecond
	m.backoffInitial = 20 * time.Millisecond
	m.backoffMax = 40 * time.Millisecond
	m.backoffReset = 500 * time.Millisecond
	return m
}

// runManager starts m.run under a fresh ctx and returns a stop func that
// cancels and blocks until run (and thus every child) has exited.
func runManager(m *Manager) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.run(ctx); close(done) }()
	return func() { cancel(); <-done }
}

func size(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return len(b)
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func cfgWithCommand(cmd config.PanelCommands) *config.Config {
	return &config.Config{Panel: config.Panel{Command: cmd}}
}

func TestStartNoopWhenUnconfigured(t *testing.T) {
	stop := Start(context.Background(), &config.Config{}, nil, log.New(io.Discard, "", 0))
	// Returns immediately and stop is safe to call.
	stop()
}

func TestSupervisorSpawnAndStop(t *testing.T) {
	f := filepath.Join(t.TempDir(), "count")
	argv := []string{"sh", "-c", fmt.Sprintf("while true; do printf x >> '%s'; sleep 0.02; done", f)}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": argv}), nil)

	stop := runManager(m)
	if !waitFor(t, 2*time.Second, func() bool { return size(t, f) > 0 }) {
		stop()
		t.Fatal("generator never wrote its file — was it launched?")
	}
	stop()

	// After stop() the process must be gone: the file stops growing.
	settled := size(t, f)
	time.Sleep(200 * time.Millisecond)
	if grew := size(t, f); grew != settled {
		t.Fatalf("file kept growing after stop (%d -> %d): child not killed", settled, grew)
	}
}

func TestSupervisorRestartsOnExit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "runs")
	// One byte per run, then exit 0. Supervisor must respawn on each exit.
	argv := []string{"sh", "-c", fmt.Sprintf("printf x >> '%s'", f)}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": argv}), nil)

	stop := runManager(m)
	defer stop()
	if !waitFor(t, 2*time.Second, func() bool { return size(t, f) >= 3 }) {
		t.Fatalf("expected >=3 restarts, got %d bytes", size(t, f))
	}
}

func TestTerminateKillsStubbornChild(t *testing.T) {
	f := filepath.Join(t.TempDir(), "alive")
	// Ignore SIGTERM, keep touching the file. Only SIGKILL (after termGrace)
	// stops it.
	argv := []string{"sh", "-c", fmt.Sprintf("trap '' TERM; while true; do printf x >> '%s'; sleep 0.02; done", f)}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": argv}), nil)

	stop := runManager(m)
	if !waitFor(t, 2*time.Second, func() bool { return size(t, f) > 0 }) {
		stop()
		t.Fatal("stubborn child never started")
	}
	start := time.Now()
	stop() // blocks until SIGKILL takes effect
	if elapsed := time.Since(start); elapsed < m.termGrace {
		t.Fatalf("stop returned in %s, before the SIGTERM grace elapsed — group not escalated to SIGKILL?", elapsed)
	}
	settled := size(t, f)
	time.Sleep(200 * time.Millisecond)
	if grew := size(t, f); grew != settled {
		t.Fatalf("stubborn child survived stop (%d -> %d)", settled, grew)
	}
}

func TestTerminateReapsGrandchild(t *testing.T) {
	dir := t.TempDir()
	gf := filepath.Join(dir, "grandchild")
	// The parent spawns a grandchild in the SAME process group that ignores
	// SIGTERM and keeps writing, then waits. On teardown the parent exits on
	// SIGTERM, but the grandchild must be reaped by the group-wide SIGKILL —
	// otherwise it would be orphaned.
	script := fmt.Sprintf(`( trap '' TERM; while true; do printf x >> '%s'; sleep 0.02; done ) & wait`, gf)
	m := testManager(cfgWithCommand(config.PanelCommands{"default": {"sh", "-c", script}}), nil)

	stop := runManager(m)
	if !waitFor(t, 2*time.Second, func() bool { return size(t, gf) > 0 }) {
		stop()
		t.Fatal("grandchild never started")
	}
	stop()
	settled := size(t, gf)
	time.Sleep(250 * time.Millisecond)
	if grew := size(t, gf); grew != settled {
		t.Fatalf("grandchild survived teardown (%d -> %d): process group not SIGKILLed", settled, grew)
	}
}

func TestTargetsPerDeviceResolution(t *testing.T) {
	def := []string{"gen", "default"}
	special := []string{"gen", "special"}
	m := testManager(cfgWithCommand(config.PanelCommands{
		"default": def,
		"dev1":    special,
	}), fakeReg{ids: []string{"dev1", "dev2"}})

	got := m.targets()
	if !sameArgv(got["dev1"].argv, special) {
		t.Errorf("dev1: want %v, got %v", special, got["dev1"])
	}
	if !sameArgv(got["dev2"].argv, def) {
		t.Errorf("dev2 (falls back to default): want %v, got %v", def, got["dev2"])
	}
	if _, ok := got[""]; ok {
		t.Errorf("no global default child should exist when devices are present: %v", got[""])
	}
}

func TestTargetsExplicitKeyForUnregisteredDevice(t *testing.T) {
	special := []string{"gen", "special"}
	// No registry, but an explicit device key: it must still run.
	m := testManager(cfgWithCommand(config.PanelCommands{"tmon-ab12": special}), nil)
	got := m.targets()
	if !sameArgv(got["tmon-ab12"].argv, special) {
		t.Errorf("explicit key: want %v, got %v", special, got["tmon-ab12"])
	}
	if _, ok := got[""]; ok {
		t.Errorf("unexpected global default child: %v", got[""])
	}
}

func TestTargetsGlobalDefaultWhenNoDevices(t *testing.T) {
	def := []string{"gen"}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": def}), nil)
	got := m.targets()
	if len(got) != 1 || !sameArgv(got[""].argv, def) {
		t.Errorf("want a single global default child, got %v", got)
	}
}

func cfgWithInterval(cmd config.PanelCommands, iv config.PanelCommandIntervals) *config.Config {
	return &config.Config{Panel: config.Panel{Command: cmd, CommandIntervalS: iv}}
}

func TestTargetsCarryInterval(t *testing.T) {
	def := []string{"gen"}
	m := testManager(cfgWithInterval(
		config.PanelCommands{"default": def},
		config.PanelCommandIntervals{"default": 900, "dev1": 60},
	), fakeReg{ids: []string{"dev1", "dev2"}})

	got := m.targets()
	if got["dev1"].interval != 60*time.Second {
		t.Errorf("dev1 own interval: want 60s, got %s", got["dev1"].interval)
	}
	if got["dev2"].interval != 900*time.Second {
		t.Errorf("dev2 falls back to default: want 900s, got %s", got["dev2"].interval)
	}
}

func TestTargetsIntervalAbsentMeansLongLived(t *testing.T) {
	m := testManager(cfgWithCommand(config.PanelCommands{"default": {"gen"}}), nil)
	if iv := m.targets()[""].interval; iv != 0 {
		t.Errorf("no [panel.command_interval_s] must mean 0 (long-lived), got %s", iv)
	}
}

// The point of the feature: a command that samples once and exits gets re-run
// on its own period instead of being treated as a crash.
func TestIntervalModeRerunsOneShot(t *testing.T) {
	f := filepath.Join(t.TempDir(), "runs")
	argv := []string{"sh", "-c", fmt.Sprintf("printf x >> '%s'", f)}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": argv}), nil)
	// The config unit is whole seconds, so drive the loop directly with a
	// sub-second period rather than making the test wait one out.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.superviseInterval(ctx, "", target{argv: argv, interval: 60 * time.Millisecond})
		close(done)
	}()
	defer func() { cancel(); <-done }()

	if !waitFor(t, 2*time.Second, func() bool { return size(t, f) >= 3 }) {
		t.Fatalf("want >=3 runs on a 60ms period, got %d", size(t, f))
	}
}

// A run that outlasts its period must not overlap with the next one.
func TestIntervalModeDoesNotOverlapRuns(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "runs")
	// Each run appends on entry, sleeps well past the period, appends on exit.
	// Overlapping runs would interleave the markers as "ss" or "ee".
	argv := []string{"sh", "-c", fmt.Sprintf("printf s >> '%s'; sleep 0.2; printf e >> '%s'", f, f)}
	m := testManager(cfgWithCommand(config.PanelCommands{"default": argv}), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.superviseInterval(ctx, "", target{argv: argv, interval: 20 * time.Millisecond})
		close(done)
	}()
	// Assert the wait: with zero runs the marker loop below iterates over
	// nothing and the test would pass without ever exercising an overlap.
	if !waitFor(t, 3*time.Second, func() bool { return size(t, f) >= 4 }) {
		t.Fatalf("want at least two complete runs, got %d markers", size(t, f))
	}
	cancel()
	<-done

	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read markers: %v", err)
	}
	// Drop a trailing "s" from the run the cancel interrupted.
	got := string(b)
	if len(got) > 0 && got[len(got)-1] == 's' {
		got = got[:len(got)-1]
	}
	for i := 0; i+1 < len(got); i += 2 {
		if got[i] != 's' || got[i+1] != 'e' {
			t.Fatalf("runs overlapped: markers %q", string(b))
		}
	}
}

// Re-pacing has to restart the child, or the new interval would only land
// whenever the old one happened to die. Drives reconcile directly (rather than
// run's ticker) so the children map is observable.
func TestReconcileRestartsChildOnIntervalChange(t *testing.T) {
	cfg := cfgWithInterval(
		config.PanelCommands{"default": {"sh", "-c", "sleep 5"}},
		config.PanelCommandIntervals{"default": 60},
	)
	m := testManager(cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	children := map[string]*child{}
	defer func() {
		cancel()
		for _, c := range children {
			<-c.done
		}
	}()

	m.reconcile(ctx, children)
	first, ok := children[""]
	if !ok {
		t.Fatal("child never started")
	}
	if first.target.interval != 60*time.Second {
		t.Fatalf("initial interval: got %s", first.target.interval)
	}

	cfg.Panel.CommandIntervalS["default"] = 30
	m.reconcile(ctx, children)
	got, ok := children[""]
	if !ok {
		t.Fatal("reconcile dropped the child instead of re-pacing it")
	}
	if got == first {
		t.Error("reconcile kept the old child after the interval changed")
	}
	if got.target.interval != 30*time.Second {
		t.Errorf("re-paced interval: want 30s, got %s", got.target.interval)
	}
}

func TestSameTargetComparesInterval(t *testing.T) {
	a := target{argv: []string{"gen"}, interval: 60 * time.Second}
	b := target{argv: []string{"gen"}, interval: 30 * time.Second}
	if sameTarget(a, b) {
		t.Error("a re-paced generator must count as changed, or the new interval never takes effect")
	}
	if !sameTarget(a, target{argv: []string{"gen"}, interval: 60 * time.Second}) {
		t.Error("identical targets must compare equal, or the child restarts every reconcile")
	}
}

func TestTargetPath(t *testing.T) {
	m := testManager(&config.Config{Panel: config.Panel{
		File: config.PanelPaths{"default": "/panels/default.json", "dev1": "/panels/dev1.json"},
		Dir:  "/panels/dir",
	}}, nil)

	if p := m.targetPath("dev1"); p != "/panels/dev1.json" {
		t.Errorf("explicit device file: got %q", p)
	}
	if p := m.targetPath("dev2"); p != "/panels/dir/dev2.json" {
		t.Errorf("dir convention: got %q", p)
	}
	if p := m.targetPath(""); p != "/panels/dir/default.json" {
		t.Errorf("empty id -> dir/default.json: got %q", p)
	}

	// No dir configured -> falls through to the default file.
	m2 := testManager(&config.Config{Panel: config.Panel{
		File: config.PanelPaths{"default": "/panels/default.json"},
	}}, nil)
	if p := m2.targetPath("dev9"); p != "/panels/default.json" {
		t.Errorf("no dir, unknown device -> default file: got %q", p)
	}
}
