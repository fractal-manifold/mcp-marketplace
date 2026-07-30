// Package panelgen supervises the user's optional custom-panel generator
// processes. It is a LEADER-SCOPED task, in the same family as the serial
// tailer, the mDNS publisher and the pull-OTA poller: main() starts it inside
// the leader's lifecycle (and in --daemon mode, which is the leader by
// construction) and calls the returned stop func when this process loses the
// bound port or shuts down. A follower never enters that lifecycle, so it
// never launches a generator — which means each device's panel file has
// exactly one writer, even when several tokenmonitor-mcp processes run at once.
//
// The commands come ONLY from the local, already-trusted tokenmonitor.toml
// ([panel.command], keyed by device id with a "default" fallback). They run
// as the broker's user with a shell-free argv. The control plane / config_sync
// can never populate them — that path writes device NVS, not the broker toml.
//
// Each generator is supervised in one of two modes, chosen per device by
// [panel.command_interval_s]:
//
//   - interval unset (0) — the long-lived contract every config had before:
//     the command is expected to keep running and write the panel file on its
//     own schedule. If it exits (cleanly or by crashing) while we are still
//     the leader, it is respawned with exponential backoff.
//   - interval > 0 — the command is a one-shot sampler: it is re-run every N
//     seconds, and a clean exit is the expected outcome rather than a crash.
//     Runs never overlap; a run that outlasts its period delays the next one.
//
// Either way, when the scoping ctx is cancelled the whole process group is
// sent SIGTERM, then SIGKILL after a grace period, so nothing is orphaned.
package panelgen

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
)

// DeviceLister is the slice of *registry.Registry that panelgen needs. Kept
// as an interface so tests can inject a fake without a real registry dir.
// Pass a nil DeviceLister (not a typed-nil *registry.Registry) when the
// registry is unavailable — see the main() wrapper.
type DeviceLister interface {
	ListDeviceIDs() ([]string, error)
}

// Manager owns the reconcile loop and the per-device supervisors.
type Manager struct {
	cfg    *config.Config
	reg    DeviceLister
	logger *log.Logger

	// Tunables — vars (not consts) so tests can shrink them.
	reconcileInterval time.Duration
	termGrace         time.Duration
	backoffInitial    time.Duration
	backoffMax        time.Duration
	backoffReset      time.Duration
}

func newManager(cfg *config.Config, reg DeviceLister, logger *log.Logger) *Manager {
	return &Manager{
		cfg:               cfg,
		reg:               reg,
		logger:            logger,
		reconcileInterval: 20 * time.Second,
		termGrace:         5 * time.Second,
		backoffInitial:    1 * time.Second,
		backoffMax:        30 * time.Second,
		backoffReset:      60 * time.Second,
	}
}

// Start launches the manager scoped to ctx and returns a stop func that blocks
// until every child has fully exited. It is a no-op (returns a no-op stop)
// when no [panel.command] is configured, so callers can wire it in
// unconditionally, exactly like startFirmwareTailer.
//
// reg may be nil (registry unavailable): only a "default" command can run in
// that case, feeding the global [panel.file] document. Callers MUST pass a
// genuinely nil interface, not a typed-nil *registry.Registry.
func Start(ctx context.Context, cfg *config.Config, reg DeviceLister, logger *log.Logger) func() {
	if len(cfg.PanelCommandMap()) == 0 {
		return func() {}
	}
	m := newManager(cfg, reg, logger)
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.run(ctx)
	}()
	return func() {
		cancel()
		wg.Wait()
	}
}

// target is one device's desired generator: what to run, and how to pace it.
// interval == 0 means "long-lived process" (the default contract); anything
// else means "one-shot, re-run on that period".
type target struct {
	argv     []string
	interval time.Duration
}

// child is one supervised generator process.
type child struct {
	target target
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *Manager) run(ctx context.Context) {
	children := map[string]*child{}
	defer func() {
		// ctx is cancelled by the time we get here (or about to be); every
		// child ctx is derived from it, so they are all winding down. Wait
		// for each to confirm its process is gone before returning, so the
		// caller's stop() is a true barrier.
		for _, c := range children {
			<-c.done
		}
	}()

	m.reconcile(ctx, children)
	t := time.NewTicker(m.reconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.reconcile(ctx, children)
		}
	}
}

// reconcile diffs the desired target set against the running children,
// stopping removed/changed ones and starting new ones. Called on a timer so a
// device provisioned (or removed) after startup gets its generator without a
// broker restart.
func (m *Manager) reconcile(ctx context.Context, children map[string]*child) {
	if ctx.Err() != nil {
		return
	}
	targets := m.targets()

	for id, c := range children {
		t, ok := targets[id]
		if !ok || !sameTarget(t, c.target) {
			c.cancel()
			<-c.done
			delete(children, id)
		}
	}

	for id, t := range targets {
		if _, ok := children[id]; ok {
			continue
		}
		cctx, ccancel := context.WithCancel(ctx)
		done := make(chan struct{})
		c := &child{target: t, cancel: ccancel, done: done}
		children[id] = c
		go func(id string, t target) {
			defer close(done)
			m.supervise(cctx, id, t)
		}(id, t)
	}
}

// targets computes the desired {deviceID: argv} set. Resolution per device id:
// its own [panel.command] entry, else "default". Every registered device is a
// candidate; explicit non-default keys are honoured even for devices not (yet)
// in the registry. With no registered devices at all, a lone "default" runs a
// single global generator (empty device id → feeds [panel.file].default).
func (m *Manager) targets() map[string]target {
	cmds := m.cfg.PanelCommandMap()
	if len(cmds) == 0 {
		return nil
	}
	out := map[string]target{}
	// The interval is resolved per id the same way the argv is, so a device
	// can be paced differently from the "default" one.
	add := func(id string, argv []string) {
		out[id] = target{
			argv:     argv,
			interval: time.Duration(m.cfg.PanelCommandIntervalFor(id)) * time.Second,
		}
	}

	var ids []string
	if m.reg != nil {
		if got, err := m.reg.ListDeviceIDs(); err == nil {
			ids = got
		} else {
			m.logger.Printf("panelgen: list devices: %v", err)
		}
	}
	for _, id := range ids {
		if argv := resolveArgv(cmds, id); argv != nil {
			add(id, argv)
		}
	}
	// Explicit per-device keys for devices not in the registry snapshot.
	for k, argv := range cmds {
		if k == "default" {
			continue
		}
		if _, ok := out[k]; !ok {
			add(k, argv)
		}
	}
	// Global default when nothing device-specific applies.
	if len(out) == 0 {
		if argv, ok := cmds["default"]; ok {
			add("", argv)
		}
	}
	return out
}

func resolveArgv(cmds map[string][]string, id string) []string {
	if argv, ok := cmds[id]; ok {
		return argv
	}
	if argv, ok := cmds["default"]; ok {
		return argv
	}
	return nil
}

// supervise runs one generator until ctx is cancelled. Which of the two
// contracts applies is the target's interval:
//
//   - 0 (the default): the command is expected to loop forever. Exiting is a
//     failure, so it restarts with exponential backoff.
//   - >0: the command is expected to sample once and exit, and we re-run it on
//     that period. Exiting is the normal case, so there is no backoff — the
//     interval is already the rate limit.
func (m *Manager) supervise(ctx context.Context, id string, t target) {
	if t.interval > 0 {
		m.superviseInterval(ctx, id, t)
		return
	}
	backoff := m.backoffInitial
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		ran, err := m.runOnce(ctx, id, t.argv)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.logger.Printf("panelgen[%s]: %v", labelOf(id), err)
		} else {
			m.logger.Printf("panelgen[%s]: exited after %s; restarting", labelOf(id), ran.Round(time.Millisecond))
		}
		// A generator that stayed up a good while is not crash-looping —
		// reset the backoff so a one-off exit restarts promptly.
		if time.Since(start) >= m.backoffReset {
			backoff = m.backoffInitial
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > m.backoffMax {
			backoff = m.backoffMax
		}
	}
}

// superviseInterval re-runs a one-shot generator every t.interval, measured
// start-to-start so the cadence does not drift with how long a run takes.
//
// Runs never overlap: a run that overruns its period simply delays the next
// one, which then starts immediately. We do not kill a slow generator — it
// may be mid-write, and half a document served to the device is worse than a
// late one. A run that fails waits the same interval as one that succeeds; a
// generator that cannot reach its source is expected to write its own "no
// data" document (docs/custom-panel.md), not to be retried harder.
func (m *Manager) superviseInterval(ctx context.Context, id string, t target) {
	m.logger.Printf("panelgen[%s]: every %s %v", labelOf(id), t.interval, t.argv)
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		ran, err := m.runOnce(ctx, id, t.argv)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.logger.Printf("panelgen[%s]: %v", labelOf(id), err)
		} else {
			m.logger.Printf("panelgen[%s]: run finished in %s", labelOf(id), ran.Round(time.Millisecond))
		}
		wait := t.interval - time.Since(start)
		if wait <= 0 {
			m.logger.Printf("panelgen[%s]: run outlasted its %s interval; starting the next one now",
				labelOf(id), t.interval)
			continue
		}
		if !sleepCtx(ctx, wait) {
			return
		}
	}
}

// runOnce starts the process, waits for it to exit or for ctx to cancel, and
// on cancellation terminates the whole process group (SIGTERM, then SIGKILL
// after termGrace). Returns how long the process ran and any start error.
func (m *Manager) runOnce(ctx context.Context, id string, argv []string) (time.Duration, error) {
	start := time.Now()
	cmd := exec.Command(argv[0], argv[1:]...)
	// Own process group so we can signal the child AND any grandchildren it
	// spawns, and so a Ctrl-C to the broker's own group doesn't hit it twice.
	// The per-OS SysProcAttr lives in proc_{unix,windows}.go.
	setSysProcAttr(cmd)
	cmd.Env = append(os.Environ(),
		"TMON_DEVICE_ID="+id,
		"TMON_PANEL_PATH="+m.targetPath(id),
	)
	lw := &logWriter{logger: m.logger, prefix: "panelgen[" + labelOf(id) + "]: "}
	cmd.Stdout = lw
	cmd.Stderr = lw

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	m.logger.Printf("panelgen[%s]: started pid=%d %v", labelOf(id), cmd.Process.Pid, argv)

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case <-waitCh:
		lw.flush()
		return time.Since(start), nil
	case <-ctx.Done():
		m.terminate(cmd.Process.Pid, waitCh)
		lw.flush()
		return time.Since(start), context.Canceled
	}
}

// terminate signals the child's process group SIGTERM, waits up to termGrace
// for the direct child to exit, then SIGKILLs the group. pgid == pid because
// Setpgid made the child a group leader. We SIGKILL the group even when the
// direct child exited promptly, to reap any grandchildren it spawned that
// ignored (or never received) the SIGTERM — killpg on an already-empty group
// is a harmless ESRCH.
func (m *Manager) terminate(pid int, waitCh <-chan error) {
	signalGroupTerm(pid)
	select {
	case <-waitCh:
		signalGroupKill(pid)
	case <-time.After(m.termGrace):
		signalGroupKill(pid)
		<-waitCh
	}
}

// targetPath is where a generator for id should write its document — the same
// place resolvePanelPath serves from, but computed without stat'ing (the file
// may not exist yet; the generator is what creates it).
func (m *Manager) targetPath(id string) string {
	if p := m.cfg.PanelFileExplicit(id); p != "" {
		return p
	}
	if dir := m.cfg.PanelDir(); dir != "" {
		if id != "" {
			return filepath.Join(dir, id+".json")
		}
		return filepath.Join(dir, "default.json")
	}
	return m.cfg.PanelFileDefault()
}

func labelOf(id string) string {
	if id == "" {
		return "default"
	}
	return id
}

// sameTarget decides whether a running child still matches what the config
// wants. The interval counts: re-pacing a generator has to restart it, or the
// change would only land whenever the child happened to die.
func sameTarget(a, b target) bool {
	return a.interval == b.interval && sameArgv(a.argv, b.argv)
}

func sameArgv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sleepCtx sleeps for d unless ctx is cancelled first. Returns false if ctx
// was cancelled (caller should stop), true if the full duration elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// logWriter forwards a child's stdout/stderr to the broker log line-by-line.
// os/exec copies both streams into it from separate goroutines, so writes are
// serialised with a mutex.
type logWriter struct {
	logger *log.Logger
	prefix string
	mu     sync.Mutex
	buf    []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := indexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := w.buf[:i]
		w.logger.Printf("%s%s", w.prefix, line)
		w.buf = w.buf[i+1:]
	}
	// Guard against an unbounded partial line from a child that never emits
	// a newline.
	if len(w.buf) > 8192 {
		w.logger.Printf("%s%s", w.prefix, w.buf)
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *logWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.logger.Printf("%s%s", w.prefix, w.buf)
		w.buf = w.buf[:0]
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

var _ io.Writer = (*logWriter)(nil)
