// Leader-scoped supervisor for the user's custom-panel generator processes.
//
// Mirror of the Go internal/panelgen package and the Python panel_generator
// module. main() starts it inside the leader's lifecycle (and in --daemon mode,
// which is the leader by construction) and stops it when this process loses the
// bound port or shuts down. A follower never starts it, so each device's panel
// file has exactly one writer even when several tokenmonitor-mcp processes run.
//
// The commands come ONLY from the local, already-trusted tokenmonitor.toml
// ([panel.command], keyed by device id with a "default" fallback). They run as
// the broker's user with a shell-free argv. The control plane / config_sync can
// never populate them — that path writes device NVS, not the broker toml.
//
// Each generator is supervised: if it exits (cleanly or by crashing) while we
// are still the leader, it is respawned with exponential backoff. On teardown
// the whole process group is sent SIGTERM, then SIGKILL after a grace period,
// so nothing is orphaned.
//
// A command that samples once and exits rather than looping can say so with
// [panel.command_interval_s]: then it is re-run on that period instead, and
// exiting is the normal case rather than a failure.

import { spawn } from "node:child_process";
import { join as joinPath } from "node:path";

const label = (id) => id || "default";

function sameArgv(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class PanelGenerator {
  constructor(cfg, registry, logger, opts = {}) {
    this.cfg = cfg;
    this.registry = registry;
    this.logger = logger;
    this.reconcileInterval = opts.reconcileInterval ?? 20000;
    this.termGrace = opts.termGrace ?? 5000;
    this.backoffInitial = opts.backoffInitial ?? 1000;
    this.backoffMax = opts.backoffMax ?? 30000;
    this.backoffReset = opts.backoffReset ?? 60000;
    this._children = new Map(); // id -> child
    this._timer = null;
    this._started = false;
    this._reconciling = false;
    this._stopPromise = null;
  }

  enabled() {
    return Object.keys(this.cfg.panelCommandMap()).length > 0;
  }

  // start launches the reconcile loop. No-op when [panel.command] is empty.
  // If an AbortSignal is given, aborting it triggers stop() (leadership loss /
  // shutdown), mirroring how ota.run is scoped in index.js.
  start(abortSignal) {
    if (this._started || !this.enabled()) return;
    if (abortSignal && abortSignal.aborted) return;
    this._started = true;
    if (abortSignal) {
      abortSignal.addEventListener("abort", () => { this.stop(); }, { once: true });
    }
    this._reconcile();
    this._timer = setInterval(() => this._reconcile(), this.reconcileInterval);
    if (this._timer.unref) this._timer.unref();
  }

  // stop tears down every child (SIGTERM → SIGKILL) and blocks until all have
  // exited. Idempotent and re-entrant: concurrent callers (e.g. the abort
  // listener and the caller's finally block) share one settle promise, so
  // `await stop()` is always a true barrier.
  stop() {
    if (this._stopPromise) return this._stopPromise;
    if (!this._started) return Promise.resolve();
    this._started = false;
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    this._stopPromise = (async () => {
      const kids = [...this._children.values()];
      this._children.clear();
      await Promise.all(kids.map((c) => this._stopChild(c)));
    })();
    return this._stopPromise;
  }

  async _reconcile() {
    // Guard against overlapping ticks (a removal awaits the child's death, so
    // a reconcile can outlast the interval) and against running after stop().
    if (!this._started || this._reconciling) return;
    this._reconciling = true;
    try {
      const targets = this._targets();
      const removals = [];
      for (const [id, child] of [...this._children]) {
        // The interval is part of the identity: re-pacing a generator has to
        // restart it, or the change would only land whenever the child
        // happened to die.
        const t = targets.get(id);
        if (!t || !sameArgv(t.argv, child.argv) || t.interval !== child.interval) {
          this._children.delete(id);
          removals.push(this._stopChild(child));
        }
      }
      // Await removals BEFORE starting replacements so a changed command never
      // has two processes writing the same file during the term grace.
      if (removals.length) await Promise.all(removals);
      if (!this._started) return;
      for (const [id, t] of targets) {
        if (this._children.has(id)) continue;
        const child = {
          id, argv: t.argv, interval: t.interval,
          stopped: false, proc: null, wakeBackoff: null,
        };
        child.done = this._supervise(child);
        this._children.set(id, child);
      }
    } finally {
      this._reconciling = false;
    }
  }

  async _stopChild(child) {
    child.stopped = true;
    if (child.wakeBackoff) child.wakeBackoff();
    await this._terminate(child);
    try { await child.done; } catch { /* supervisor never rejects */ }
  }

  // targets: desired {deviceID -> {argv, interval}}. Per device: its own
  // command, else "default"; the interval resolves the same way, so a device
  // can be paced differently from the default one. interval 0 = long-lived
  // process (the default contract), >0 = one-shot re-run on that period in ms.
  // Every registered device is a candidate; explicit non-default keys run even
  // for unregistered devices. With no devices at all, a lone "default" runs one
  // global generator (empty id → feeds file.default).
  _targets() {
    const cmds = this.cfg.panelCommandMap();
    const out = new Map();
    if (Object.keys(cmds).length === 0) return out;
    const mk = (id, argv) => ({ argv, interval: this.cfg.panelCommandIntervalFor(id) * 1000 });
    let ids = [];
    if (this.registry) {
      try { ids = this.registry.listDeviceIds(); }
      catch (e) { this.logger.warn(`panelgen: list devices: ${e.message}`); }
    }
    for (const id of ids) {
      const argv = cmds[id] || cmds.default;
      if (argv) out.set(id, mk(id, argv));
    }
    for (const [k, argv] of Object.entries(cmds)) {
      if (k === "default") continue;
      if (!out.has(k)) out.set(k, mk(k, argv));
    }
    if (out.size === 0 && cmds.default) out.set("", mk("", cmds.default));
    return out;
  }

  _targetPath(id) {
    const explicit = this.cfg.panelFileExplicitAbs(id);
    if (explicit) return explicit;
    const dir = this.cfg.panelDirAbs();
    if (dir) return id ? joinPath(dir, `${id}.json`) : joinPath(dir, "default.json");
    return this.cfg.panelFileDefaultAbs();
  }

  // _supervise runs one generator until the child is stopped. Which of the two
  // contracts applies is the child's interval:
  //
  // - 0 (the default): the command is expected to loop forever. Exiting is a
  //   failure, so it restarts with exponential backoff.
  // - >0: the command is expected to sample once and exit, and we re-run it on
  //   that period. Exiting is the normal case, so there is no backoff — the
  //   interval is already the rate limit.
  async _supervise(child) {
    if (child.interval > 0) return this._superviseInterval(child);
    let backoff = this.backoffInitial;
    while (!child.stopped) {
      const start = Date.now();
      const started = await this._runOnce(child);
      if (child.stopped) return; // stop path already terminated / will not restart
      if (started) {
        const ran = Date.now() - start;
        this.logger.info(`panelgen[${label(child.id)}]: exited after ${(ran / 1000).toFixed(1)}s; restarting`);
        // A generator that stayed up a good while is not crash-looping.
        if (ran >= this.backoffReset) backoff = this.backoffInitial;
      }
      if (!(await this._sleepUnlessStopped(child, backoff))) return;
      backoff = Math.min(backoff * 2, this.backoffMax);
    }
  }

  // _superviseInterval re-runs a one-shot generator every child.interval ms,
  // measured start-to-start so the cadence does not drift with how long a run
  // takes.
  //
  // Runs never overlap: a run that overruns its period simply delays the next
  // one, which then starts immediately. We do not kill a slow generator — it
  // may be mid-write, and half a document served to the device is worse than a
  // late one. A run that fails waits the same interval as one that succeeds; a
  // generator that cannot reach its source is expected to write its own "no
  // data" document (docs/custom-panel.md), not to be retried harder.
  async _superviseInterval(child) {
    const secs = (child.interval / 1000).toFixed(0);
    this.logger.info(`panelgen[${label(child.id)}]: every ${secs}s ${JSON.stringify(child.argv)}`);
    while (!child.stopped) {
      const start = Date.now();
      const started = await this._runOnce(child);
      if (child.stopped) return;
      if (started) {
        this.logger.info(`panelgen[${label(child.id)}]: run finished in ${((Date.now() - start) / 1000).toFixed(1)}s`);
      }
      const wait = child.interval - (Date.now() - start);
      if (wait <= 0) {
        this.logger.info(`panelgen[${label(child.id)}]: run outlasted its ${secs}s interval; starting the next one now`);
        continue;
      }
      if (!(await this._sleepUnlessStopped(child, wait))) return;
    }
  }

  // _runOnce spawns the generator and waits for it to exit. Returns false when
  // it could not be spawned at all — already logged.
  async _runOnce(child) {
    let proc;
    try {
      proc = spawn(child.argv[0], child.argv.slice(1), {
        env: { ...process.env, TMON_DEVICE_ID: child.id, TMON_PANEL_PATH: this._targetPath(child.id) },
        detached: true, // own process group so we can SIGTERM/SIGKILL the group
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      this.logger.error(`panelgen[${label(child.id)}]: ${e.message}`);
      return false;
    }
    child.proc = proc;
    this.logger.info(`panelgen[${label(child.id)}]: started pid=${proc.pid} ${JSON.stringify(child.argv)}`);
    this._pipeLogs(child.id, proc);

    const exited = new Promise((resolve) => {
      proc.once("exit", () => resolve("exit"));
      proc.once("error", (e) => { this.logger.error(`panelgen[${label(child.id)}]: ${e.message}`); resolve("error"); });
    });
    await exited;
    return true;
  }

  // _terminate sends the child's process group SIGTERM, waits up to termGrace,
  // then SIGKILLs the group unconditionally to reap any grandchildren (harmless
  // ESRCH if the group is already empty). Safe to call when the child never
  // started (failed spawn → no pid) or already exited.
  async _terminate(child) {
    const proc = child.proc;
    if (!proc || !proc.pid || proc.exitCode !== null || proc.signalCode !== null) return;
    const exited = new Promise((resolve) => proc.once("exit", resolve));
    try { process.kill(-proc.pid, "SIGTERM"); } catch { /* already gone */ }
    let killTimer;
    const grace = new Promise((resolve) => {
      killTimer = setTimeout(() => resolve("timeout"), this.termGrace);
      if (killTimer.unref) killTimer.unref();
    });
    await Promise.race([exited.then(() => "exited"), grace]);
    clearTimeout(killTimer);
    try { process.kill(-proc.pid, "SIGKILL"); } catch { /* already gone */ }
    await exited;
  }

  // _sleepUnlessStopped resolves true after `ms`, or false early if the child
  // is stopped meanwhile (so the supervisor bails out promptly).
  _sleepUnlessStopped(child, ms) {
    if (child.stopped) return Promise.resolve(false);
    if (ms <= 0) return Promise.resolve(true);
    return new Promise((resolve) => {
      const t = setTimeout(() => { child.wakeBackoff = null; resolve(true); }, ms);
      if (t.unref) t.unref();
      child.wakeBackoff = () => { clearTimeout(t); child.wakeBackoff = null; resolve(false); };
    });
  }

  _pipeLogs(id, proc) {
    const mk = (stream) => {
      if (!stream) return;
      let buf = "";
      stream.on("data", (chunk) => {
        buf += chunk.toString();
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          this.logger.info(`panelgen[${label(id)}]: ${buf.slice(0, i)}`);
          buf = buf.slice(i + 1);
        }
        if (buf.length > 8192) { this.logger.info(`panelgen[${label(id)}]: ${buf}`); buf = ""; }
      });
    };
    mk(proc.stdout);
    mk(proc.stderr);
  }
}
