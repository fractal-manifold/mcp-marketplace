// Custom-panel generator: config parsing + leader-scoped supervision.
// Mirrors Go internal/panelgen + internal/config panel tests and the Python
// test_panel_generator: string-or-table [panel.file], [panel.command] parsing,
// per-device target resolution, spawn on start, restart-on-exit with backoff,
// and SIGTERM→SIGKILL teardown.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, statSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { homedir } from "node:os";

import { load } from "../src/config.js";
import { PanelGenerator } from "../src/panelGenerator.js";

const AUTH = '[auth]\npsk_passphrase = "passphrase-1234"\n';
const silentLogger = { info() {}, warn() {}, error() {} };

function loadTOML(body) {
  const dir = mkdtempSync(join(tmpdir(), "tmon-cfg-"));
  const p = join(dir, "tokenmonitor.toml");
  writeFileSync(p, AUTH + body);
  try { return load(p); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

// --- config parsing -------------------------------------------------------

test("panel.file bare string becomes the default entry", () => {
  const cfg = loadTOML('[panel]\nfile = "~/panel.json"\n');
  assert.equal(cfg.panelFileDefaultAbs(), join(homedir(), "panel.json"));
  assert.equal(cfg.panelFileExplicitAbs("dev1"), "");
});

test("panel.file table resolves per device", () => {
  const cfg = loadTOML('[panel.file]\ndefault = "/panels/default.json"\n"tmon-ab12" = "/panels/ab12.json"\n');
  assert.equal(cfg.panelFileDefaultAbs(), "/panels/default.json");
  assert.equal(cfg.panelFileExplicitAbs("tmon-ab12"), "/panels/ab12.json");
  assert.equal(cfg.panelFileExplicitAbs("other"), "");
});

test("panel.command table parses and tilde-expands argv", () => {
  const cfg = loadTOML('[panel.command]\ndefault = ["python3", "~/bin/gen.py"]\n"tmon-ab12" = ["/usr/bin/special", "--fast"]\n');
  const cmds = cfg.panelCommandMap();
  assert.equal(cmds.default[0], "python3");
  assert.equal(cmds.default[1], join(homedir(), "bin/gen.py"));
  assert.deepEqual(cmds["tmon-ab12"], ["/usr/bin/special", "--fast"]);
});

test("no [panel.command] yields an empty map", () => {
  const cfg = loadTOML("");
  assert.deepEqual(cfg.panelCommandMap(), {});
  assert.equal(cfg.panelFileDefaultAbs(), "");
  assert.equal(cfg.panelDirAbs(), "");
});

test("panel.command_interval_s bare number becomes the default entry", () => {
  const cfg = loadTOML("[panel]\ncommand_interval_s = 900\n");
  assert.equal(cfg.panelCommandIntervalFor("anything"), 900);
});

test("panel.command_interval_s table resolves per device", () => {
  const cfg = loadTOML('[panel.command_interval_s]\ndefault = 900\n"tmon-ab12" = 60\n');
  assert.equal(cfg.panelCommandIntervalFor("tmon-ab12"), 60);
  assert.equal(cfg.panelCommandIntervalFor("other"), 900);
});

test("absent panel.command_interval_s is 0 (long-lived process)", () => {
  const cfg = loadTOML('[panel.command]\ndefault = ["gen"]\n');
  assert.equal(cfg.panelCommandIntervalFor("dev1"), 0);
});

// Must fail loudly, exactly as the Go broker does on the same toml.
test("panel.command_interval_s rejects bad values", () => {
  // 0.5 s truncated to 0 would mean "long-lived process" — the opposite
  // contract to what was asked for, so it is an error, not a rounding.
  for (const body of [
    "[panel]\ncommand_interval_s = -5\n",
    "[panel]\ncommand_interval_s = 0.5\n",
    '[panel]\ncommand_interval_s = "900"\n',
  ]) {
    assert.throws(() => loadTOML(body), undefined, `should reject: ${body}`);
  }
});

test("panel.command_interval_s accepts an integral float", () => {
  const cfg = loadTOML("[panel]\ncommand_interval_s = 900.0\n");
  assert.equal(cfg.panelCommandIntervalFor("dev1"), 900);
});

// --- target resolution ----------------------------------------------------

function fakeCfg({ command = {}, file = {}, dir = "", intervalS = 0 } = {}) {
  return {
    panelCommandMap: () => command,
    panelFileExplicitAbs: (id) => (id && file[id] ? file[id] : ""),
    panelFileDefaultAbs: () => file.default || "",
    panelDirAbs: () => dir,
    // Mirrors cfg.panelCommandIntervalFor: a number is the "default" entry, an
    // object is the per-device table.
    panelCommandIntervalFor: (id) => {
      if (intervalS && typeof intervalS === "object") {
        const v = id in intervalS ? intervalS[id] : intervalS.default;
        return typeof v === "number" && v > 0 ? v : 0;
      }
      return typeof intervalS === "number" && intervalS > 0 ? intervalS : 0;
    },
  };
}

function fakeReg(ids) {
  return { listDeviceIds: () => ids };
}

function gen(cfg, reg) {
  return new PanelGenerator(cfg, reg, silentLogger, {
    reconcileInterval: 50,
    termGrace: 300,
    backoffInitial: 20,
    backoffMax: 40,
    backoffReset: 500,
  });
}

test("targets: per-device resolution with default fallback", () => {
  const def = ["gen", "default"];
  const special = ["gen", "special"];
  const g = gen(fakeCfg({ command: { default: def, dev1: special } }), fakeReg(["dev1", "dev2"]));
  const t = g._targets();
  assert.deepEqual(t.get("dev1").argv, special);
  assert.deepEqual(t.get("dev2").argv, def);
  assert.equal(t.has(""), false);
});

test("targets: explicit key for an unregistered device", () => {
  const special = ["gen", "special"];
  const g = gen(fakeCfg({ command: { "tmon-ab12": special } }), null);
  const t = g._targets();
  assert.deepEqual(t.get("tmon-ab12").argv, special);
  assert.equal(t.has(""), false);
});

test("targets: global default when there are no devices", () => {
  const def = ["gen"];
  const g = gen(fakeCfg({ command: { default: def } }), null);
  const t = g._targets();
  assert.equal(t.size, 1);
  assert.deepEqual(t.get("").argv, def);
  // absent [panel.command_interval_s] = the long-lived-process contract
  assert.equal(t.get("").interval, 0);
});

test("targetPath: explicit > dir > default", () => {
  const g = gen(fakeCfg({ file: { default: "/panels/default.json", dev1: "/panels/dev1.json" }, dir: "/panels/dir" }));
  assert.equal(g._targetPath("dev1"), "/panels/dev1.json");
  assert.equal(g._targetPath("dev2"), "/panels/dir/dev2.json");
  assert.equal(g._targetPath(""), "/panels/dir/default.json");
  const g2 = gen(fakeCfg({ file: { default: "/panels/default.json" } }));
  assert.equal(g2._targetPath("dev9"), "/panels/default.json");
});

// --- supervision ----------------------------------------------------------

async function waitFor(ms, cond) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return cond();
}

test("supervisor spawns on start and kills on stop", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-pg-"));
  const f = join(dir, "count");
  try {
    const argv = ["sh", "-c", `while true; do printf x >> '${f}'; sleep 0.02; done`];
    const g = gen(fakeCfg({ command: { default: argv } }), null);
    g.start();
    assert.ok(await waitFor(2000, () => existsSync(f) && statSync(f).size > 0), "generator never wrote its file");
    await g.stop();
    const settled = statSync(f).size;
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(statSync(f).size, settled, "child kept writing after stop — not killed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("supervisor restarts a generator that exits", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-pg-"));
  const f = join(dir, "runs");
  try {
    const argv = ["sh", "-c", `printf x >> '${f}'`]; // one byte, exit 0
    const g = gen(fakeCfg({ command: { default: argv } }), null);
    g.start();
    try {
      assert.ok(await waitFor(2000, () => existsSync(f) && statSync(f).size >= 3), "expected >=3 restarts");
    } finally {
      await g.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The point of the feature: a command that samples once and exits gets re-run
// on its own period instead of being treated as a crash.
test("interval mode re-runs a one-shot generator", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-pg-"));
  const f = join(dir, "runs");
  try {
    const argv = ["sh", "-c", `printf x >> '${f}'`];
    // 0.06 s — sub-second so the test stays quick; the config unit is seconds.
    const g = gen(fakeCfg({ command: { default: argv }, intervalS: 0.06 }), null);
    g.start();
    try {
      assert.ok(await waitFor(2000, () => existsSync(f) && statSync(f).size >= 3), "expected >=3 paced runs");
    } finally {
      await g.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A run that outlasts its period must delay the next one, not overlap it.
test("interval mode does not overlap runs", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-pg-"));
  const f = join(dir, "runs");
  try {
    // 's' on entry, 'e' on exit: overlapping runs would show up as "ss"/"ee".
    const argv = ["sh", "-c", `printf s >> '${f}'; sleep 0.2; printf e >> '${f}'`];
    const g = gen(fakeCfg({ command: { default: argv }, intervalS: 0.02 }), null);
    g.start();
    try {
      // Assert the wait, or a generator that never ran would make the marker
      // loop below iterate over nothing and pass vacuously.
      assert.ok(
        await waitFor(3000, () => existsSync(f) && statSync(f).size >= 4),
        "expected at least two complete runs",
      );
    } finally {
      await g.stop();
    }
    let got = readFileSync(f, "utf8");
    if (got.endsWith("s")) got = got.slice(0, -1); // the run stop() interrupted
    for (let i = 0; i + 1 < got.length; i += 2) {
      assert.equal(got.slice(i, i + 2), "se", `runs overlapped: ${JSON.stringify(got)}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Re-pacing has to restart the child, or the new interval would only land
// whenever the old one happened to die.
test("changing the interval restarts the child", async () => {
  let intervalS = 60;
  const cfg = fakeCfg({ command: { default: ["sh", "-c", "sleep 5"] } });
  cfg.panelCommandIntervalFor = () => intervalS;
  const g = gen(cfg, null);
  g.start();
  try {
    assert.ok(await waitFor(2000, () => g._children.size > 0), "child never started");
    const first = g._children.get("");
    intervalS = 30;
    // Wait for the REPLACEMENT, not merely for the old entry to go: reconcile
    // deletes before it re-adds, so `!== first` is briefly true with no child.
    assert.ok(
      await waitFor(2000, () => { const c = g._children.get(""); return c && c !== first; }),
      "reconcile kept the old child after the interval changed",
    );
    assert.equal(g._children.get("").interval, 30000);
  } finally {
    await g.stop();
  }
});

test("teardown escalates SIGTERM to SIGKILL for a stubborn child", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tmon-pg-"));
  const f = join(dir, "alive");
  try {
    const argv = ["sh", "-c", `trap '' TERM; while true; do printf x >> '${f}'; sleep 0.02; done`];
    const g = gen(fakeCfg({ command: { default: argv } }), null);
    g.start();
    assert.ok(await waitFor(2000, () => existsSync(f) && statSync(f).size > 0), "stubborn child never started");
    const start = Date.now();
    await g.stop();
    assert.ok(Date.now() - start >= g.termGrace, "stop returned before SIGTERM grace — no SIGKILL escalation?");
    const settled = statSync(f).size;
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(statSync(f).size, settled, "stubborn child survived stop");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
