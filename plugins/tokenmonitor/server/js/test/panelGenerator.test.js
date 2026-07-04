// Custom-panel generator: config parsing + leader-scoped supervision.
// Mirrors Go internal/panelgen + internal/config panel tests and the Python
// test_panel_generator: string-or-table [panel.file], [panel.command] parsing,
// per-device target resolution, spawn on start, restart-on-exit with backoff,
// and SIGTERM→SIGKILL teardown.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, statSync } from "node:fs";
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

// --- target resolution ----------------------------------------------------

function fakeCfg({ command = {}, file = {}, dir = "" } = {}) {
  return {
    panelCommandMap: () => command,
    panelFileExplicitAbs: (id) => (id && file[id] ? file[id] : ""),
    panelFileDefaultAbs: () => file.default || "",
    panelDirAbs: () => dir,
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
  assert.deepEqual(t.get("dev1"), special);
  assert.deepEqual(t.get("dev2"), def);
  assert.equal(t.has(""), false);
});

test("targets: explicit key for an unregistered device", () => {
  const special = ["gen", "special"];
  const g = gen(fakeCfg({ command: { "tmon-ab12": special } }), null);
  const t = g._targets();
  assert.deepEqual(t.get("tmon-ab12"), special);
  assert.equal(t.has(""), false);
});

test("targets: global default when there are no devices", () => {
  const def = ["gen"];
  const g = gen(fakeCfg({ command: { default: def } }), null);
  const t = g._targets();
  assert.equal(t.size, 1);
  assert.deepEqual(t.get(""), def);
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
