// First-run config bootstrap (mirror of Go config/bootstrap_test.go and
// py/tests/test_config_bootstrap.py).
//
// Before this, load() on a machine with no
// ~/.config/tokenmonitor/tokenmonitor.toml threw "file not found" and the
// process exited, so the MCP client never saw the server reach "ready" and
// silently dropped it from the session.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, statSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

import { load, bootstrap } from "../src/config.js";

// os.homedir() reads $HOME on POSIX, which is what expandUser() resolves.
function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), "tmon-home-"));
  const prev = process.env.HOME;
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (prev === undefined) delete process.env.HOME;
    else process.env.HOME = prev;
  }
}

function defaultConfigPath(home) {
  return join(home, ".config", "tokenmonitor", "tokenmonitor.toml");
}

test("load() bootstraps a missing default config", () => {
  withHome((home) => {
    const cfg = load();

    const path = defaultConfigPath(home);
    assert.ok(existsSync(path), "config was not created");
    // The file holds a shared secret; it must not be world- or group-readable.
    assert.equal(statSync(path).mode & 0o777, 0o600);

    assert.ok(cfg.auth.psk_passphrase);
    assert.ok(!cfg.auth.psk_passphrase.includes("@@"), "placeholder not substituted");
    assert.equal(cfg.auth.psk_passphrase.length, 32);
    assert.deepEqual(
      cfg.pskBytes,
      createHash("sha256").update(cfg.auth.psk_passphrase).digest(),
    );
    // Defaults the device depends on must survive the short template.
    assert.equal(cfg.server.bind, "0.0.0.0");
    assert.equal(cfg.server.port, 8765);
  });
});

test("load() bootstrap is idempotent", () => {
  // The second start must adopt the first run's passphrase, not mint a new one
  // — rotating it would silently break every device already paired.
  withHome(() => {
    assert.equal(load().auth.psk_passphrase, load().auth.psk_passphrase);
  });
});

test("load() with an explicit path does not bootstrap", () => {
  // --config names a file the user believes exists. Creating it silently would
  // hide their typo behind a broker that starts with the wrong settings.
  withHome((home) => {
    const missing = join(home, "typo.toml");
    assert.throws(() => load(missing), /file not found/);
    assert.ok(!existsSync(missing), "explicit missing path was created");
  });
});

test("load() prefers a legacy service.toml over bootstrapping", () => {
  withHome((home) => {
    const dir = join(home, ".config", "tokenmonitor");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "service.toml"), '[auth]\npsk_passphrase = "legacy-secret"\n');

    assert.equal(load().auth.psk_passphrase, "legacy-secret");
    assert.ok(!existsSync(defaultConfigPath(home)), "bootstrapped despite a legacy config");
  });
});

test("load() does not shadow an unreadable legacy service.toml", (t) => {
  // Bootstrapping over a service.toml that exists but cannot be read (root-owned
  // after a sudo run, say) would start the broker on a brand-new passphrase and
  // silently break every device paired against the old one.
  if (process.getuid && process.getuid() === 0) {
    t.skip("root bypasses file permissions");
    return;
  }
  withHome((home) => {
    const dir = join(home, ".config", "tokenmonitor");
    mkdirSync(dir, { recursive: true });
    const legacy = join(dir, "service.toml");
    writeFileSync(legacy, '[auth]\npsk_passphrase = "legacy-secret"\n');
    chmodSync(legacy, 0o000);

    assert.throws(() => load(), /EACCES|permission denied/i);
    assert.ok(!existsSync(defaultConfigPath(home)), "bootstrapped over an unreadable legacy");
  });
});

test("bootstrap() loser of the race adopts the winner's file", () => {
  // Several tokenmonitor-mcp processes can start simultaneously (leader
  // election happens later, on the port). The second writer must return the
  // first one's bytes, not overwrite them with a different passphrase.
  const path = join(mkdtempSync(join(tmpdir(), "tmon-cfg-")), "tokenmonitor.toml");
  assert.equal(bootstrap(path), bootstrap(path));
});
