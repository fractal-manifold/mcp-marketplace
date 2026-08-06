// First-run config bootstrap (mirror of Go config/bootstrap_test.go and
// py/tests/test_config_bootstrap.py).
//
// Before this, load() on a machine with no
// ~/.config/tokenmonitor/tokenmonitor.toml threw "file not found" and the
// process exited, so the MCP client never saw the server reach "ready" and
// silently dropped it from the session.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  statSync,
  chmodSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

import { load, bootstrap, FALLBACK_PSK_NAME } from "../src/config.js";

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

// Drop a config with the given [auth] body at the canonical path.
function writeDefaultConfig(home, authBody) {
  const path = defaultConfigPath(home);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `[server]\nbind = "0.0.0.0"\nport = 8765\n\n[auth]\n${authBody}`);
  return path;
}

test("load() falls back to a sidecar key when the config has an empty PSK", () => {
  // A config that EXISTS but carries no usable PSK used to throw before the
  // server answered `initialize`, so the MCP client dropped it exactly as it
  // did with no config at all. A hand-written psk_hex = "" is the real case.
  withHome((home) => {
    const path = writeDefaultConfig(home, 'psk_hex = ""\n');
    const cfg = load();
    assert.equal(cfg.pskBytes.length, 32);

    const sidecar = join(dirname(path), FALLBACK_PSK_NAME);
    assert.equal(statSync(sidecar).mode & 0o777, 0o600);
    // The config itself must be left exactly as the user wrote it.
    assert.match(readFileSync(path, "utf8"), /psk_hex = ""/);
  });
});

test("load() falls back to a sidecar key when there is no [auth] section", () => {
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "[server]\nport = 8765\n");
    assert.equal(load().pskBytes.length, 32);
  });
});

test("load() fallback PSK is stable across starts", () => {
  // A key that changed on every start would break any device holding the
  // global PSK.
  withHome((home) => {
    writeDefaultConfig(home, 'psk_hex = ""\n');
    assert.deepEqual(load().pskBytes, load().pskBytes);
  });
});

test("load() drops a malformed [auth] instead of dying on it", () => {
  // A typo in [auth] must not cost you the broker: it is how a device gets
  // configured in the first place. The section is dropped, the sidecar supplies
  // a key, and the salvage is reported — the user's file is never rewritten.
  const cases = [
    ['psk_passphrase = "abc"\n', "short passphrase"],
    ['psk_hex = "abcd"\n', "short hex"],
    [`psk_hex = "${"z".repeat(64)}"\n`, "non-hex"],
    ["psk_hex = []\n", "wrong type"],
  ];
  for (const [authBody, label] of cases) {
    withHome((home) => {
      const path = writeDefaultConfig(home, authBody);
      const cfg = load();
      assert.equal(cfg.pskBytes.length, 32, `${label}: no usable PSK`);
      assert.ok(
        existsSync(join(dirname(path), FALLBACK_PSK_NAME)),
        `${label}: no fallback key minted after dropping [auth]`,
      );
      assert.ok(cfg.salvaged.length > 0, `${label}: dropped a section silently`);
      assert.ok(
        readFileSync(path, "utf8").includes(authBody.trim()),
        `${label}: the user's config was rewritten`,
      );
    });
  }
});

test("load() salvage keeps the good sections", () => {
  // The property the whole salvage exists for: one broken section must not cost
  // you the rest of the file, and what survives has to be the values the user
  // actually wrote.
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      '[server]\nbind = "0.0.0.0"\nport = 9999\n\n' +
        '[auth]\npsk_passphrase = "a-good-long-passphrase"\n\n' +
        '[logging]\nlevel = "DEBUG"\n\n' +
        "[panel\nthis section is broken\n",
    );

    const cfg = load();
    assert.equal(cfg.server.port, 9999);
    assert.equal(cfg.server.bind, "0.0.0.0");
    assert.equal(cfg.auth.psk_passphrase, "a-good-long-passphrase");
    assert.deepEqual(
      cfg.pskBytes,
      createHash("sha256").update("a-good-long-passphrase", "utf8").digest(),
    );
    assert.equal(cfg.logging.level, "DEBUG");
    assert.ok(cfg.salvaged.length > 0, "dropped a section without reporting it");
  });
});

test("load() salvage never fabricates a section", () => {
  // The soundness property: a line starting with '[' inside a multi-line string
  // is not a header, and a splitter that trusted it would hand the salvage a
  // chunk of *string content* that parses as a perfectly good [auth] — with a
  // PSK the user never set. Losing data is acceptable; inventing it is not.
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    // [auth] here is the contents of panel.file, not a section: the '#' makes
    // the closing """ a comment, so a naive split sees a header.
    writeFileSync(
      path,
      '[panel]\nfile = """\n[auth] # """\npsk_passphrase = "fabricated-secret"\n\n[broken\nx\n',
    );

    const cfg = load();
    assert.equal(cfg.auth.psk_passphrase, "", "invented an [auth] out of string content");
    assert.notDeepEqual(
      cfg.pskBytes,
      createHash("sha256").update("fabricated-secret", "utf8").digest(),
    );
    assert.equal(cfg.pskBytes.length, 32);
  });
});

test("load() salvage keeps a valid passphrase under a stale psk_hex", () => {
  // load() resolves the passphrase first and never reads psk_hex when one is
  // set, so a leftover malformed hex must not condemn the section. Dropping
  // [auth] here would swap a working key for the sidecar and desync every
  // paired device.
  withHome((home) => {
    writeDefaultConfig(home, 'psk_passphrase = "the-current-valid-secret"\npsk_hex = "bad"\n');

    const cfg = load();
    assert.deepEqual(
      cfg.pskBytes,
      createHash("sha256").update("the-current-valid-secret", "utf8").digest(),
    );
    assert.deepEqual(cfg.salvaged, []);
  });
});

test("load() salvage does not widen an unreadable bind", () => {
  // The 0.0.0.0 rescue exists so a device can still reach the broker, but a
  // bind we failed to parse is still the user saying something about their
  // network boundary. Widening it on their behalf is not a rescue.
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, '[server]\nbind = "127.0.0.1"\nport == 8765\n');

    const cfg = load();
    assert.notEqual(cfg.server.bind, "0.0.0.0");
    assert.ok(cfg.salvaged.length > 0);
  });
});

test("load() salvage names a dropped repeated header", () => {
  // [[ota.keys]] is one entry per signing key, so the same header appears
  // several times. A dropped second entry must still be named — matching
  // kept-vs-dropped by presence would let it hide behind the first entry that
  // survived, and losing a signing key silently is what the report prevents.
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      '[auth]\npsk_passphrase = "a-good-long-passphrase"\n\n' +
        '[[ota.keys]]\nkey_id = "k1"\npubkey_b64 = "AAAA"\n\n' +
        // A syntax error, not a type error: Go's typed unmarshal rejects a
        // wrong-typed value that py/js would coerce, and this test is about the
        // reporting, so it has to fail identically in all three parsers.
        '[[ota.keys]]\nkey_id = "k2"\npubkey_b64 == "AAAA"\n',
    );

    const cfg = load();
    assert.deepEqual(cfg.ota.keys.map((k) => k.key_id), ["k1"]);
    assert.ok(cfg.salvaged.some((s) => s.includes("ota.keys")), cfg.salvaged.join("; "));
  });
});

test("load() salvage still binds for the device", () => {
  // When the rescue loses [server], the code default (loopback) would leave the
  // device unable to reach the broker — and the broker is how a device gets
  // configured. Fall back to the bind a fresh bootstrap would have written.
  withHome((home) => {
    const path = defaultConfigPath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "[server\nbroken header\n");

    const cfg = load();
    assert.equal(cfg.server.bind, "0.0.0.0");
    assert.equal(cfg.server.port, 8765);
    assert.equal(cfg.pskBytes.length, 32);
  });
});

test("load() with an explicit path is strict, never salvaged", () => {
  // --config is the operator's file. Quietly running on half of it would hide
  // the mistake behind a broker that works but isn't doing what they wrote.
  const dir = mkdtempSync(join(tmpdir(), "tmon-cfg-"));
  const path = join(dir, "explicit.toml");
  writeFileSync(path, "[server]\nport = 9999\n\n[panel\nbroken\n");

  assert.throws(() => load(path), /parse /);
});

test("load() with an explicit path mints no fallback key", () => {
  // An operator-supplied --config may be managed from elsewhere; we don't
  // quietly add a key beside it.
  const dir = mkdtempSync(join(tmpdir(), "tmon-cfg-"));
  const path = join(dir, "explicit.toml");
  writeFileSync(path, '[auth]\npsk_hex = ""\n');

  assert.throws(() => load(path), /psk_passphrase or psk_hex is required/);
  assert.ok(!existsSync(join(dir, FALLBACK_PSK_NAME)));
});

test("load() refuses to overwrite a corrupt sidecar", () => {
  // The user may have put a specific key there.
  withHome((home) => {
    const path = writeDefaultConfig(home, 'psk_hex = ""\n');
    const sidecar = join(dirname(path), FALLBACK_PSK_NAME);
    writeFileSync(sidecar, "not-a-key\n");

    assert.throws(() => load(), /64 hex characters/);
    assert.equal(readFileSync(sidecar, "utf8").trim(), "not-a-key");
  });
});

test("bootstrap() loser of the race adopts the winner's file", () => {
  // Several tokenmonitor-mcp processes can start simultaneously (leader
  // election happens later, on the port). The second writer must return the
  // first one's bytes, not overwrite them with a different passphrase.
  const path = join(mkdtempSync(join(tmpdir(), "tmon-cfg-")), "tokenmonitor.toml");
  assert.equal(bootstrap(path), bootstrap(path));
});
