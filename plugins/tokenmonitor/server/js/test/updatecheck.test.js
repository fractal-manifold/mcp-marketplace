// Tests for the broker self-version check (src/updatecheck.js): the verdict is
// `outdated` when the remote catalog is newer than installed, `up to date` when
// equal, and `unknown` on any fetch/parse failure. The marketplace URL is
// pointed at a local http server via TMON_MARKETPLACE_URL, exactly the
// override the module honours in production.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { check, fetchLatest, marketplaceURL, installedVersion } from "../src/updatecheck.js";

// Spin up a throwaway HTTP server returning `body` (a string) with `status`.
// Returns { url, close }.
function serveOnce(body, status = 200) {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(body);
    });
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      resolve({
        url: `http://127.0.0.1:${port}/marketplace.json`,
        close: () => new Promise((r) => srv.close(r)),
      });
    });
  });
}

function catalog(version) {
  return JSON.stringify({
    plugins: [
      { name: "somethingelse", version: "1.2.3" },
      { name: "tokenmonitor", version },
    ],
  });
}

test("fetchLatest extracts the tokenmonitor entry version", async () => {
  const s = await serveOnce(catalog("0.9.4"));
  try {
    assert.equal(await fetchLatest(s.url), "0.9.4");
  } finally { await s.close(); }
});

test("marketplaceURL: TMON_ wins over the legacy alias", () => {
  const saved = { a: process.env.TMON_MARKETPLACE_URL, b: process.env.TOKENMONITOR_MARKETPLACE_URL };
  try {
    process.env.TMON_MARKETPLACE_URL = "https://canonical.example/c.json";
    process.env.TOKENMONITOR_MARKETPLACE_URL = "https://legacy.example/c.json";
    assert.equal(marketplaceURL(), "https://canonical.example/c.json");
    delete process.env.TMON_MARKETPLACE_URL;
    assert.equal(marketplaceURL(), "https://legacy.example/c.json");
  } finally {
    if (saved.a === undefined) delete process.env.TMON_MARKETPLACE_URL; else process.env.TMON_MARKETPLACE_URL = saved.a;
    if (saved.b === undefined) delete process.env.TOKENMONITOR_MARKETPLACE_URL; else process.env.TOKENMONITOR_MARKETPLACE_URL = saved.b;
  }
});

test("installedVersion: TMON_PLUGIN_ROOT wins over CLAUDE_PLUGIN_ROOT, then baked", () => {
  const saved = { t: process.env.TMON_PLUGIN_ROOT, c: process.env.CLAUDE_PLUGIN_ROOT };
  const mk = (v) => {
    const root = mkdtempSync(join(tmpdir(), "tmon-root-"));
    mkdirSync(join(root, ".claude-plugin"));
    writeFileSync(join(root, ".claude-plugin", "plugin.json"), JSON.stringify({ name: "tokenmonitor", version: v }));
    return root;
  };
  try {
    process.env.TMON_PLUGIN_ROOT = mk("1.2.3");
    process.env.CLAUDE_PLUGIN_ROOT = mk("4.5.6");
    assert.equal(installedVersion("0.0.0"), "1.2.3");
    delete process.env.TMON_PLUGIN_ROOT;
    assert.equal(installedVersion("0.0.0"), "4.5.6");
    delete process.env.CLAUDE_PLUGIN_ROOT;
    assert.equal(installedVersion("0.0.0"), "0.0.0");
  } finally {
    if (saved.t === undefined) delete process.env.TMON_PLUGIN_ROOT; else process.env.TMON_PLUGIN_ROOT = saved.t;
    if (saved.c === undefined) delete process.env.CLAUDE_PLUGIN_ROOT; else process.env.CLAUDE_PLUGIN_ROOT = saved.c;
  }
});

test("check marks outdated when remote > installed", async () => {
  const s = await serveOnce(catalog("0.9.4"));
  try {
    const v = await check("0.9.2", s.url);
    assert.equal(v.known, true);
    assert.equal(v.outdated, true);
    assert.equal(v.current, "0.9.2");
    assert.equal(v.latest, "0.9.4");
    assert.ok(v.checkedAt > 0);
  } finally { await s.close(); }
});

test("check is up-to-date (known, not outdated) when remote == installed", async () => {
  const s = await serveOnce(catalog("0.9.4"));
  try {
    const v = await check("0.9.4", s.url);
    assert.equal(v.known, true);
    assert.equal(v.outdated, false);
    assert.equal(v.latest, "0.9.4");
  } finally { await s.close(); }
});

test("check is not outdated when installed is NEWER than remote", async () => {
  const s = await serveOnce(catalog("0.9.2"));
  try {
    const v = await check("0.9.4", s.url);
    assert.equal(v.known, true);
    assert.equal(v.outdated, false);
  } finally { await s.close(); }
});

test("check is unknown on HTTP error (non-200)", async () => {
  const s = await serveOnce("nope", 500);
  try {
    const v = await check("0.9.2", s.url);
    assert.equal(v.known, false);
    assert.equal(v.current, "0.9.2");
    assert.equal(v.latest, "");
  } finally { await s.close(); }
});

test("check is unknown on connection failure", async () => {
  // Nothing listening on this port.
  const v = await check("0.9.2", "http://127.0.0.1:1/marketplace.json");
  assert.equal(v.known, false);
  assert.equal(v.current, "0.9.2");
});

test("check is unknown when the tokenmonitor entry is absent", async () => {
  const s = await serveOnce(JSON.stringify({ plugins: [{ name: "other", version: "1.0.0" }] }));
  try {
    const v = await check("0.9.2", s.url);
    assert.equal(v.known, false);
  } finally { await s.close(); }
});

test("check is unknown when a version is unparseable", async () => {
  const s = await serveOnce(catalog("not-a-version"));
  try {
    const v = await check("0.9.2", s.url);
    assert.equal(v.known, false);
  } finally { await s.close(); }
});

test("check is unknown on malformed JSON body", async () => {
  const s = await serveOnce("{ this is not json");
  try {
    const v = await check("0.9.2", s.url);
    assert.equal(v.known, false);
  } finally { await s.close(); }
});
