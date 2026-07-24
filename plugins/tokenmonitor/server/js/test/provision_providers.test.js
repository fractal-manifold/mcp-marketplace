// Regression guard for the 3->2 re-configure provider bug (parity with the Go
// internal/mcp/provision_providers_test.go and py test_provision_providers.py).
//
// When a provision names ANY provider, the broker must forward the WHOLE triple
// so an unchecked provider reaches the device as an explicit `false`. Forwarding
// only the named providers left the device's NVS for the omitted provider
// untouched (the firmware only overwrites keys present in the payload), so a
// device dropped from 3 to 2 providers kept the third enabled.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import { provisionTool } from "../src/mcp/server.js";

// Run provisionTool against a throwaway /provision endpoint and resolve with
// the JSON body the broker POSTed to the device.
async function capture(args) {
  const srv = createServer((req, res) => {
    let buf = "";
    req.on("data", (c) => { buf += c; });
    req.on("end", () => {
      srv._body = JSON.parse(buf || "{}");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true,"next":"rebooting"}');
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;

  const full = {
    device_id: "ab12cd34",
    provision_url: `http://127.0.0.1:${port}/provision`,
    pairing_code: "071718",
    // Explicit psk_hex keeps provisionTool off the registry-reuse path so a
    // null registry is fine — we only care about the wire body here.
    broker_url: "http://10.0.0.5:8787",
    psk_hex: "0".repeat(64),
    ...args,
  };
  const deps = { cfg: {}, state: {}, logs: null, registry: null, version: "test" };
  await provisionTool(deps, full);
  await new Promise((r) => srv.close(r));
  return srv._body;
}

test("provision drops an unchecked provider (3->2)", async () => {
  // provider_antigravity omitted (user unchecked it) -> must arrive as false.
  const body = await capture({ provider_claude: true, provider_codex: true });
  assert.deepEqual(body.providers, { claude: true, codex: true, gemini: false });
});

test("provision honours the legacy gemini alias and disables the rest", async () => {
  const body = await capture({ provider_gemini: true });
  assert.deepEqual(body.providers, { claude: false, codex: false, gemini: true });
});

test("provision prefers provider_antigravity over the deprecated gemini alias", async () => {
  // Both present: the new arg wins, provider_gemini is ignored.
  const body = await capture({ provider_antigravity: false, provider_gemini: true });
  assert.deepEqual(body.providers, { claude: false, codex: false, gemini: false });
});

test("provision with no provider keys omits the providers field", async () => {
  const body = await capture({ city: "Madrid" });
  assert.equal("providers" in body, false);
});
