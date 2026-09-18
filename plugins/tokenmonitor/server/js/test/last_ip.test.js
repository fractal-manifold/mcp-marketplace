// active.last_ip: the source address a device was last seen from.
//
// It exists for one job — publish_firmware has to hand out the one of THIS
// host's addresses that is on the device's network. A laptop on WiFi and
// Ethernet at once has several, and picking blind does not merely produce an
// unreachable firmware_url: tmon_ota.c treats a foreign origin as reason to
// withhold the HMAC headers, so the download 401s as well.
//
// Mirrors Go's TestTouch_RecordsLastIPAndSurvivesRebuilds /
// TestPickLocalIP_PrefersTheDevicesSubnet and py test_last_ip.py.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { Registry, remoteIPv4, _testing } from "../src/registry/store.js";
import { pickLocalIP } from "../src/mcp/server.js";

const DEVID = "ab12cd34";
const PSK_HEX = "aa".repeat(32);

function newReg() {
  const dir = mkdtempSync(join(tmpdir(), "tmon-lastip-"));
  const reg = new Registry(dir);
  reg.register(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
  return { dir, reg };
}

test("remoteIPv4 accepts the shapes a peer arrives in", () => {
  assert.equal(remoteIPv4("192.168.1.55"), "192.168.1.55");
  assert.equal(remoteIPv4("192.168.1.55:41234"), "192.168.1.55");
  // A dual-stack listener reports IPv4 peers in mapped form.
  assert.equal(remoteIPv4("::ffff:192.168.1.55"), "192.168.1.55");
  for (const bad of ["", "[fe80::1]:5000", "fe80::1", "not-an-address", "999.1.1.1"]) {
    assert.equal(remoteIPv4(bad), "", bad);
  }
  // Loopback is this host talking to itself, not a device on the LAN.
  for (const lo of ["127.0.0.1", "127.0.0.1:8765", "::ffff:127.0.0.1"]) {
    assert.equal(remoteIPv4(lo), "", lo);
  }
});

test("touch records last_ip and it survives promote and re-provision", () => {
  const { dir, reg } = newReg();
  try {
    reg.touch(DEVID, "192.168.2.44");
    assert.equal(reg.load(DEVID).active.lastIP, "192.168.2.44");

    // A peer we cannot use as an IPv4 literal must not erase what we know: one
    // request over IPv6 should not cost the OTA its hint.
    for (const bad of ["", "[fe80::1]:5000", "garbage"]) {
      reg.touch(DEVID, bad);
      assert.equal(reg.load(DEVID).active.lastIP, "192.168.2.44", bad);
    }

    // On disk, and back off it again.
    assert.match(readFileSync(join(dir, `${DEVID}.toml`), "utf8"), /last_ip = "192\.168\.2\.44"/);
    assert.equal(new Registry(dir).load(DEVID).active.lastIP, "192.168.2.44");

    reg.setPending(DEVID, { ..._testing.emptyPayload(), city: "Madrid" });
    reg.maybePromote(DEVID, 2, false);
    assert.equal(reg.load(DEVID).active.lastIP, "192.168.2.44", "promote lost it");

    reg.replaceActive(DEVID, { ..._testing.emptyPayload(), broker_url: "http://x", psk_hex: PSK_HEX });
    assert.equal(reg.load(DEVID).active.lastIP, "192.168.2.44", "re-provision lost it");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pickLocalIP prefers the device's subnet", () => {
  const nets = [
    { address: "10.0.0.5", cidr: "10.0.0.5/24" },      // Ethernet, listed first
    { address: "192.168.2.7", cidr: "192.168.2.7/24" }, // WiFi, where the device is
  ];
  assert.equal(pickLocalIP(nets, "192.168.2.44"), "192.168.2.7");
  assert.equal(pickLocalIP(nets, "10.0.0.99"), "10.0.0.5");
  for (const unknown of ["172.16.4.4", "", "garbage", "fe80::1"]) {
    assert.equal(pickLocalIP(nets, unknown), "10.0.0.5", unknown);
  }
});

test("pickLocalIP honours the mask, not the octets", () => {
  const nets = [
    { address: "192.168.1.5", cidr: "192.168.1.5/24" },
    { address: "192.168.0.9", cidr: "192.168.0.9/16" },
  ];
  assert.equal(pickLocalIP(nets, "192.168.99.3"), "192.168.0.9");
});

test("pickLocalIP tolerates an interface with no usable CIDR", () => {
  const nets = [{ address: "10.0.0.5", cidr: "" }, { address: "192.168.2.7", cidr: "192.168.2.7/24" }];
  assert.equal(pickLocalIP(nets, "192.168.2.44"), "192.168.2.7");
  assert.equal(pickLocalIP(nets, "172.16.0.1"), "10.0.0.5");
});

// The address the device DIALLED identifies the origin its OTA download will
// authenticate against: the firmware compares a firmware_url's origin with its
// NVS svc_url by exact strcmp and drops the HMAC headers on any mismatch, so
// /firmware/ 401s. Like last_ip it has to survive a promote and a re-provision.
// Mirror of Go TestTouch_RecordsTheAddressTheDeviceDialled and py
// test_touch_records_the_address_the_device_dialled.
test("touch records the address the device dialled and it survives rebuilds", () => {
  const { dir, reg } = newReg();
  try {
    reg.touch(DEVID, "192.168.2.44", "192.168.2.28:8765");
    assert.equal(reg.load(DEVID).active.lastLocalAddr, "192.168.2.28:8765");

    // A dual-stack listener reports its own address in mapped form; it must
    // normalise to the same bytes a broker bound to 0.0.0.0 records, because
    // the device's comparison is a string compare.
    reg.touch(DEVID, "192.168.2.44", "[::ffff:192.168.2.28]:8765");
    assert.equal(reg.load(DEVID).active.lastLocalAddr, "192.168.2.28:8765");

    // Nothing usable may erase it. Loopback is deliberately in this list: it is
    // a real local address when broker and device share a host, but never what
    // a device on the LAN dialled, and recording it would hand out a
    // firmware_url pointing at the device itself.
    for (const bad of ["", "no-port", "[fe80::1]:8765", "127.0.0.1:8765",
                       "0.0.0.0:8765", "192.168.2.28"]) {
      reg.touch(DEVID, "192.168.2.44", bad);
      assert.equal(reg.load(DEVID).active.lastLocalAddr, "192.168.2.28:8765", bad);
    }

    reg.setPending(DEVID, { ..._testing.emptyPayload(), city: "Madrid" });
    reg.maybePromote(DEVID, 2, false);
    assert.equal(reg.load(DEVID).active.lastLocalAddr, "192.168.2.28:8765");

    reg.replaceActive(DEVID, { ..._testing.emptyPayload(), broker_url: "u", psk_hex: "aa".repeat(32) });
    assert.equal(reg.load(DEVID).active.lastLocalAddr, "192.168.2.28:8765");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The floor mirror follows the device in BOTH directions. It used to be a
// high-water mark, on the reasoning that a spoofed-high value could only lock a
// device out of downgrades. That stopped being true once the broker began
// refusing to stage a manifest whose floor sits below the device's: a mirror
// stuck high now blocks legitimate updates too — the exact shape a USB re-flash
// with an NVS wipe leaves behind.
test("recordMinSV follows the device in both directions", () => {
  const { dir, reg } = newReg();
  try {
    reg.recordMinSV(DEVID, 16777216); // packed(1.0.0)
    assert.equal(reg.load(DEVID).active.payload.min_secure_version, 16777216);
    reg.recordMinSV(DEVID, 720900); // came back on 0.11.4, NVS wiped
    assert.equal(reg.load(DEVID).active.payload.min_secure_version, 720900);
    reg.recordMinSV(DEVID, 16777217); // and up again after the update
    assert.equal(reg.load(DEVID).active.payload.min_secure_version, 16777217);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
