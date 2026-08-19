// Runtime state for tokenmonitor_status.

import { RUNTIME } from "./version.js";

export const Role = Object.freeze({ UNKNOWN: "unknown", LEADER: "leader", FOLLOWER: "follower" });

function rfc3339(epochS) {
  if (!epochS) return "";
  const d = new Date(epochS * 1000);
  // Match Go's time.RFC3339Z formatting.
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export class State {
  constructor() {
    this._role = Role.UNKNOWN;
    this._roleSince = Math.floor(Date.now() / 1000);
    this._lastAt = 0;
    // Millisecond twin of _lastAt, kept because the mDNS idle watchdog
    // compares against a 30 s threshold on a 30 s tick: truncating to whole
    // seconds can move the crossing a whole tick earlier, not a second. Go
    // keeps a time.Time and Python a float, so this is what makes the three
    // runtimes decide alike. Stays 0 until the first request — the publisher
    // relies on falsy-zero to fall back to its own start time.
    this._lastAtMs = 0;
    this._lastRemote = "";
    this._lastStatus = 0;
    this._count = 0;
    // Cached broker self-version-check verdict. `known` stays false until the
    // first successful marketplace fetch; while unknown the broker advertises
    // nothing (never a false "up to date" or "outdated"). Mirrors Go
    // state.UpdateInfo.
    this._update = { known: false, outdated: false, current: "", latest: "", checkedAt: 0 };
  }
  setRole(r) {
    if (this._role === r) return;
    this._role = r;
    this._roleSince = Math.floor(Date.now() / 1000);
  }
  recordRequest(remote, status, when) {
    // One clock read: two fields sampled from different nows could place
    // _lastAtMs before _lastAt across a second boundary.
    const nowMs = Date.now();
    this._lastAt = when ?? Math.floor(nowMs / 1000);
    this._lastAtMs = when != null ? when * 1000 : nowMs;
    this._lastRemote = remote || "";
    this._lastStatus = status;
    this._count += 1;
  }
  // lastRequestAt reports when a device last hit the broker, as epoch
  // milliseconds (0 if never). The mDNS publisher reads it to decide whether
  // its advertisement has gone unheard and should be re-announced.
  lastRequestAt() {
    return this._lastAtMs;
  }
  // setUpdate records the latest broker self-version-check result. The
  // update-check poller pokes this; the broker /sync handler and the MCP
  // health/status tools read it back via update(). Mirrors Go State.SetUpdate.
  setUpdate(u) {
    this._update = {
      known: !!(u && u.known),
      outdated: !!(u && u.outdated),
      current: (u && u.current) || "",
      latest: (u && u.latest) || "",
      checkedAt: (u && u.checkedAt) || 0,
    };
  }
  // update returns the last cached self-version-check result (default =
  // known:false, i.e. no check has succeeded yet). Mirrors Go State.Update.
  update() {
    return this._update;
  }
  snapshot() {
    const out = {
      runtime: RUNTIME,
      role: this._role,
      role_since: rfc3339(this._roleSince),
      requests_total: this._count,
    };
    if (this._lastAt) out.last_request_at = rfc3339(this._lastAt);
    if (this._lastRemote) out.last_request_remote = this._lastRemote;
    if (this._lastStatus) out.last_request_status = this._lastStatus;
    // Surface the update verdict only once known, so callers distinguish
    // "up to date" from "not yet checked". Mirrors Go Snapshot's
    // *bool omitempty + latest_version,omitempty.
    if (this._update.known) {
      out.update_available = this._update.outdated;
      if (this._update.latest) out.latest_version = this._update.latest;
    }
    return out;
  }
}
