// Runtime state for wall_monitor_status.

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
    this._lastRemote = "";
    this._lastStatus = 0;
    this._count = 0;
  }
  setRole(r) {
    if (this._role === r) return;
    this._role = r;
    this._roleSince = Math.floor(Date.now() / 1000);
  }
  recordRequest(remote, status, when) {
    this._lastAt = when ?? Math.floor(Date.now() / 1000);
    this._lastRemote = remote || "";
    this._lastStatus = status;
    this._count += 1;
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
    return out;
  }
}
