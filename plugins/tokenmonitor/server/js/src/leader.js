// TCP-bind-based single-leader election. The leader holds the HTTP
// server bound to the configured port; followers cannot bind it.
//
// IMPORTANT: there is no probe-then-listen handoff. The caller passes a
// factory that returns a fresh `http.Server` (or any `net.Server`); we
// call `listen({exclusive: true})` on it directly. On EADDRINUSE we
// report "follower"; on success the same server keeps the port for its
// whole life. Closing+relistening would allow a competing follower to
// snatch the port in between.

import { Role } from "./state.js";

export const RETRY_INTERVAL_MS = 5000;

/**
 * Try to listen on host:port using the given server factory.
 * Returns the listening server on success, null on EADDRINUSE/EACCES.
 */
export function tryListen(makeServer, host, port) {
  return new Promise((resolve) => {
    let srv;
    try { srv = makeServer(); } catch (e) { return resolve(null); }
    const onError = (e) => {
      srv.removeListener("listening", onListening);
      try { srv.close(); } catch {}
      if (e.code === "EADDRINUSE" || e.code === "EACCES") return resolve(null);
      return resolve(null);
    };
    const onListening = () => {
      srv.removeListener("error", onError);
      resolve(srv);
    };
    srv.once("error", onError);
    srv.once("listening", onListening);
    srv.listen({ host, port, exclusive: true });
  });
}

export async function run({ host, port, state, makeServer, onAcquired, abortSignal, logger }) {
  let announcedFollower = false;
  while (!abortSignal.aborted) {
    const srv = await tryListen(makeServer, host, port);
    if (!srv) {
      if (!announcedFollower) {
        logger.info(`leader: ${host}:${port} busy, running as follower (probing every ${RETRY_INTERVAL_MS / 1000}s)`);
        announcedFollower = true;
      }
      state.setRole(Role.FOLLOWER);
    } else {
      announcedFollower = false;
      state.setRole(Role.LEADER);
      logger.info(`leader: bound ${host}:${port}`);
      try { await onAcquired(srv); } finally { try { srv.close(); } catch {} }
    }
    if (abortSignal.aborted) return;
    await sleepUntil(RETRY_INTERVAL_MS, abortSignal);
  }
}

function sleepUntil(ms, signal) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
  });
}
