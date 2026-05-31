"""TCP-bind-based single-leader election.

The kernel guarantees exactly one bind to the same (bind, port). The
loser sleeps and retries. We disable SO_REUSEADDR explicitly so a
follower can't take the port from a still-bound leader.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
from typing import Awaitable, Callable

from .state import Role, State

log = logging.getLogger("cwm_mcp.leader")
RETRY_INTERVAL = 5.0  # seconds


def try_bind(host: str, port: int) -> socket.socket | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Explicit: do NOT set SO_REUSEADDR. Same behaviour as Go's net.Listen.
    try:
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
        return sock
    except OSError as e:
        sock.close()
        if e.errno in (errno.EADDRINUSE, errno.EACCES):
            return None
        raise


async def run(
    host: str,
    port: int,
    state: State,
    on_acquired: Callable[[socket.socket], Awaitable[None]],
    stop_event: asyncio.Event,
) -> None:
    announced_follower = False
    while not stop_event.is_set():
        sock = try_bind(host, port)
        if sock is None:
            if not announced_follower:
                log.info("leader: %s:%d busy, running as follower (probing every %.0fs)", host, port, RETRY_INTERVAL)
                announced_follower = True
            state.set_role(Role.FOLLOWER)
        else:
            announced_follower = False
            state.set_role(Role.LEADER)
            log.info("leader: bound %s:%d", host, port)
            try:
                await on_acquired(sock)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=RETRY_INTERVAL)
        except asyncio.TimeoutError:
            pass
