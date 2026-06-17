"""
HomeLink UDP Hole Puncher
==========================
Implements simultaneous-open UDP hole punching for NAT traversal.

Algorithm
---------
1. Both peers discover public endpoints via STUN.
2. Both exchange public endpoints via Telegram signaling.
3. Both send UDP packets to each other simultaneously (opens NAT pinholes).
4. Session established when echo-reply received.

Works with: Full-cone NAT, Address-restricted NAT, Port-restricted NAT.
Does NOT work with: Symmetric NAT (falls back to Telegram relay).

References: RFC 5128, RFC 8489
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

PUNCH_MAGIC  = b"HOMELINK-PUNCH-v1"
PING_MAGIC   = b"HOMELINK-PING-v1:"
PONG_MAGIC   = b"HOMELINK-PONG-v1:"
HOLE_TIMEOUT = 10.0   # seconds to attempt punching
PING_INTERVAL = 0.5   # seconds between punch packets


@dataclass
class PeerEndpoint:
    device_id: str
    public_ip: str
    public_port: int
    local_ip: str
    local_port: int


class HolePuncher:
    """
    Attempts UDP hole punching to establish direct P2P connection.
    """

    def __init__(self, local_port: int = 0):
        self._local_port = local_port
        self._sock: Optional[socket.socket] = None
        self._actual_port: int = 0

    def bind(self) -> int:
        """Bind UDP socket. Returns actual local port."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(False)
        self._sock.bind(("", self._local_port))
        self._actual_port = self._sock.getsockname()[1]
        return self._actual_port

    @property
    def local_port(self) -> int:
        return self._actual_port

    async def punch(
        self,
        peer: PeerEndpoint,
        my_device_id: str,
        timeout: float = HOLE_TIMEOUT,
    ) -> Optional[tuple[str, int]]:
        """
        Attempt hole punching to peer.
        Returns (peer_ip, peer_port) on success, None on failure.
        """
        if self._sock is None:
            raise RuntimeError("Call bind() first")

        loop = asyncio.get_event_loop()
        targets = [
            (peer.public_ip, peer.public_port),
            (peer.local_ip, peer.local_port),  # LAN fallback
        ]

        nonce = os.urandom(8).hex()
        ping = PING_MAGIC + f"{my_device_id}:{nonce}".encode()

        deadline = time.monotonic() + timeout
        log.info("Hole punching to %s at %s:%d", peer.device_id, peer.public_ip, peer.public_port)

        # Start punch task
        punch_task = asyncio.create_task(
            self._punch_loop(loop, ping, targets, deadline)
        )
        recv_task = asyncio.create_task(
            self._recv_pong(loop, nonce, deadline)
        )

        done, pending = await asyncio.wait(
            [punch_task, recv_task],
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )

        for t in pending:
            t.cancel()

        for t in done:
            result = t.result()
            if result:
                log.info("Hole punch succeeded: %s", result)
                return result

        log.info("Hole punch failed — falling back to Telegram relay")
        return None

    async def _punch_loop(
        self,
        loop: asyncio.AbstractEventLoop,
        ping: bytes,
        targets: list[tuple],
        deadline: float,
    ) -> None:
        while time.monotonic() < deadline:
            for addr in targets:
                try:
                    await loop.sock_sendto(self._sock, ping, addr)
                except Exception:
                    pass
            await asyncio.sleep(PING_INTERVAL)

    async def _recv_pong(
        self,
        loop: asyncio.AbstractEventLoop,
        nonce: str,
        deadline: float,
    ) -> Optional[tuple[str, int]]:
        while time.monotonic() < deadline:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self._sock, 256),
                    timeout=0.5,
                )
                if data.startswith(PONG_MAGIC):
                    payload = data[len(PONG_MAGIC):].decode()
                    if nonce in payload:
                        return addr
                elif data.startswith(PING_MAGIC):
                    # Respond with pong
                    payload = data[len(PING_MAGIC):]
                    pong = PONG_MAGIC + payload
                    await loop.sock_sendto(self._sock, pong, addr)
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                log.debug("Recv error: %s", e)
        return None

    def get_socket(self) -> Optional[socket.socket]:
        return self._sock

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None
