"""
HomeLink STUN Client
====================
Discovers public IP + port using STUN (RFC 5389).
Used to share reachability info via Telegram signaling channel.

No paid infrastructure required — uses Google/Cloudflare free STUN servers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# STUN message type constants
BINDING_REQUEST  = 0x0001
BINDING_RESPONSE = 0x0101
MAGIC_COOKIE     = 0x2112A442

DEFAULT_STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


@dataclass
class PublicEndpoint:
    ip: str
    port: int
    nat_type: str = "unknown"   # "full_cone" | "symmetric" | "unknown"

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


class STUNClient:
    """Minimal STUN client — discovers public UDP endpoint."""

    def __init__(self, stun_servers: list[tuple] | None = None):
        self._servers = stun_servers or DEFAULT_STUN_SERVERS

    async def get_public_endpoint(
        self,
        local_port: int = 0,
        timeout: float = 5.0,
    ) -> Optional[PublicEndpoint]:
        """
        Try each STUN server in order. Return first successful PublicEndpoint.
        Returns None if all servers fail (no internet / strict firewall).
        """
        for host, port in self._servers:
            try:
                ep = await asyncio.wait_for(
                    self._query_stun(host, port, local_port),
                    timeout=timeout,
                )
                if ep:
                    log.debug("STUN: public endpoint %s via %s:%d", ep, host, port)
                    return ep
            except asyncio.TimeoutError:
                log.debug("STUN timeout: %s:%d", host, port)
            except Exception as e:
                log.debug("STUN error (%s:%d): %s", host, port, e)
        log.warning("STUN: all servers failed — P2P may not work")
        return None

    async def _query_stun(
        self, host: str, port: int, local_port: int
    ) -> Optional[PublicEndpoint]:
        loop = asyncio.get_event_loop()

        # Build STUN Binding Request
        transaction_id = os.urandom(12)
        msg = struct.pack(
            ">HHI12s",
            BINDING_REQUEST,
            0,             # message length (no attributes)
            MAGIC_COOKIE,
            transaction_id,
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if local_port:
            sock.bind(("", local_port))
        else:
            sock.bind(("", 0))

        actual_local_port = sock.getsockname()[1]

        server_addr = (socket.gethostbyname(host), port)
        await loop.sock_sendto(sock, msg, server_addr)

        data, _ = await loop.sock_recvfrom(sock, 1024)
        sock.close()

        return self._parse_response(data, transaction_id)

    def _parse_response(self, data: bytes, transaction_id: bytes) -> Optional[PublicEndpoint]:
        if len(data) < 20:
            return None

        msg_type, msg_len, magic, txn = struct.unpack(">HHI12s", data[:20])
        if msg_type != BINDING_RESPONSE:
            return None
        if txn != transaction_id:
            log.warning("STUN transaction ID mismatch")
            return None

        # Parse attributes
        offset = 20
        while offset < len(data):
            if offset + 4 > len(data):
                break
            attr_type, attr_len = struct.unpack(">HH", data[offset:offset+4])
            offset += 4
            attr_val = data[offset:offset+attr_len]
            offset += attr_len
            # Pad to 4-byte boundary
            offset += (4 - attr_len % 4) % 4

            # XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            if attr_type in (0x0020, 0x0001):
                family = attr_val[1]
                if family != 0x01:  # only IPv4
                    continue
                raw_port, raw_ip = struct.unpack(">H4s", attr_val[2:8])
                if attr_type == 0x0020:
                    # XOR with magic cookie
                    port = raw_port ^ (MAGIC_COOKIE >> 16)
                    ip_int = struct.unpack(">I", raw_ip)[0] ^ MAGIC_COOKIE
                    ip = socket.inet_ntoa(struct.pack(">I", ip_int))
                else:
                    port = raw_port
                    ip = socket.inet_ntoa(raw_ip)
                return PublicEndpoint(ip=ip, port=port)

        return None
