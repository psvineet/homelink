"""
HomeLink Message Broker
========================
Routes messages between the active transport and handler modules.
Manages transport selection and fallback.

Transport priority
------------------
1. P2P direct (UDP hole-punched)
2. Telegram (signaling + fallback transport)

Switching is transparent — callers use send/receive; broker picks transport.
"""

from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum, auto
from typing import Callable, Optional

log = logging.getLogger(__name__)


class TransportType(Enum):
    P2P = auto()
    TELEGRAM = auto()
    NONE = auto()


class MessageBroker:
    """
    Central message router.

    Maintains reference to active transport, handles fallback,
    dispatches inbound messages to registered handlers.
    """

    def __init__(self):
        self._p2p_transport = None
        self._telegram_transport = None
        self._active: TransportType = TransportType.NONE
        self._handlers: dict[str, list[Callable]] = {}
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._last_p2p_check: float = 0
        self._p2p_check_interval: float = 60.0  # re-check P2P every minute

    # ------------------------------------------------------------------ #
    # Transport registration                                                #
    # ------------------------------------------------------------------ #

    def register_p2p(self, transport) -> None:
        self._p2p_transport = transport
        log.info("P2P transport registered")

    def register_telegram(self, transport) -> None:
        self._telegram_transport = transport
        log.info("Telegram transport registered")

    # ------------------------------------------------------------------ #
    # Handler registration                                                  #
    # ------------------------------------------------------------------ #

    def on(self, message_type: str, handler: Callable) -> None:
        """Register handler for a message type."""
        self._handlers.setdefault(message_type, []).append(handler)

    async def dispatch(self, message: dict) -> None:
        """Dispatch inbound message to all registered handlers."""
        msg_type = message.get("type", "unknown")
        handlers = self._handlers.get(msg_type, [])
        if not handlers:
            log.warning("No handler for message type: %s", msg_type)
            return
        for handler in handlers:
            try:
                await handler(message)
            except Exception as e:
                log.error("Handler error (%s): %s", msg_type, e)

    # ------------------------------------------------------------------ #
    # Sending                                                               #
    # ------------------------------------------------------------------ #

    async def send(self, device_id: str, message: dict) -> bool:
        """
        Send message to device. Tries P2P first, falls back to Telegram.
        Returns True on success.
        """
        transport = await self._select_transport(device_id, message)
        if transport is None:
            log.error("No available transport for %s", device_id)
            return False

        try:
            await transport.send(device_id, message)
            return True
        except Exception as e:
            log.warning("Send failed via %s: %s — trying fallback", self._active.name, e)
            return await self._fallback_send(device_id, message)

    async def _select_transport(self, device_id: str, message: dict):
        """Choose best available transport."""
        # Periodically re-check P2P availability
        now = time.time()
        if now - self._last_p2p_check > self._p2p_check_interval:
            await self._check_p2p()

        if self._active == TransportType.P2P and self._p2p_transport:
            if await self._p2p_transport.is_peer_reachable(device_id):
                return self._p2p_transport

        if self._telegram_transport and self._telegram_transport.is_available():
            self._active = TransportType.TELEGRAM
            return self._telegram_transport

        return None

    async def _fallback_send(self, device_id: str, message: dict) -> bool:
        """Attempt Telegram as fallback."""
        if self._telegram_transport and self._telegram_transport.is_available():
            self._active = TransportType.TELEGRAM
            log.info("Fell back to Telegram transport")
            try:
                await self._telegram_transport.send(device_id, message)
                return True
            except Exception as e:
                log.error("Telegram fallback also failed: %s", e)
        return False

    async def _check_p2p(self) -> None:
        """Re-evaluate P2P availability."""
        self._last_p2p_check = time.time()
        if self._p2p_transport and await self._p2p_transport.is_available():
            if self._active != TransportType.P2P:
                log.info("P2P transport became available — switching")
            self._active = TransportType.P2P
        else:
            if self._active == TransportType.P2P:
                log.info("P2P transport unavailable — staying on Telegram")

    # ------------------------------------------------------------------ #
    # Status                                                                #
    # ------------------------------------------------------------------ #

    def current_transport(self) -> str:
        return self._active.name

    def status(self) -> dict:
        return {
            "active_transport": self._active.name,
            "p2p_available": (
                self._p2p_transport is not None
                and getattr(self._p2p_transport, "_connected", False)
            ),
            "telegram_available": (
                self._telegram_transport is not None
                and self._telegram_transport.is_available()
            ),
        }
