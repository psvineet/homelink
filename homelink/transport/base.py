"""
HomeLink Transport Base
========================
Abstract interface all transports must implement.
"""

from __future__ import annotations
import abc
from typing import Callable, Optional


class TransportError(Exception):
    """Raised by transports on unrecoverable send/receive errors."""


class BaseTransport(abc.ABC):
    """Abstract transport interface."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Start the transport (connect, bind, etc.)."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Graceful shutdown."""

    @abc.abstractmethod
    async def send(self, device_id: str, message: dict) -> None:
        """Send message dict to device."""

    @abc.abstractmethod
    async def is_available(self) -> bool:
        """True if transport can currently send/receive."""

    @abc.abstractmethod
    async def is_peer_reachable(self, device_id: str) -> bool:
        """True if a specific peer is reachable via this transport."""

    def set_receive_callback(self, callback: Callable) -> None:
        """Register callback(message: dict) for inbound messages."""
        self._on_receive = callback
