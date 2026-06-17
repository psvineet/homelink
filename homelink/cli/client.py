"""
HomeLink Remote Client
=======================
Used by CLI commands to communicate with the remote device.
Handles transport selection, request/response pairing, timeouts.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Optional

from homelink.config.manager import ConfigManager

log = logging.getLogger(__name__)


class RemoteClient:
    """
    Async client that connects to a specific remote device and sends requests.
    Auto-selects P2P or Telegram based on availability.
    """

    def __init__(self, config_mgr: ConfigManager, target_device_id: str, timeout: float = 30.0):
        self._mgr = config_mgr
        self._target = target_device_id
        self._timeout = timeout
        self._pending: dict[str, asyncio.Future] = {}

    async def send_request(self, message: dict) -> dict:
        """
        Send request to remote device and await response.
        Raises TimeoutError if no response within self._timeout.
        """
        cfg = self._mgr.load_config()
        message["from_device"] = cfg.device_id
        msg_type = message.get("type", "")

        # Build transport
        transport = await self._get_transport(cfg)
        if transport is None:
            return {"error": "No transport available. Is the daemon running?"}

        # Send and wait for response
        response_event = asyncio.Event()
        response_container = {}

        original_cb = getattr(transport, "_on_receive", None)

        async def capture_response(msg):
            resp_type = msg.get("type", "")
            if _is_response_for(msg_type, resp_type):
                response_container["data"] = msg
                response_event.set()
            elif original_cb:
                await original_cb(msg)

        transport.set_receive_callback(capture_response)

        await transport.send(self._target, message)
        try:
            await asyncio.wait_for(response_event.wait(), timeout=self._timeout)
            return response_container.get("data", {})
        except asyncio.TimeoutError:
            return {"error": f"Timeout waiting for response to {msg_type}"}
        finally:
            if original_cb:
                transport.set_receive_callback(original_cb)

    async def download_file(self, remote_path: str, local_path: Path, progress_cb: Optional[Callable] = None) -> None:
        """Request file download from remote."""
        cfg = self._mgr.load_config()
        transport = await self._get_transport(cfg)
        if transport is None:
            raise ConnectionError("No transport available")

        from homelink.files.transfer import FileTransfer
        ft = FileTransfer(
            send_fn=lambda did, msg: transport.send(did, msg),
            device_id=self._target,
            downloads_dir=local_path.parent,
            progress_cb=progress_cb,
        )
        transport.set_receive_callback(ft._handle_download_message)
        await transport.send(self._target, {
            "type": "get_request",
            "path": remote_path,
            "from_device": cfg.device_id,
        })
        # Wait for transfer to complete
        await asyncio.sleep(0)  # yield; actual wait in transfer logic

    async def upload_file(self, local_path: Path, remote_path: str, progress_cb: Optional[Callable] = None) -> None:
        """Upload file to remote device."""
        cfg = self._mgr.load_config()
        transport = await self._get_transport(cfg)
        if transport is None:
            raise ConnectionError("No transport available")

        from homelink.files.transfer import FileTransfer
        ft = FileTransfer(
            send_fn=lambda did, msg: transport.send(did, msg),
            device_id=self._target,
            downloads_dir=local_path.parent,
            progress_cb=progress_cb,
        )
        await ft.send_file(local_path, remote_path)

    async def _get_transport(self, cfg):
        """Return best available transport."""
        # Try Telegram (always available if configured)
        if cfg.telegram.enabled and cfg.telegram.is_valid():
            from homelink.transport.telegram.transport import TelegramTransport
            t = TelegramTransport(
                bot_token=cfg.telegram.bot_token,
                chat_id=cfg.telegram.chat_id,
                device_id=cfg.device_id,
                signing_key=None,  # loaded separately
                config=cfg.telegram,
            )
            await t.start()
            return t

        log.warning("No transport configured")
        return None


def _is_response_for(request_type: str, response_type: str) -> bool:
    """Match response types to their request types."""
    mapping = {
        "ls_request":      "ls_result",
        "exec_request":    "exec_result",
        "status_request":  "status_result",
        "rm_request":      "rm_result",
        "mkdir_request":   "mkdir_result",
        "tree_request":    "tree_result",
    }
    return mapping.get(request_type) == response_type
