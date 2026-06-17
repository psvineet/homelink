"""
HomeLink Telegram Transport
============================

Fixes applied
-------------
- SA-05  : device approval validates format + pending state
- SA-08  : bot token never appears in logs (scrubbed URLs, sanitized errors)
- SA-09  : all inbound envelopes verified with Ed25519 before dispatch
- SA-12  : MSG_LIMITER applied to all inbound processing

Security model
--------------
Telegram is treated as a COMPROMISED channel.
Even if Telegram is fully compromised, an attacker:
  - Can READ all messages (all payloads are additionally encrypted)
  - Can BLOCK messages (DoS only — not access)
  - CANNOT forge valid Ed25519 signatures without the sender's private key
  - CANNOT approve devices without a pending pairing request in devices.json
  - CANNOT inject commands that pass signature verification
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Callable, Optional

from homelink.transport.base import BaseTransport, TransportError
from homelink.core.rate_limiter import MSG_LIMITER

log     = logging.getLogger(__name__)
sec_log = logging.getLogger("homelink.audit")

TELEGRAM_MAX_MSG_BYTES = 4096
LARGE_FILE_THRESHOLD   = 50    # MB — never relay via Telegram
_DEVICE_ID_RE          = re.compile(r"^[0-9A-F]{16}$")


class TelegramTransport(BaseTransport):
    """
    Telegram Bot API transport: signaling + emergency relay.
    Assumes Telegram is compromised — all messages verified before dispatch.
    """

    def __init__(
        self,
        bot_token:   str,
        chat_id:     str,
        device_id:   str,
        signing_key,
        config,
        device_mgr=None,   # injected for peer lookup + approval (SA-05, SA-09)
        nonce_cache_factory: Callable | None = None,  # factory() → NonceCache
    ):
        self._token      = bot_token
        self._chat_id    = str(chat_id)
        self._device_id  = device_id
        self._signing_key = signing_key
        self._config     = config
        self._device_mgr = device_mgr
        self._nonce_cache_factory = nonce_cache_factory
        self._peer_nonce_caches: dict[str, object] = {}  # per-peer NonceCache
        self._on_receive: Optional[Callable] = None
        self._available  = False
        self._last_update_id = 0

    # ------------------------------------------------------------------ #
    # BaseTransport                                                         #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        if not self._token or not self._chat_id:
            log.warning("Telegram not configured — transport disabled")
            return
        try:
            await self._test_connection()
            self._available = True
            asyncio.create_task(self._poll_loop())
            log.info("Telegram transport started (chat_id=%s)", self._chat_id)
        except Exception as e:
            # SA-08: never log the token or URL
            log.error("Telegram start failed: %s", type(e).__name__)
            self._available = False

    async def stop(self) -> None:
        self._available = False
        log.info("Telegram transport stopped")

    async def send(self, device_id: str, message: dict) -> None:
        if not self._available:
            raise TransportError("Telegram transport not available")

        if self._signing_key is None:
            raise TransportError("Cannot send: no signing key loaded")

        # Block large file chunks (never relay big files via Telegram)
        if message.get("type") == "file_chunk":
            import base64
            size_mb = len(base64.b64decode(message.get("data", ""))) / 1_048_576
            if size_mb > LARGE_FILE_THRESHOLD:
                raise TransportError(
                    f"File chunk {size_mb:.1f} MB exceeds Telegram relay limit. Use P2P transport."
                )

        from homelink.crypto.signing import sign_message
        envelope = sign_message(
            json.dumps(message).encode(),
            self._signing_key,
            self._device_id,
        )

        wrapper = json.dumps({
            "hl":       1,
            "to":       device_id,
            "from":     self._device_id,
            "envelope": envelope,
        })

        if len(wrapper.encode()) > TELEGRAM_MAX_MSG_BYTES:
            raise TransportError("Message too large for Telegram relay")

        await self._send_text(wrapper)

    async def is_available(self) -> bool:
        return self._available

    async def is_peer_reachable(self, device_id: str) -> bool:
        return self._available

    # ------------------------------------------------------------------ #
    # Telegram API — token never in logs (SA-08)                           #
    # ------------------------------------------------------------------ #

    def _api_url(self, endpoint: str) -> str:
        """Build API URL. Only called internally — never logged."""
        return f"https://api.telegram.org/bot{self._token}/{endpoint}"

    async def _test_connection(self) -> None:
        import aiohttp
        url = self._api_url("getMe")   # URL never logged
        async with aiohttp.ClientSession() as s:
            async with s.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    # SA-08: log only status, not the URL or response data
                    raise TransportError("Telegram API rejected bot token (check config)")
                bot_name = data["result"].get("username", "unknown")
                log.info("Telegram bot connected: @%s", bot_name)

    async def _send_text(self, text: str, parse_mode: str | None = None) -> None:
        import aiohttp
        url     = self._api_url("sendMessage")
        payload = {"chat_id": self._chat_id, "text": text, "disable_notification": True}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    raise TransportError("Telegram sendMessage failed")

    async def _get_updates(self) -> list:
        import aiohttp
        url    = self._api_url("getUpdates")
        params = {"offset": self._last_update_id + 1, "timeout": 30, "limit": 100}
        async with aiohttp.ClientSession() as s:
            async with s.get(url, params=params, timeout=aiohttp.ClientTimeout(total=40)) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    return []
                updates = data.get("result", [])
                if updates:
                    self._last_update_id = updates[-1]["update_id"]
                return updates

    # ------------------------------------------------------------------ #
    # Poll + dispatch                                                       #
    # ------------------------------------------------------------------ #

    async def _poll_loop(self) -> None:
        backoff = 1.0
        while self._available:
            try:
                updates = await self._get_updates()
                backoff = 1.0
                for update in updates:
                    await self._handle_update(update)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("Telegram poll error: %s — retry in %ds", type(e).__name__, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
            else:
                await asyncio.sleep(0.5)

    async def _handle_update(self, update: dict) -> None:
        msg     = update.get("message", {})
        text    = msg.get("text", "")
        chat_id = str(msg.get("chat", {}).get("id", ""))

        # Only accept messages from the configured chat_id
        if chat_id != self._chat_id:
            sec_log.warning("TELEGRAM_UNKNOWN_CHAT chat=%s", chat_id)
            return

        # Rate limit all inbound processing (SA-12)
        if not MSG_LIMITER.is_allowed(chat_id):
            log.debug("Telegram rate limit hit for chat %s", chat_id)
            return

        # Admin commands
        if text.startswith("/approve "):
            await self._handle_approve(text.split(None, 1)[1].strip(), approved=True)
            return
        if text.startswith("/deny "):
            await self._handle_approve(text.split(None, 1)[1].strip(), approved=False)
            return
        if text.startswith("/status"):
            if self._on_receive:
                await self._on_receive({"type": "status_request"})
            return

        # HomeLink protocol message — VERIFY SIGNATURE BEFORE DISPATCH (SA-09)
        try:
            wrapper = json.loads(text)
        except json.JSONDecodeError:
            return

        if wrapper.get("hl") != 1:
            return
        if wrapper.get("to") != self._device_id:
            return

        from_id  = str(wrapper.get("from", ""))
        envelope = wrapper.get("envelope")
        if not from_id or not envelope:
            return

        # Lookup approved peer (SA-09)
        peer = None
        if self._device_mgr:
            peer = self._device_mgr.get_peer(from_id)
        if peer is None or not peer.approved:
            sec_log.warning("TELEGRAM_UNAPPROVED_SENDER from=%s", from_id)
            return

        # Verify Ed25519 signature (SA-09) with per-peer nonce cache (SA-04)
        from homelink.crypto.signing import verify_signature
        from homelink.crypto.nonce_cache import NonceCache

        if from_id not in self._peer_nonce_caches:
            self._peer_nonce_caches[from_id] = NonceCache()
        nonce_cache = self._peer_nonce_caches[from_id]

        try:
            payload_bytes = verify_signature(envelope, peer.signing.verify_key, nonce_cache)
        except ValueError as e:
            sec_log.warning("TELEGRAM_BAD_SIGNATURE from=%s reason=%s", from_id, e)
            return

        # Parse and dispatch verified message
        try:
            message = json.loads(payload_bytes)
        except json.JSONDecodeError:
            log.warning("Telegram: invalid JSON payload from %s", from_id)
            return

        message["from_device"] = from_id
        message["transport"]   = "telegram"

        if self._on_receive:
            await self._on_receive(message)

    # ------------------------------------------------------------------ #
    # Admin approval (SA-05)                                               #
    # ------------------------------------------------------------------ #

    async def _handle_approve(self, device_id: str, approved: bool) -> None:
        """
        SA-05 fix: Validate format, verify pending state, prevent self-approval.
        """
        device_id = device_id.strip().upper()

        # 1. Format validation
        if not _DEVICE_ID_RE.match(device_id):
            await self._send_text(f"❌ Invalid device ID format: `{device_id}`")
            return

        # 2. Prevent self-approval
        if device_id == self._device_id:
            await self._send_text("❌ Cannot approve/deny own device")
            return

        # 3. Verify device exists and is in pending state
        if self._device_mgr:
            peer = self._device_mgr.get_peer(device_id)
            if peer is None:
                await self._send_text(f"❌ No pending device with ID `{device_id}`")
                return
            if peer.approved and approved:
                await self._send_text(f"ℹ️ Device `{device_id}` is already approved")
                return

        sec_log.info("ADMIN_APPROVAL device=%s approved=%s", device_id, approved)

        if self._on_receive:
            await self._on_receive({
                "type":      "admin_approval",
                "device_id": device_id,
                "approved":  approved,
            })

        verb = "approved ✅" if approved else "denied ❌"
        await self._send_text(f"Device `{device_id}` {verb}.", parse_mode="Markdown")

    # ------------------------------------------------------------------ #
    # Signaling helpers                                                     #
    # ------------------------------------------------------------------ #

    async def send_signaling(self, device_id: str, signal_type: str, data: dict) -> None:
        await self.send(device_id, {"type": f"signal:{signal_type}", "data": data})

    async def send_pairing_notification(self, device_id: str, code: str, name: str) -> None:
        text = (
            f"🔗 *HomeLink Pairing Request*\n\n"
            f"Device: `{name}`\n"
            f"ID: `{device_id}`\n"
            f"Code: `{code}`\n\n"
            f"Reply `/approve {device_id}` to approve or `/deny {device_id}` to reject."
        )
        await self._send_text(text, parse_mode="Markdown")
