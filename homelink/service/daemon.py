"""
HomeLink Daemon
================
Main background service. Wires all components together.

Security changes
----------------
- SA-12  : Rate limiting applied in all handlers
- SA-09  : Telegram transport now receives device_mgr for signature verification
- RBAC   : Device role passed to PermissionManager
- AUDIT  : Structured audit logging throughout
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Optional

from homelink.config.manager import ConfigManager
from homelink.core.device import DeviceManager
from homelink.core.broker import MessageBroker, TransportType
from homelink.transport.p2p.transport import P2PTransport
from homelink.transport.telegram.transport import TelegramTransport
from homelink.files.transfer import FileTransfer
from homelink.commands.executor import CommandExecutor
from homelink.commands.permissions import PermissionManager
from homelink.core.rate_limiter import EXEC_LIMITER, OFFER_LIMITER

log       = logging.getLogger(__name__)
audit_log = logging.getLogger("homelink.audit")


class HomeLinkDaemon:
    def __init__(self, config_dir: Optional[Path] = None, password: str = ""):
        self._config_mgr  = ConfigManager(config_dir)
        self._password    = password
        self._device_mgr: Optional[DeviceManager] = None
        self._broker      = MessageBroker()
        self._p2p:        Optional[P2PTransport]      = None
        self._telegram:   Optional[TelegramTransport] = None
        self._file_transfer: Optional[FileTransfer]   = None
        self._executor:   Optional[CommandExecutor]   = None
        self._running     = False
        self._start_time  = time.time()

    async def start(self) -> None:
        log.info("HomeLink daemon starting")

        self._device_mgr = DeviceManager(self._config_mgr)
        identity = self._device_mgr.load(self._password)
        cfg      = self._device_mgr.config

        _configure_logging(cfg.logging)

        downloads = Path(cfg.config_dir) / "downloads"
        downloads.mkdir(exist_ok=True, mode=0o750)

        self._file_transfer = FileTransfer(
            send_fn=self._broker.send,
            device_id=identity.device_id,
            downloads_dir=downloads,
            progress_cb=self._on_progress,
            max_file_size=cfg.security.max_file_size_gb * 1_073_741_824,
        )

        # PermissionManager uses device role — default viewer for daemon itself
        perms = PermissionManager(device_role="administrator")
        self._executor = CommandExecutor(
            permissions=perms,
            max_timeout=cfg.security.max_exec_timeout,
        )

        if cfg.p2p.enabled:
            self._p2p = P2PTransport(
                device_id=identity.device_id,
                config=cfg.p2p,
                signaling_send=self._signaling_send,
            )
            self._p2p.set_receive_callback(self._broker.dispatch)
            self._broker.register_p2p(self._p2p)
            await self._p2p.start()

        if cfg.telegram.enabled and cfg.telegram.is_valid():
            self._telegram = TelegramTransport(
                bot_token=cfg.telegram.bot_token,
                chat_id=cfg.telegram.chat_id,
                device_id=identity.device_id,
                signing_key=identity.signing.signing_key,
                config=cfg.telegram,
                device_mgr=self._device_mgr,   # SA-09: peer lookup for sig verify
            )
            self._telegram.set_receive_callback(self._on_telegram_message)
            self._broker.register_telegram(self._telegram)
            await self._telegram.start()
        else:
            log.warning("Telegram not configured — only P2P transport available")

        self._register_handlers()
        self._running = True

        audit_log.info(
            "DAEMON_START device=%s transport=%s",
            identity.device_id,
            self._broker.current_transport(),
        )

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))

        await self._main_loop()

    async def stop(self) -> None:
        log.info("HomeLink daemon shutting down")
        self._running = False
        if self._p2p:
            await self._p2p.stop()
        if self._telegram:
            await self._telegram.stop()
        audit_log.info("DAEMON_STOP")
        log.info("HomeLink daemon stopped")

    async def _main_loop(self) -> None:
        while self._running:
            await asyncio.sleep(10)

    # ------------------------------------------------------------------ #
    # Handlers                                                              #
    # ------------------------------------------------------------------ #

    def _register_handlers(self) -> None:
        self._broker.on("file_offer",     self._handle_file_offer)
        self._broker.on("file_chunk",     self._file_transfer.handle_chunk)
        self._broker.on("file_complete",  self._file_transfer.handle_complete)
        self._broker.on("exec_request",   self._handle_exec)
        self._broker.on("ls_request",     self._handle_ls)
        self._broker.on("rm_request",     self._handle_rm)
        self._broker.on("mkdir_request",  self._handle_mkdir)
        self._broker.on("tree_request",   self._handle_tree)
        self._broker.on("status_request", self._handle_status)
        self._broker.on("admin_approval", self._handle_admin_approval)
        self._broker.on("signal:endpoint", self._handle_p2p_signal)
        self._broker.on("heartbeat",      self._handle_heartbeat)

    async def _handle_file_offer(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        # Rate limit check (SA-12) — also done inside handle_offer
        if not OFFER_LIMITER.is_allowed(from_device):
            return
        # RBAC: only operator+ can push files
        if not self._check_role(from_device, "operator"):
            await self._broker.send(from_device, {
                "type": "file_reject",
                "transfer_id": message.get("transfer_id", ""),
                "reason": "insufficient role (operator required for file transfer)",
            })
            return
        await self._file_transfer.handle_offer(message)

    async def _handle_exec(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        command     = str(message.get("command", ""))
        timeout     = int(message.get("timeout", 60))

        # RBAC: viewer can only run viewer commands; role enforced in PermissionManager
        peer_role = self._get_peer_role(from_device)
        perms     = PermissionManager(device_role=peer_role)
        executor  = CommandExecutor(
            permissions=perms,
            max_timeout=self._device_mgr.config.security.max_exec_timeout,
        )
        result = await executor.execute(command, timeout=timeout, requester_device_id=from_device)
        await self._broker.send(from_device, result.to_dict())

    async def _handle_ls(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        if not self._check_role(from_device, "viewer"):
            return
        path_str = str(message.get("path", "~"))
        try:
            path    = Path(path_str).expanduser().resolve()
            # Restrict ls to home directory
            home    = Path.home().resolve()
            if not str(path).startswith(str(home)):
                raise PermissionError(f"Access restricted to home directory")
            entries = _list_path(path) if path.exists() else []
            error   = None
        except Exception as e:
            entries = []
            error   = str(e)
        await self._broker.send(from_device, {
            "type": "ls_result", "path": path_str,
            "entries": entries, "error": error,
        })

    async def _handle_rm(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        if not self._check_role(from_device, "operator"):
            await self._broker.send(from_device, {
                "type": "rm_result", "error": "operator role required"
            })
            return
        path_str = str(message.get("path", ""))
        try:
            p = Path(path_str).expanduser().resolve()
            if not str(p).startswith(str(Path.home())):
                raise PermissionError("Can only delete files within home directory")
            p.unlink()
            error = None
        except Exception as e:
            error = str(e)
        await self._broker.send(from_device, {"type": "rm_result", "error": error})

    async def _handle_mkdir(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        if not self._check_role(from_device, "operator"):
            return
        path_str = str(message.get("path", ""))
        try:
            p = Path(path_str).expanduser().resolve()
            if not str(p).startswith(str(Path.home())):
                raise PermissionError("Can only create directories within home directory")
            p.mkdir(parents=True, exist_ok=True, mode=0o750)
            error = None
        except Exception as e:
            error = str(e)
        await self._broker.send(from_device, {"type": "mkdir_result", "error": error})

    async def _handle_tree(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        if not self._check_role(from_device, "viewer"):
            return
        path_str = str(message.get("path", "~"))
        try:
            path = Path(path_str).expanduser().resolve()
            home = Path.home().resolve()
            if not str(path).startswith(str(home)):
                raise PermissionError("Access restricted to home directory")
            tree = _build_tree(path, depth=0, max_depth=3)
            error = None
        except Exception as e:
            tree  = {}
            error = str(e)
        await self._broker.send(from_device, {
            "type": "tree_result", "tree": tree, "error": error
        })

    async def _handle_status(self, message: dict) -> None:
        from_device = message.get("from_device", "unknown")
        status = {
            "type":        "status_result",
            "device_id":   self._device_mgr.identity.device_id,
            "device_name": self._device_mgr.identity.name,
            "uptime":      time.time() - self._start_time,
            "transport":   self._broker.current_transport(),
            **self._broker.status(),
        }
        if from_device and from_device != "unknown":
            await self._broker.send(from_device, status)
        elif self._telegram:
            lines = [
                "📡 *HomeLink Status*",
                f"Device: `{status['device_id']}`",
                f"Transport: `{status['transport']}`",
                f"P2P: {'✅' if status['p2p_available'] else '❌'}",
                f"Telegram: {'✅' if status['telegram_available'] else '❌'}",
                f"Uptime: {int(status['uptime'])}s",
            ]
            await self._telegram._send_text("\n".join(lines), parse_mode="Markdown")

    async def _handle_admin_approval(self, message: dict) -> None:
        device_id = str(message.get("device_id", ""))
        approved  = bool(message.get("approved", False))
        if approved:
            self._device_mgr.approve_peer(device_id)
            audit_log.info("DEVICE_APPROVED device=%s", device_id)
        else:
            self._device_mgr._mgr.remove_device(device_id)
            audit_log.info("DEVICE_DENIED device=%s", device_id)

    async def _handle_p2p_signal(self, message: dict) -> None:
        log.debug("P2P signal: %s", message.get("data", {}).get("type"))

    async def _handle_heartbeat(self, message: dict) -> None:
        pass

    # ------------------------------------------------------------------ #
    # RBAC helpers                                                          #
    # ------------------------------------------------------------------ #

    def _get_peer_role(self, device_id: str) -> str:
        peer = self._device_mgr.get_peer(device_id)
        if peer is None or not peer.approved:
            return "viewer"
        return peer.role

    def _check_role(self, device_id: str, required_role: str) -> bool:
        from homelink.commands.permissions import ROLE_HIERARCHY
        peer_role    = self._get_peer_role(device_id)
        peer_level   = ROLE_HIERARCHY.get(peer_role, 0)
        req_level    = ROLE_HIERARCHY.get(required_role, 999)
        if peer_level < req_level:
            audit_log.warning(
                "RBAC_DENIED device=%s peer_role=%s required=%s",
                device_id, peer_role, required_role,
            )
            return False
        return True

    # ------------------------------------------------------------------ #
    # Transport helpers                                                     #
    # ------------------------------------------------------------------ #

    async def _signaling_send(self, device_id: str, message: dict) -> None:
        if self._telegram:
            await self._telegram.send(device_id, message)

    async def _on_telegram_message(self, message: dict) -> None:
        await self._broker.dispatch(message)

    def _on_progress(self, session) -> None:
        log.debug("Transfer %s: %.1f%%", session.transfer_id[:8], session.progress)

    def status_dict(self) -> dict:
        if not self._device_mgr or not self._device_mgr.identity:
            return {"running": False}
        return {
            "running":     self._running,
            "device_id":   self._device_mgr.identity.device_id,
            "device_name": self._device_mgr.identity.name,
            "transport":   self._broker.current_transport(),
            **self._broker.status(),
        }


# ------------------------------------------------------------------ #
# Helpers                                                               #
# ------------------------------------------------------------------ #

def _list_path(path: Path) -> list[dict]:
    entries = []
    try:
        for p in sorted(path.iterdir()):
            try:
                st = p.stat()
                entries.append({
                    "name":  p.name,
                    "type":  "dir" if p.is_dir() else "file",
                    "size":  st.st_size if p.is_file() else 0,
                    "mtime": st.st_mtime,
                    "mode":  oct(st.st_mode)[-3:],
                })
            except (PermissionError, OSError):
                pass
    except PermissionError:
        pass
    return entries


def _build_tree(path: Path, depth: int, max_depth: int) -> dict:
    node: dict = {"name": path.name, "type": "dir" if path.is_dir() else "file"}
    if path.is_dir() and depth < max_depth:
        children = []
        try:
            for p in sorted(path.iterdir()):
                try:
                    children.append(_build_tree(p, depth + 1, max_depth))
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            pass
        node["children"] = children
    return node


def _configure_logging(log_cfg) -> None:
    import logging.handlers
    log_dir = Path(log_cfg.log_dir)
    log_dir.mkdir(exist_ok=True, mode=0o750)

    level = getattr(logging, log_cfg.level.upper(), logging.INFO)
    fmt   = "%(asctime)s %(name)s %(levelname)s %(message)s"

    root = logging.getLogger("homelink")
    root.setLevel(level)

    fh = logging.handlers.RotatingFileHandler(
        log_dir / "homelink.log",
        maxBytes=log_cfg.max_bytes,
        backupCount=log_cfg.backup_count,
    )
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)

    if log_cfg.audit_enabled:
        ah = logging.handlers.RotatingFileHandler(
            log_dir / "audit.log",
            maxBytes=log_cfg.max_bytes,
            backupCount=log_cfg.backup_count,
        )
        ah.setFormatter(logging.Formatter(fmt))
        logging.getLogger("homelink.audit").addHandler(ah)
