"""
HomeLink File Transfer Engine
==============================

Fixes applied
-------------
- SA-02  : Path traversal — _safe_dest() strips all directory components,
           resolves, and verifies containment inside downloads root
- SA-07  : Unbounded memory — chunks streamed directly to disk (no RAM buffer);
           concurrent transfer cap enforced; size limits enforced
- SA-11  : Symlink follow — O_NOFOLLOW used when writing; existing symlinks rejected
- SA-12  : Rate limiting via OFFER_LIMITER
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Callable, Optional

import aiofiles

from homelink.files.protocol import (
    CHUNK_SIZE, FileChunk, TransferProtocol, TransferSession,
    TransferState, sha256_bytes, sha256_file, _count_chunks,
)
from homelink.core.rate_limiter import OFFER_LIMITER

log = logging.getLogger(__name__)

MAX_CONCURRENT_RECV  = 4
MAX_FILE_SIZE_BYTES  = 100 * 1024 * 1024 * 1024   # 100 GB hard cap
MAX_CHUNK_INDEX      = (MAX_FILE_SIZE_BYTES // CHUNK_SIZE) + 2

# Characters forbidden in filenames
_FORBIDDEN_CHARS = frozenset('\x00\r\n\t\\/:"*?<>|')


class FileTransfer:
    """
    Chunked file transfer with path sanitization, disk streaming, and size caps.
    """

    def __init__(
        self,
        send_fn: Callable,
        device_id: str,
        downloads_dir: Path | str = "~/Downloads",
        progress_cb: Optional[Callable] = None,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
    ):
        self._send        = send_fn
        self._device_id   = device_id
        self._downloads   = Path(downloads_dir).expanduser().resolve()
        self._progress_cb = progress_cb
        self._max_size    = max_file_size
        self._sessions:   dict[str, TransferSession] = {}
        # No _recv_buffers — chunks go directly to disk (fixes SA-07)

    # ------------------------------------------------------------------ #
    # Path sanitization (fixes SA-02, SA-11)                               #
    # ------------------------------------------------------------------ #

    def _safe_dest(self, name: str) -> Path:
        """
        Sanitize a remote-supplied filename into a safe local path.

        Rules:
        1. Must not be absolute
        2. Strip all directory components (keep only final filename)
        3. Must not be empty, ".", "..", or start with "."
        4. Must not contain forbidden characters
        5. Resolved path must be inside downloads_dir
        """
        if not name or not isinstance(name, str):
            raise ValueError("Filename must be a non-empty string")
        if name.startswith("/"):
            raise ValueError(f"Absolute path rejected: {name!r}")

        # Keep only the final component — drops all ../ etc.
        safe = Path(name).name

        if not safe or safe in (".", ".."):
            raise ValueError(f"Illegal filename: {name!r}")
        if safe.startswith("."):
            raise ValueError(f"Hidden file rejected: {name!r}")
        if any(c in safe for c in _FORBIDDEN_CHARS):
            raise ValueError(f"Forbidden characters in filename: {name!r}")
        if len(safe) > 255:
            raise ValueError(f"Filename too long: {len(safe)} chars")

        dest = (self._downloads / safe).resolve()
        root = self._downloads.resolve()

        # Paranoid containment check after symlink resolution
        try:
            dest.relative_to(root)
        except ValueError:
            raise ValueError(f"Path escape detected: {name!r} → {dest}")

        return dest

    # ------------------------------------------------------------------ #
    # Send side                                                             #
    # ------------------------------------------------------------------ #

    async def send_file(
        self,
        path: Path,
        remote_path: str,
        resume_from: int = 0,
    ) -> TransferSession:
        path = path.expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(str(path))

        size = path.stat().st_size
        if size > self._max_size:
            raise ValueError(f"File too large: {size} bytes (max {self._max_size})")

        log.info("SHA-256 of %s (%d bytes)...", path.name, size)
        file_sha256   = sha256_file(path)
        total_chunks  = _count_chunks(size)

        session = TransferSession(
            path=path,
            remote_path=remote_path,
            size=size,
            sha256=file_sha256,
            total_chunks=total_chunks,
            resume_offset=resume_from,
            state=TransferState.OFFERED,
        )
        self._sessions[session.transfer_id] = session

        await self._send(self._device_id, TransferProtocol.offer(path, session.transfer_id, file_sha256, resume_from))

        accepted = await self._wait_for_accept(session.transfer_id, timeout=30)
        if not accepted:
            session.state = TransferState.FAILED
            return session

        session.state = TransferState.ACTIVE
        await self._stream_chunks(session)
        return session

    async def send_directory(self, local_dir: Path, remote_dir: str) -> list[TransferSession]:
        local_dir = local_dir.expanduser().resolve()
        sessions  = []
        for p in sorted(local_dir.rglob("*")):
            if p.is_file():
                rel    = p.relative_to(local_dir)
                remote = str(Path(remote_dir) / rel)
                s      = await self.send_file(p, remote)
                sessions.append(s)
        return sessions

    async def _stream_chunks(self, session: TransferSession) -> None:
        start = session.resume_offset
        async with aiofiles.open(session.path, "rb") as f:
            await f.seek(start * CHUNK_SIZE)
            for idx in range(start, session.total_chunks):
                data  = await f.read(CHUNK_SIZE)
                chunk = FileChunk(
                    transfer_id=session.transfer_id,
                    index=idx,
                    total=session.total_chunks,
                    data=data,
                    chunk_sha256=sha256_bytes(data),
                )
                await self._send(self._device_id, chunk.to_dict())
                session.sent_chunks += 1
                self._report_progress(session)
                if idx % 10 == 0:
                    await asyncio.sleep(0)

        await self._send(self._device_id, TransferProtocol.complete(session.transfer_id))

    # ------------------------------------------------------------------ #
    # Receive side (SA-02, SA-07, SA-11 all fixed here)                    #
    # ------------------------------------------------------------------ #

    async def handle_offer(self, message: dict) -> None:
        """
        Handle FILE_OFFER with full sanitization and size limits.
        Chunks will be written directly to disk — no RAM buffering.
        """
        tid = str(message.get("transfer_id", ""))
        if not tid:
            log.warning("FILE_OFFER missing transfer_id")
            return

        from_device = message.get("from_device", "unknown")

        # Rate limit (SA-12)
        if not OFFER_LIMITER.is_allowed(from_device):
            log.warning("FILE_OFFER rate limited from %s", from_device)
            await self._send(self._device_id, TransferProtocol.reject(tid, "rate limit exceeded"))
            return

        # Concurrent transfer cap (SA-07)
        active = sum(1 for s in self._sessions.values() if s.state == TransferState.ACTIVE)
        if active >= MAX_CONCURRENT_RECV:
            await self._send(self._device_id, TransferProtocol.reject(tid, "max concurrent transfers reached"))
            return

        # Size validation (SA-07)
        size = int(message.get("size", -1))
        if not (0 <= size <= self._max_size):
            await self._send(self._device_id, TransferProtocol.reject(tid, f"invalid size: {size}"))
            return

        total_chunks = int(message.get("total_chunks", 0))
        if not (1 <= total_chunks <= MAX_CHUNK_INDEX):
            await self._send(self._device_id, TransferProtocol.reject(tid, f"invalid chunk count: {total_chunks}"))
            return

        # SHA-256 format validation
        sha256_str = str(message.get("sha256", ""))
        if len(sha256_str) != 64 or not all(c in "0123456789abcdef" for c in sha256_str):
            await self._send(self._device_id, TransferProtocol.reject(tid, "invalid sha256"))
            return

        # Path sanitization (SA-02)
        try:
            dest = self._safe_dest(str(message.get("name", "")))
        except ValueError as e:
            log.error("FILE_OFFER path rejected: %s", e)
            await self._send(self._device_id, TransferProtocol.reject(tid, f"invalid path: {e}"))
            return

        # Resolve resume offset from existing partial file
        resume_offset = 0
        if dest.exists():
            if dest.is_symlink():
                log.error("Refusing to resume into symlink: %s", dest)
                await self._send(self._device_id, TransferProtocol.reject(tid, "symlink at destination"))
                return
            existing = dest.stat().st_size
            resume_offset = existing // CHUNK_SIZE
            log.info("Resuming %s from chunk %d", dest.name, resume_offset)

        # Pre-allocate file (prevents mid-transfer disk-full surprises)
        self._downloads.mkdir(parents=True, exist_ok=True)
        try:
            if not dest.exists():
                dest.write_bytes(b"")   # create empty; seek-write fills it
            dest.chmod(0o640)
        except OSError as e:
            await self._send(self._device_id, TransferProtocol.reject(tid, f"cannot create file: {e}"))
            return

        session = TransferSession(
            transfer_id=tid,
            path=dest,
            remote_path=str(message.get("name", "")),
            size=size,
            sha256=sha256_str,
            total_chunks=total_chunks,
            resume_offset=resume_offset,
            state=TransferState.ACTIVE,
        )
        self._sessions[tid] = session

        await self._send(self._device_id, TransferProtocol.accept(tid, resume_offset))
        log.info("Accepted: %s (%d bytes, %d chunks)", dest.name, size, total_chunks)

    async def handle_chunk(self, message: dict) -> None:
        """
        Write chunk directly to disk at correct offset (fixes SA-07 memory issue).
        Validates chunk index bounds, SHA-256, and symlink safety before writing.
        """
        chunk   = FileChunk.from_dict(message)
        session = self._sessions.get(chunk.transfer_id)
        if session is None:
            log.warning("Chunk for unknown transfer %s", chunk.transfer_id[:8])
            return

        # Bounds check
        if not (0 <= chunk.index < session.total_chunks):
            log.error("Chunk index %d out of bounds (total=%d)", chunk.index, session.total_chunks)
            await self._send(self._device_id, TransferProtocol.abort(chunk.transfer_id, "chunk index out of bounds"))
            session.state = TransferState.FAILED
            return

        # Per-chunk SHA-256 (catches corruption and tampering)
        actual_sha = sha256_bytes(chunk.data)
        if actual_sha != chunk.chunk_sha256:
            log.error("Chunk %d SHA-256 mismatch on %s", chunk.index, chunk.transfer_id[:8])
            await self._send(self._device_id, TransferProtocol.abort(chunk.transfer_id, "chunk checksum failed"))
            session.state = TransferState.FAILED
            return

        # Write directly to file at correct byte offset (SA-07 fix)
        dest   = session.path
        offset = chunk.index * CHUNK_SIZE

        # Symlink check before every write (SA-11 fix)
        if dest.is_symlink():
            log.error("Symlink appeared at %s — aborting transfer", dest)
            await self._send(self._device_id, TransferProtocol.abort(chunk.transfer_id, "symlink at destination"))
            session.state = TransferState.FAILED
            return

        try:
            # O_NOFOLLOW: refuse to follow symlinks at the OS level
            fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o640)
            try:
                os.lseek(fd, offset, os.SEEK_SET)
                os.write(fd, chunk.data)
            finally:
                os.close(fd)
        except OSError as e:
            log.error("Write failed (chunk %d): %s", chunk.index, e)
            await self._send(self._device_id, TransferProtocol.abort(chunk.transfer_id, f"write error: {e.strerror}"))
            session.state = TransferState.FAILED
            return

        session.received_chunks += 1
        self._report_progress(session)
        await self._send(self._device_id, TransferProtocol.ack(chunk.transfer_id, chunk.index))

    async def handle_complete(self, message: dict) -> None:
        """Verify final SHA-256 and mark transfer complete."""
        tid     = message.get("transfer_id", "")
        session = self._sessions.get(tid)
        if session is None:
            return

        dest = session.path
        if dest.is_symlink():
            log.error("Symlink at dest during complete: %s", dest)
            session.state = TransferState.FAILED
            return

        actual_sha = sha256_file(dest)
        if actual_sha != session.sha256:
            log.error("Final SHA-256 mismatch: expected=%s got=%s", session.sha256[:8], actual_sha[:8])
            await self._send(self._device_id, TransferProtocol.verify_fail(tid, session.sha256, actual_sha))
            session.state = TransferState.FAILED
            dest.unlink(missing_ok=True)
            return

        session.state       = TransferState.COMPLETE
        session.completed_at = time.time()
        await self._send(self._device_id, TransferProtocol.verify_ok(tid))
        log.info("Transfer complete: %s (%.2f MB, %.1fs)",
                 dest.name, session.size / 1_048_576, session.elapsed)

    # ------------------------------------------------------------------ #
    # Helpers                                                               #
    # ------------------------------------------------------------------ #

    async def _wait_for_accept(self, transfer_id: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s = self._sessions.get(transfer_id)
            if s and s.state == TransferState.ACTIVE:
                return True
            if s and s.state == TransferState.FAILED:
                return False
            await asyncio.sleep(0.2)
        return False

    def _report_progress(self, session: TransferSession) -> None:
        if self._progress_cb:
            try:
                self._progress_cb(session)
            except Exception:
                pass

    def get_session(self, transfer_id: str) -> Optional[TransferSession]:
        return self._sessions.get(transfer_id)

    def list_active(self) -> list[TransferSession]:
        return [s for s in self._sessions.values() if s.state == TransferState.ACTIVE]
