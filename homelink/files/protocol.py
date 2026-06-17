"""
HomeLink File Transfer Protocol
=================================
Chunked, resumable, SHA-256-verified file transfer.

Packet types
------------
FILE_OFFER      : sender announces file (name, size, sha256, transfer_id)
FILE_ACCEPT     : receiver accepts; optionally sets resume_offset
FILE_REJECT     : receiver rejects (reason included)
FILE_CHUNK      : chunk of file data (index, data, sha256_of_chunk)
FILE_ACK        : receiver acknowledges chunk (index)
FILE_COMPLETE   : sender signals all chunks sent
FILE_VERIFY_OK  : receiver confirms final SHA-256 match
FILE_VERIFY_FAIL: receiver reports final SHA-256 mismatch → resend
FILE_ABORT      : either side aborts transfer

Chunk size: 256 KB (tuneable)
Max file size: unlimited (tested to >5 GB)
Resume: receiver sends resume_offset in FILE_ACCEPT; sender skips chunks below offset
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

CHUNK_SIZE = 256 * 1024   # 256 KB


class TransferState(Enum):
    PENDING   = auto()
    OFFERED   = auto()
    ACTIVE    = auto()
    PAUSED    = auto()
    COMPLETE  = auto()
    FAILED    = auto()
    ABORTED   = auto()


@dataclass
class FileChunk:
    transfer_id: str
    index: int          # zero-based chunk index
    total: int          # total number of chunks
    data: bytes
    chunk_sha256: str   # SHA-256 of this chunk's data

    def to_dict(self) -> dict:
        import base64
        return {
            "type": "file_chunk",
            "transfer_id": self.transfer_id,
            "index": self.index,
            "total": self.total,
            "data": base64.b64encode(self.data).decode(),
            "chunk_sha256": self.chunk_sha256,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileChunk":
        import base64
        data = base64.b64decode(d["data"])
        return cls(
            transfer_id=d["transfer_id"],
            index=d["index"],
            total=d["total"],
            data=data,
            chunk_sha256=d["chunk_sha256"],
        )


@dataclass
class TransferSession:
    """Tracks state of one file transfer."""
    transfer_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: TransferState = TransferState.PENDING
    path: Optional[Path] = None
    remote_path: str = ""
    size: int = 0
    sha256: str = ""
    total_chunks: int = 0
    sent_chunks: int = 0
    received_chunks: int = 0
    acked_chunks: set = field(default_factory=set)
    resume_offset: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error: Optional[str] = None

    @property
    def progress(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        n = max(self.sent_chunks, self.received_chunks)
        return min(100.0, n / self.total_chunks * 100)

    @property
    def elapsed(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def throughput_mbps(self) -> float:
        if self.elapsed < 0.001:
            return 0.0
        transferred = max(self.sent_chunks, self.received_chunks) * CHUNK_SIZE
        return transferred / self.elapsed / 1_048_576


class TransferProtocol:
    """Build and parse transfer protocol messages."""

    @staticmethod
    def offer(path: Path, transfer_id: str, sha256: str, resume_from: int = 0) -> dict:
        stat = path.stat()
        total_chunks = _count_chunks(stat.st_size)
        return {
            "type": "file_offer",
            "transfer_id": transfer_id,
            "name": path.name,
            "size": stat.st_size,
            "sha256": sha256,
            "total_chunks": total_chunks,
            "chunk_size": CHUNK_SIZE,
            "resume_from": resume_from,
        }

    @staticmethod
    def accept(transfer_id: str, resume_offset: int = 0) -> dict:
        return {
            "type": "file_accept",
            "transfer_id": transfer_id,
            "resume_offset": resume_offset,
        }

    @staticmethod
    def reject(transfer_id: str, reason: str) -> dict:
        return {
            "type": "file_reject",
            "transfer_id": transfer_id,
            "reason": reason,
        }

    @staticmethod
    def ack(transfer_id: str, index: int) -> dict:
        return {
            "type": "file_ack",
            "transfer_id": transfer_id,
            "index": index,
        }

    @staticmethod
    def complete(transfer_id: str) -> dict:
        return {"type": "file_complete", "transfer_id": transfer_id}

    @staticmethod
    def verify_ok(transfer_id: str) -> dict:
        return {"type": "file_verify_ok", "transfer_id": transfer_id}

    @staticmethod
    def verify_fail(transfer_id: str, expected: str, got: str) -> dict:
        return {
            "type": "file_verify_fail",
            "transfer_id": transfer_id,
            "expected": expected,
            "got": got,
        }

    @staticmethod
    def abort(transfer_id: str, reason: str) -> dict:
        return {
            "type": "file_abort",
            "transfer_id": transfer_id,
            "reason": reason,
        }


def sha256_file(path: Path) -> str:
    """Stream SHA-256 of file. Handles files > 5 GB."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(1 << 20)  # 1 MB at a time
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _count_chunks(size: int) -> int:
    return max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
