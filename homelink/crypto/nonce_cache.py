"""
HomeLink Nonce Cache
====================
Thread-safe, TTL-bounded, per-session nonce deduplication.

Fixes SA-04 and SA-17:
- Replaces global set with per-instance OrderedDict (FIFO eviction)
- TTL-bounded: nonces expire after window closes (default 120s)
- Thread-safe via lock
- No global shared state
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict


class NonceCache:
    """
    Thread-safe nonce deduplication cache with TTL-based eviction.

    Eviction is FIFO (oldest first) — deterministic, unlike set().
    Nonces are automatically expired after ttl_seconds.
    """

    def __init__(self, max_size: int = 10_000, ttl_seconds: float = 120.0):
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_size
        self._ttl = ttl_seconds

    def check_and_add(self, nonce: str) -> None:
        """
        Record nonce as seen. Raises ValueError on replay.

        Thread-safe. FIFO eviction of expired entries first,
        then capacity eviction if still full.
        """
        now = time.monotonic()
        cutoff = now - self._ttl

        with self._lock:
            # Replay check
            if nonce in self._cache:
                raise ValueError(f"Replay detected: nonce already seen")

            # Evict expired (FIFO — OrderedDict preserves insertion order)
            while self._cache:
                oldest_nonce, oldest_ts = next(iter(self._cache.items()))
                if oldest_ts >= cutoff:
                    break
                self._cache.popitem(last=False)

            # Capacity evict (drop oldest if still full)
            while len(self._cache) >= self._max:
                self._cache.popitem(last=False)

            self._cache[nonce] = now

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)
