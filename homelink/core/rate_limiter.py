"""
HomeLink Rate Limiter
=====================
Token-bucket rate limiter, per-key, thread-safe.

Fixes SA-12: no rate limiting anywhere.
Applied to: exec requests, file offers, pairing requests, Telegram messages.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """
    Sliding-window token bucket rate limiter.

    Thread-safe. Per-key tracking (e.g. per device_id).
    """

    def __init__(self, max_calls: int, window_seconds: float):
        self._max    = max_calls
        self._window = window_seconds
        self._buckets: dict[str, deque] = defaultdict(deque)
        self._lock   = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        """Return True if request is within rate limit."""
        now    = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            return True

    def remaining(self, key: str) -> int:
        """Return remaining calls available in current window."""
        now    = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return max(0, self._max - len(bucket))


# Module-level shared limiters (configured via SecurityConfig)
EXEC_LIMITER   = RateLimiter(max_calls=10, window_seconds=60)
OFFER_LIMITER  = RateLimiter(max_calls=5,  window_seconds=60)
PAIR_LIMITER   = RateLimiter(max_calls=3,  window_seconds=300)
MSG_LIMITER    = RateLimiter(max_calls=60, window_seconds=60)
