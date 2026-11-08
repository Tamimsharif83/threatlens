"""Login rate limiting.

Failed logins are counted per client IP and per username in a sliding window.
When either counter reaches the limit, further attempts are refused until old
failures age out. In-memory on purpose: ThreatLens is a single process, and a
restart clearing the counters is acceptable.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class LoginThrottle:
    def __init__(self, max_failures: int, window_seconds: float) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _keys(ip: str | None, username: str) -> tuple[str, str]:
        return f"ip:{ip or '?'}", f"user:{username.casefold()}"

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            del self._failures[key]
            return deque()
        return q

    def retry_after(self, ip: str | None, username: str) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        now = time.monotonic()
        with self._lock:
            wait = 0.0
            for key in self._keys(ip, username):
                q = self._prune(key, now)
                if len(q) >= self.max_failures:
                    wait = max(wait, q[0] + self.window - now)
            return int(wait) + 1 if wait > 0 else 0

    def failure(self, ip: str | None, username: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in self._keys(ip, username):
                self._failures[key].append(now)

    def success(self, ip: str | None, username: str) -> None:
        """Clear the username counter only. The IP counter keeps aging out on its
        own, so logging into one's own account cannot reset an IP's guess budget."""
        with self._lock:
            self._failures.pop(self._keys(ip, username)[1], None)
