"""Replay protection.

Signed one-time messages (client assertions, DPoP proofs) carry a unique
``jti``.  If an attacker captures one and sends it again, we will have already
seen that jti and reject it.  Entries only need to be kept until the message
would have expired anyway, so memory stays bounded.

This in-memory version is fine for a single process.  With several replicas
you would back it with a shared store such as Redis (SET key NX EX ttl).
"""

from __future__ import annotations

import threading
import time


class ReplayCache:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_store(self, jti: str, expires_at: float) -> bool:
        """Return True the first time a jti is seen, False on any replay."""
        now = time.time()
        with self._lock:
            self._purge(now)
            if jti in self._seen:
                return False
            self._seen[jti] = expires_at
            return True

    def _purge(self, now: float) -> None:
        expired = [k for k, exp in self._seen.items() if exp < now]
        for k in expired:
            del self._seen[k]
