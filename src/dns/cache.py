from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


class DNSCache:
    """Caching layer for DNS resolutions using local memory cache with TTL."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[list[str], float]] = {}
        logger.info("[DNSCache] Local memory DNS cache initialized.")

    async def get(self, domain: str) -> list[str] | None:
        """Retrieve cached IP addresses list for a domain. Return None on cache miss/expiration."""
        if domain in self._cache:
            ips, expire_time = self._cache[domain]
            if time.time() < expire_time:
                return ips
            else:
                del self._cache[domain]
        return None

    async def set(self, domain: str, ips: list[str], ttl: int = 300) -> None:
        """Store resolved IP addresses in local memory cache with a specified TTL."""
        self._cache[domain] = (ips, time.time() + ttl)