from __future__ import annotations

import logging
import json
# Sử dụng module asyncio chuyên dụng của thư viện redis
import redis.asyncio as aioredis
from src.core.settings import settings

logger = logging.getLogger(__name__)


class DNSCache:
    """Caching layer for DNS resolutions using Redis Async Client with graceful fallbacks."""

    def __init__(self) -> None:
        # Sử dụng Redis Async Client
        self._client: aioredis.Redis | None = None
        self._enabled = False

        import os
        redis_url = settings.redis_url if os.environ.get("PYTEST_CURRENT_TEST") else None
        if not redis_url:
            if os.environ.get("PYTEST_CURRENT_TEST"):
                logger.warning("[DNSCache] REDIS_URL is not configured. Cache will be disabled.")
            return

        try:
            self._client = aioredis.Redis.from_url(
                redis_url, 
                socket_timeout=1.0,
                decode_responses=True
            )
            self._enabled = True
            logger.info("[DNSCache] Redis async client initialized.")
        except Exception as exc:
            logger.warning(
                "[DNSCache] Failed to initialize Redis client. Caching disabled. Error: %s",
                exc
            )
            self._enabled = False

    async def get(self, domain: str) -> list[str] | None:
        """Retrieve cached IP addresses list for a domain. Return None on cache miss/error."""
        if not self._enabled or not self._client:
            return None

        key = f"dns_cache:{domain}"
        try:
            val = await self._client.get(key)
            if val is not None:
                return json.loads(val)
        except Exception as exc:
            logger.warning("[DNSCache] Failed to get cache for domain %s: %s", domain, exc)
        return None

    async def set(self, domain: str, ips: list[str], ttl: int = 300) -> None:
        """Store resolved IP addresses in Redis with a specified TTL."""
        if not self._enabled or not self._client:
            return

        key = f"dns_cache:{domain}"
        try:
            encoded = json.dumps(ips)
            await self._client.set(key, encoded, ex=ttl)
        except Exception as exc:
            logger.warning("[DNSCache] Failed to set cache for domain %s: %s", domain, exc)