import json
import logging
import time
import asyncio
from typing import Optional, Any, Dict, Tuple
import redis.asyncio as aioredis

from src.core.settings import settings
from src.core.models import AnalysisContext

logger = logging.getLogger(__name__)

class BaseCache:
    """Abstract Base Class defining the Async Cache Interface."""

    async def get(self, key: str) -> Optional[AnalysisContext]:
        raise NotImplementedError

    async def set(self, key: str, context: AnalysisContext, ttl: int = 86400) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class RedisCache(BaseCache):
    """Redis-backed Cache Implementation with async support."""

    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url
        self._client: Optional[aioredis.Redis] = None

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            logger.info(f"Initializing Redis Cache connection: {self.redis_url}")
            self._client = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._client

    async def get(self, key: str) -> Optional[AnalysisContext]:
        try:
            cached_data = await self.client.get(key)
            if not cached_data:
                return None
            
            logger.info(f"Cache HIT for key: {key} (Redis)")
            raw_dict = json.loads(cached_data)
            return AnalysisContext.model_validate(raw_dict)
        except Exception as e:
            logger.error(f"Redis get cache failed: {str(e)}")
            return None

    async def set(self, key: str, context: AnalysisContext, ttl: int = 86400) -> None:
        try:
            # Dump to JSON using by_alias=True to preserve JSON names
            serialized = json.dumps(context.model_dump(by_alias=True))
            await self.client.set(key, serialized, ex=ttl)
            logger.info(f"Successfully cached key: {key} for {ttl}s (Redis)")
        except Exception as e:
            logger.error(f"Redis set cache failed: {str(e)}")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None


class InMemoryCache(BaseCache):
    """Thread-safe Local In-Memory Cache with expiration support."""

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()
        logger.info("Initializing InMemory Cache")

    async def get(self, key: str) -> Optional[AnalysisContext]:
        async with self._lock:
            if key not in self._cache:
                return None
            
            data, expiry = self._cache[key]
            if time.time() > expiry:
                logger.info(f"InMemory cache expired for key: {key}")
                del self._cache[key]
                return None
            
            logger.info(f"Cache HIT for key: {key} (InMemory)")
            return AnalysisContext.model_validate(data)

    async def set(self, key: str, context: AnalysisContext, ttl: int = 86400) -> None:
        async with self._lock:
            expiry = time.time() + ttl
            data = context.model_dump(by_alias=True)
            self._cache[key] = (data, expiry)
            logger.info(f"Successfully cached key: {key} for {ttl}s (InMemory)")


# Global factory function
def get_cache() -> BaseCache:
    """Factory to retrieve active cache client based on settings config."""
    if settings.redis_url:
        return RedisCache(settings.redis_url)
    return InMemoryCache()
