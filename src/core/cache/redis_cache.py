import json
import logging
from typing import Optional
import redis.asyncio as aioredis

from src.core.cache.base import BaseCache
from src.core.report.fraud_report import FraudReport
from src.core.cache.memory_cache import InMemoryCache

logger = logging.getLogger(__name__)

class RedisCache(BaseCache):
    """Redis-backed Cache Implementation for FraudReport caching with transparent local memory fallback."""

    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url
        self._client: Optional[aioredis.Redis] = None
        self._is_alive = True
        self._fallback_cache = InMemoryCache()

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            logger.info(f"Initializing Redis Cache connection: {self.redis_url}")
            self._client = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._client

    async def get(self, key: str) -> Optional[FraudReport]:
        if not self._is_alive:
            return await self._fallback_cache.get(key)
        try:
            redis_key = f"scan:{key}"
            # Test connection/command execution
            cached_data = await self.client.get(redis_key)
            if not cached_data:
                return None
            
            logger.info(f"Cache HIT for key: {redis_key} (Redis)")
            raw_dict = json.loads(cached_data)
            return FraudReport.model_validate(raw_dict)
        except Exception as e:
            logger.warning(f"Redis get cache failed: {str(e)}. Falling back to local memory cache.")
            self._is_alive = False
            return await self._fallback_cache.get(key)

    async def set(self, key: str, report: FraudReport, ttl: int = 86400) -> None:
        if not self._is_alive:
            await self._fallback_cache.set(key, report, ttl)
            return
        try:
            redis_key = f"scan:{key}"
            # Use Pydantic's native model_dump_json to correctly serialize datetime and UUID fields
            serialized = report.model_dump_json(by_alias=True)
            await self.client.set(redis_key, serialized, ex=ttl)
            logger.info(f"Successfully cached key: {redis_key} for {ttl}s (Redis)")
        except Exception as e:
            logger.warning(f"Redis set cache failed: {str(e)}. Falling back to local memory cache.")
            self._is_alive = False
            await self._fallback_cache.set(key, report, ttl)

    async def get_all(self) -> list[FraudReport]:
        if not self._is_alive:
            return await self._fallback_cache.get_all()
        try:
            # Simple scan for keys starting with scan:
            keys = await self.client.keys("scan:*")
            reports = []
            for k in keys:
                # Avoid keys that have "url:" (are duplicates of uuid keyed ones)
                if "url:" not in k:
                    data = await self.client.get(k)
                    if data:
                        reports.append(FraudReport.model_validate(json.loads(data)))
            return reports
        except Exception as e:
            logger.warning(f"Redis get_all failed: {str(e)}. Falling back to local memory cache.")
            self._is_alive = False
            return await self._fallback_cache.get_all()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None
        await self._fallback_cache.close()
