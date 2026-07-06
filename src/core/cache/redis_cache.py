import json
import logging
from typing import Optional
import redis.asyncio as aioredis

from src.core.cache.base import BaseCache
from src.core.report.fraud_report import FraudReport

logger = logging.getLogger(__name__)

class RedisCache(BaseCache):
    """Redis-backed Cache Implementation for FraudReport caching."""

    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url
        self._client: Optional[aioredis.Redis] = None

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            logger.info(f"Initializing Redis Cache connection: {self.redis_url}")
            self._client = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._client

    async def get(self, key: str) -> Optional[FraudReport]:
        try:
            cached_data = await self.client.get(key)
            if not cached_data:
                return None
            
            logger.info(f"Cache HIT for key: {key} (Redis)")
            raw_dict = json.loads(cached_data)
            return FraudReport.model_validate(raw_dict)
        except Exception as e:
            logger.error(f"Redis get cache failed: {str(e)}")
            return None

    async def set(self, key: str, report: FraudReport, ttl: int = 86400) -> None:
        try:
            # Use Pydantic's native model_dump_json to correctly serialize datetime and UUID fields
            serialized = report.model_dump_json(by_alias=True)
            await self.client.set(key, serialized, ex=ttl)
            logger.info(f"Successfully cached key: {key} for {ttl}s (Redis)")
        except Exception as e:
            logger.error(f"Redis set cache failed: {str(e)}")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None
