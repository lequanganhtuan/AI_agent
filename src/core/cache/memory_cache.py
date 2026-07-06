import time
import logging
import asyncio
from typing import Optional, Dict, Tuple, Any

from src.core.cache.base import BaseCache
from src.core.report.fraud_report import FraudReport

logger = logging.getLogger(__name__)

class InMemoryCache(BaseCache):
    """Thread-safe Local In-Memory Cache for FraudReports with expiration support."""

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()
        logger.info("Initializing InMemory Cache")

    async def get(self, key: str) -> Optional[FraudReport]:
        async with self._lock:
            if key not in self._cache:
                return None
            
            data, expiry = self._cache[key]
            if time.monotonic() > expiry:
                logger.info(f"InMemory cache expired for key: {key}")
                del self._cache[key]
                return None
            
            logger.info(f"Cache HIT for key: {key} (InMemory)")
            return FraudReport.model_validate(data)

    async def set(self, key: str, report: FraudReport, ttl: int = 86400) -> None:
        async with self._lock:
            expiry = time.monotonic() + ttl
            data = report.model_dump(by_alias=True)
            self._cache[key] = (data, expiry)
            logger.info(f"Successfully cached key: {key} for {ttl}s (InMemory)")
