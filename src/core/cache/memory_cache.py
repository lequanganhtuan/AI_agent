import os
import json
import time
import logging
import asyncio
from typing import Optional, Dict, Tuple, Any

from src.core.cache.base import BaseCache
from src.core.report.fraud_report import FraudReport

logger = logging.getLogger(__name__)

class InMemoryCache(BaseCache):
    """Thread-safe Local In-Memory Cache for FraudReports with expiration support and disk-persistence fallback."""

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()
        
        # Resolve path for disk persistence
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self._cache_file = os.path.join(base_dir, "artifacts", "local_memory_cache.json")
        logger.info(f"Initializing InMemory Cache with disk backup at: {self._cache_file}")
        
        # Load existing cache from disk if available
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    serialized = json.load(f)
                
                # Filter out expired items during load
                current_time = time.time()
                loaded_count = 0
                for key, val in serialized.items():
                    data, expiry_timestamp = val
                    if current_time < expiry_timestamp:
                        # Convert absolute timestamp back to relative monotonic time
                        monotonic_expiry = time.monotonic() + (expiry_timestamp - current_time)
                        self._cache[key] = (data, monotonic_expiry)
                        loaded_count += 1
                logger.info(f"Loaded {loaded_count} valid cache entries from disk backup.")
        except Exception as e:
            logger.warning(f"Failed to load cache from disk backup: {str(e)}")

    def _save_to_disk(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._cache_file), exist_ok=True)
            serialized = {}
            current_time = time.time()
            for key, val in self._cache.items():
                data, monotonic_expiry = val
                remaining_ttl = monotonic_expiry - time.monotonic()
                if remaining_ttl > 0:
                    absolute_expiry = current_time + remaining_ttl
                    serialized[key] = (data, absolute_expiry)
            
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2)
            logger.info("Successfully serialized cache to disk backup.")
        except Exception as e:
            logger.warning(f"Failed to save cache to disk backup: {str(e)}")

    async def get(self, key: str) -> Optional[FraudReport]:
        async with self._lock:
            if key not in self._cache:
                return None
            
            data, expiry = self._cache[key]
            if time.monotonic() > expiry:
                logger.info(f"InMemory cache expired for key: {key}")
                del self._cache[key]
                # Save changes asynchronously in threadpool to keep it non-blocking
                await asyncio.to_thread(self._save_to_disk)
                return None
            
            logger.info(f"Cache HIT for key: {key} (InMemory)")
            return FraudReport.model_validate(data)

    async def set(self, key: str, report: FraudReport, ttl: int = 86400) -> None:
        async with self._lock:
            expiry = time.monotonic() + ttl
            data = report.model_dump(by_alias=True)
            self._cache[key] = (data, expiry)
            logger.info(f"Successfully cached key: {key} for {ttl}s (InMemory)")
            # Save changes asynchronously in threadpool to keep it non-blocking
            await asyncio.to_thread(self._save_to_disk)

    async def get_all(self) -> list[FraudReport]:
        async with self._lock:
            reports = []
            current_time = time.monotonic()
            for key, val in list(self._cache.items()):
                data, expiry = val
                if current_time > expiry:
                    del self._cache[key]
                else:
                    try:
                        # Only return entries that are keyed by UUID or similar to avoid duplicates (keys starting with url: are duplicates of key = uuid)
                        if not key.startswith("url:"):
                            reports.append(FraudReport.model_validate(data))
                    except Exception:
                        pass
            return reports
