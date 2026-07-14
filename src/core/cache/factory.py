from src.core.settings import settings
from src.core.cache.base import BaseCache
from src.core.cache.memory_cache import InMemoryCache

def get_cache() -> BaseCache:
    """Factory to retrieve active cache client based on settings config. Redis is removed; always returns InMemoryCache."""
    return InMemoryCache()
