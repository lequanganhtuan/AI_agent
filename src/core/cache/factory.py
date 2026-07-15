from src.core.cache.base import BaseCache
from src.core.cache.memory_cache import InMemoryCache

def get_cache() -> BaseCache:
    """Factory to retrieve active cache client. Always returns InMemoryCache."""
    return InMemoryCache()
