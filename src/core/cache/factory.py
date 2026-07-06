from src.core.settings import settings
from src.core.cache.base import BaseCache
from src.core.cache.redis_cache import RedisCache
from src.core.cache.memory_cache import InMemoryCache

def get_cache() -> BaseCache:
    """Factory to retrieve active cache client based on settings config."""
    if settings.redis_url:
        return RedisCache(settings.redis_url)
    return InMemoryCache()
