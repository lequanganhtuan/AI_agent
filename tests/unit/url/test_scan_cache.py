import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.cache.scan_cache import get_cache, InMemoryCache, RedisCache
from src.core.models import AnalysisContext, ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult
from src.core.settings import settings

VALID_CONTEXT_DICT = {
    "validation": {
        "valid": True,
        "normalized_url": "https://example.com",
        "cache_key": "TEST_KEY"
    },
    "static": {
        "lexical": {
            "url_length": 16,
            "root_domain_length": 8,
            "full_domain_length": 8,
            "subdomain_count": 0,
            "url_special_char_count": 0,
            "digit_ratio_domain": 0.0,
            "domain_entropy": 2.5,
            "hyphen_count": 0,
            "url_depth": 0,
            "query_parameter_count": 0,
            "max_path_segment_length": 0,
            "longest_token_length": 0,
            "consecutive_digit_count": 0
        },
        "brand": {},
        "pattern": {},
        "tld": {},
        "typosquatting": {},
        "risk": {
            "score": 0,
            "risk_level": "low"
        }
    },
    "threat_intel": {
        "virustotal": {},
        "google_safe_browsing": {},
        "urlscan": {},
        "ip_reputation": {},
        "risk": {
            "score": 0,
            "risk_level": "low"
        }
    }
}

@pytest.fixture
def mock_context():
    return AnalysisContext.model_validate(VALID_CONTEXT_DICT)

@pytest.mark.anyio
async def test_in_memory_cache_get_set(mock_context):
    cache = InMemoryCache()
    
    # Verify missing key returns None
    result = await cache.get("nonexistent")
    assert result is None
    
    # Store and retrieve context
    await cache.set("test_key", mock_context, ttl=10)
    retrieved = await cache.get("test_key")
    
    assert retrieved is not None
    assert retrieved.validation.normalized_url == "https://example.com"
    assert retrieved.validation.cache_key == "TEST_KEY"

@pytest.mark.anyio
async def test_in_memory_cache_expiration(mock_context):
    cache = InMemoryCache()
    
    # Set with immediate expiration (TTL = 0 or negative)
    await cache.set("expired_key", mock_context, ttl=-1)
    
    retrieved = await cache.get("expired_key")
    assert retrieved is None

@pytest.mark.anyio
async def test_redis_cache_get_set(mock_context):
    cache = RedisCache("redis://localhost:6379")
    
    # Mock redis client calls
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    cache._client = mock_redis
    
    # Get missing
    res = await cache.get("missing")
    assert res is None
    mock_redis.get.assert_called_once_with("missing")
    
    # Set item
    mock_redis.set = AsyncMock()
    await cache.set("key", mock_context, ttl=60)
    mock_redis.set.assert_called_once()
    
    # Get present item
    import json
    mock_redis.get.return_value = json.dumps(VALID_CONTEXT_DICT)
    res = await cache.get("key")
    assert res is not None
    assert res.validation.normalized_url == "https://example.com"

def test_cache_factory_selection():
    # If redis_url is unset, factory returns InMemoryCache
    with patch("src.core.cache.scan_cache.settings") as mock_settings:
        mock_settings.redis_url = None
        cache = get_cache()
        assert isinstance(cache, InMemoryCache)
        
    # If redis_url is set, factory returns RedisCache
    with patch("src.core.cache.scan_cache.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379"
        cache = get_cache()
        assert isinstance(cache, RedisCache)

