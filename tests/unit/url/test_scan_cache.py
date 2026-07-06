import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.cache.factory import get_cache
from src.core.cache.memory_cache import InMemoryCache
from src.core.cache.redis_cache import RedisCache
from src.core.report.fraud_report import FraudReport
from src.core.settings import settings

VALID_REPORT_DICT = {
    "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
    "cache_key": "TEST_KEY",
    "url": "https://example.com",
    "normalized_url": "https://example.com",
    "scanned_at": "2026-07-06T09:28:16.123Z",
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
def sample_report():
    return FraudReport.model_validate(VALID_REPORT_DICT)

@pytest.mark.anyio
async def test_in_memory_cache_get_set(sample_report):
    cache = InMemoryCache()
    
    # Verify missing key returns None
    result = await cache.get("nonexistent")
    assert result is None
    
    # Store and retrieve report
    await cache.set("test_key", sample_report, ttl=10)
    retrieved = await cache.get("test_key")
    
    assert retrieved is not None
    assert retrieved.id == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    assert retrieved.cache_key == "TEST_KEY"

@pytest.mark.anyio
async def test_in_memory_cache_expiration(sample_report):
    cache = InMemoryCache()
    await cache.set("expired_key", sample_report, ttl=-1)
    
    retrieved = await cache.get("expired_key")
    assert retrieved is None

@pytest.mark.anyio
async def test_redis_cache_get_set(sample_report):
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
    await cache.set("key", sample_report, ttl=60)
    mock_redis.set.assert_called_once()
    
    # Get present item
    import json
    mock_redis.get.return_value = json.dumps(VALID_REPORT_DICT)
    res = await cache.get("key")
    assert res is not None
    assert res.id == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"

def test_cache_factory_selection():
    # If redis_url is unset, factory returns InMemoryCache
    with patch("src.core.cache.factory.settings") as mock_settings:
        mock_settings.redis_url = None
        cache = get_cache()
        assert isinstance(cache, InMemoryCache)
        
    # If redis_url is set, factory returns RedisCache
    with patch("src.core.cache.factory.settings") as mock_settings:
        mock_settings.redis_url = "redis://localhost:6379"
        cache = get_cache()
        assert isinstance(cache, RedisCache)
