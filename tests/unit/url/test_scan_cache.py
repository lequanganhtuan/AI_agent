import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch

from src.core.cache.factory import get_cache
from src.core.cache.memory_cache import InMemoryCache
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

def test_cache_factory_selection():
    cache = get_cache()
    assert isinstance(cache, InMemoryCache)

@pytest.mark.anyio
async def test_in_memory_cache_eviction_policy(sample_report):
    cache = InMemoryCache()
    # Fill cache up to 205 elements (exceeding MAX_CACHE_SIZE = 200)
    # The elements will have different TTLs so that we know which ones expire first
    for i in range(205):
        key = f"key_{i}"
        # Make key_0 have the lowest expiry time (TTL = 1s), others have higher TTLs
        ttl = 1 if i == 0 else 1000 + i
        await cache.set(key, sample_report, ttl=ttl)

    # key_0 should have been evicted first because it had the soonest expiry
    retrieved_key_0 = await cache.get("key_0")
    assert retrieved_key_0 is None
    
    # We should have exactly 200 elements left in cache
    # (Since 205 keys were inserted, 5 should be evicted)
    reports = await cache.get_all()
    # Note: get_all returns keys that don't start with "url:" (which f"key_{i}" doesn't)
    assert len(reports) == 200
