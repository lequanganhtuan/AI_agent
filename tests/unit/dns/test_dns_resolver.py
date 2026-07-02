from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import dns.resolver
import dns.exception

from src.dns.models import DNSResult
from src.dns.cache import DNSCache
from src.dns.dnspython_resolver import resolve_dns
from src.dns.resolver import DNSResolver


# =========================================================================
# TEST CACHE LAYER
# =========================================================================
@pytest.mark.anyio
class TestCache:

    async def test_cache_disabled_no_redis_url(self):
        """DNSCache falls back gracefully when REDIS_URL is not set."""
        with patch("src.dns.cache.settings") as mock_settings:
            mock_settings.redis_url = None
            cache = DNSCache()
            assert cache._enabled is False
            assert await cache.get("example.com") is None
            # Set does not throw
            await cache.set("example.com", ["1.1.1.1"])

    async def test_cache_disabled_redis_connection_error(self):
        """DNSCache handles Redis connection errors gracefully during initialization."""
        with patch("src.dns.cache.settings") as mock_settings, \
             patch("redis.asyncio.Redis.from_url") as mock_redis_conn:
            mock_settings.redis_url = "redis://localhost:6379"
            mock_redis_conn.side_effect = Exception("Connection Refused")

            cache = DNSCache()
            assert cache._enabled is False
            assert await cache.get("example.com") is None

    async def test_cache_get_and_set_success(self):
        """DNSCache correctly writes and reads from Redis."""
        with patch("src.dns.cache.settings") as mock_settings, \
             patch("redis.asyncio.Redis.from_url") as mock_redis_conn:
            mock_settings.redis_url = "redis://localhost:6379"
            mock_client = MagicMock()
            mock_client.ping = AsyncMock(return_value=True)
            mock_client.get = AsyncMock(return_value='["1.2.3.4", "5.6.7.8"]')
            mock_client.set = AsyncMock()
            mock_redis_conn.return_value = mock_client

            cache = DNSCache()
            assert cache._enabled is True
            assert await cache.get("example.com") == ["1.2.3.4", "5.6.7.8"]
            
            # Write to cache
            await cache.set("example.com", ["1.2.3.4"], ttl=60)
            mock_client.set.assert_called_once_with("dns_cache:example.com", '["1.2.3.4"]', ex=60)

    async def test_cache_failures_handled_gracefully(self):
        """DNSCache handles post-init Redis query failures without throwing exceptions."""
        with patch("src.dns.cache.settings") as mock_settings, \
             patch("redis.asyncio.Redis.from_url") as mock_redis_conn:
            mock_settings.redis_url = "redis://localhost:6379"
            mock_client = MagicMock()
            mock_client.ping = AsyncMock(return_value=True)
            mock_client.get = AsyncMock(side_effect=Exception("Redis crash"))
            mock_client.set = AsyncMock(side_effect=Exception("Redis crash"))
            mock_redis_conn.return_value = mock_client

            cache = DNSCache()
            assert cache._enabled is True
            
            # Read fails gracefully
            assert await cache.get("example.com") is None
            # Write fails gracefully
            await cache.set("example.com", ["1.2.3.4"])


# =========================================================================
# TEST SYNC CORE ENGINE
# =========================================================================
class TestDnspythonResolver:

    def test_resolve_dns_empty_input(self):
        """resolve_dns handles empty domains immediately."""
        assert resolve_dns("") == []
        assert resolve_dns(None) == []

    def test_resolve_dns_success(self):
        """resolve_dns parses successfully resolved A/AAAA records."""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_record_a = MagicMock()
            mock_record_a.address = "1.2.3.4"
            mock_record_aaaa = MagicMock()
            mock_record_aaaa.address = "2001:db8::1"
            
            mock_resolve.side_effect = [
                [mock_record_a],  # resolve for A
                [mock_record_aaaa]  # resolve for AAAA
            ]

            ips = resolve_dns("example.com")
            assert ips == ["1.2.3.4", "2001:db8::1"]

    def test_resolve_dns_no_answer(self):
        """resolve_dns returns empty list when NoAnswer is encountered."""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer()
            ips = resolve_dns("example.com")
            assert ips == []


# =========================================================================
# TEST MAIN ASYNC ORCHESTRATOR
# =========================================================================
@pytest.mark.anyio
class TestDNSResolver:

    async def test_resolver_empty_input(self):
        """DNSResolver resolves empty domain inputs immediately."""
        resolver = DNSResolver()
        res = await resolver.resolve("")
        assert isinstance(res, DNSResult)
        assert res.resolved is False
        assert res.ips == []

    async def test_resolver_cache_hit(self):
        """DNSResolver returns cached entries first."""
        resolver = DNSResolver()
        with patch.object(resolver._cache, "get", return_value=["1.1.1.1", "2.2.2.2"]) as mock_cache_get, \
             patch("src.dns.resolver.resolve_dns") as mock_resolve:
            
            res = await resolver.resolve("cache-hit.com")
            assert isinstance(res, DNSResult)
            assert res.resolved is True
            assert res.ips == ["1.1.1.1", "2.2.2.2"]
            mock_cache_get.assert_called_once_with("cache-hit.com")
            mock_resolve.assert_not_called()

    async def test_resolver_cache_miss_and_resolve(self):
        """DNSResolver performs lookup and caches the result on cache miss."""
        resolver = DNSResolver()
        with patch.object(resolver._cache, "get", return_value=None), \
             patch.object(resolver._cache, "set") as mock_cache_set, \
             patch("src.dns.resolver.resolve_dns", return_value=["8.8.8.8"]) as mock_resolve_dns:
            
            res = await resolver.resolve("cache-miss.com")
            assert isinstance(res, DNSResult)
            assert res.resolved is True
            assert res.ips == ["8.8.8.8"]
            mock_resolve_dns.assert_called_once_with("cache-miss.com")
            mock_cache_set.assert_called_once_with("cache-miss.com", ["8.8.8.8"], ttl=1800)

    async def test_resolver_timeout_handled_gracefully(self):
        """DNSResolver falls back to empty result on resolution timeouts."""
        resolver = DNSResolver()
        resolver._timeout_seconds = 0.001
        
        async def slow_resolve(domain):
            await asyncio.sleep(0.5)
            return ["8.8.8.8"]

        with patch.object(resolver._cache, "get", return_value=None), \
             patch.object(resolver._cache, "set") as mock_cache_set, \
             patch("src.dns.resolver.resolve_dns", side_effect=asyncio.TimeoutError()):
            
            res = await resolver.resolve("timeout.com")
            assert isinstance(res, DNSResult)
            assert res.resolved is False
            assert res.ips == []
            # Caches empty list as negative cache
            mock_cache_set.assert_called_once_with("timeout.com", [], ttl=300)

    async def test_resolver_critical_failure_safety(self):
        """DNSResolver returns safe empty response if a critical error occurs."""
        resolver = DNSResolver()
        with patch.object(resolver._cache, "get", side_effect=Exception("DB Corrupted")):
            res = await resolver.resolve("failed.com")
            assert isinstance(res, DNSResult)
            assert res.resolved is False
            assert res.ips == []
