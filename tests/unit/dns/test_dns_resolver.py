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

    async def test_cache_get_and_set_success(self):
        """DNSCache correctly writes and reads from local memory."""
        cache = DNSCache()
        assert await cache.get("example.com") is None

        # Write to cache
        await cache.set("example.com", ["1.2.3.4"], ttl=60)
        assert await cache.get("example.com") == ["1.2.3.4"]

    async def test_cache_expiration(self):
        """DNSCache respects TTL and expires values."""
        cache = DNSCache()
        await cache.set("example.com", ["1.2.3.4"], ttl=-1)
        assert await cache.get("example.com") is None


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
